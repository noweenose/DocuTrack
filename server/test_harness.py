#!/usr/bin/env python3
"""
DocuTrack Test Harness
Creates test issuances/submissions, injects tampered/duplicate/sign-corrupt cases, runs verification,
and reports metrics. Designed to be user-friendly for thesis testing.

Usage examples:
  # 1) Generate dataset: 50 unique, 10 duplicate-pairs (20 submissions), 5 tampered, 5 corrupted signatures, 2 large files 10MB each:
  python server/test_harness.py --generate --n_unique 50 --n_duplicates 10 --n_tampered 5 --n_sig_corrupt 5 --n_large 2 --large_size_mb 10

  # 2) Run verification only (reads DB and ciphertexts)
  python server/test_harness.py --verify

  # 3) Generate and verify
  python server/test_harness.py --generate --verify --n_unique 100 --n_duplicates 20 --large_size_mb 5

Notes:
 - Script expects the project's SQLite DB at: server/docutrack.db
 - Ciphertexts are written to server/uploads/issuances/
 - Signatures are created if a private key is available in server/prof_keys.json or server/keys/server_private.pem
 - Requires Python package: cryptography
"""

import os, sys, argparse, sqlite3, json, base64, datetime, secrets
from time import perf_counter

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("Missing required package 'cryptography'. Install with: pip install cryptography")
    raise

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(ROOT, "docutrack.db")    # <<-- adjust if your DB is elsewhere
UPLOAD_DIR = os.path.join(ROOT, "uploads", "issuances")
os.makedirs(UPLOAD_DIR, exist_ok=True)
PROF_KEYS_JSON = os.path.join(ROOT, "prof_keys.json")
KEYS_DIR = os.path.join(ROOT, "keys")

# Helpers
def b64e(b): return base64.b64encode(b).decode() if b is not None else None
def b64d(s):
    if s is None: return None
    try:
        return base64.b64decode(s)
    except Exception:
        return None

def canonicalize(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_hex(b):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(b)
    return digest.finalize().hex()

def load_private_key():
    # try prof_keys.json then server/keys/server_private.pem
    if os.path.exists(PROF_KEYS_JSON):
        try:
            with open(PROF_KEYS_JSON,"r") as fh:
                j = json.load(fh)
            if "priv_pem" in j and j["priv_pem"]:
                return serialization.load_pem_private_key(j["priv_pem"].encode(), password=None, backend=default_backend())
        except Exception:
            pass
    candidate = os.path.join(KEYS_DIR, "server_private.pem")
    if os.path.exists(candidate):
        with open(candidate,"rb") as fh:
            try:
                return serialization.load_pem_private_key(fh.read(), password=None, backend=default_backend())
            except Exception:
                pass
    return None

def load_public_key():
    if os.path.exists(PROF_KEYS_JSON):
        try:
            with open(PROF_KEYS_JSON,"r") as fh:
                j = json.load(fh)
            if "pub_pem" in j and j["pub_pem"]:
                return serialization.load_pem_public_key(j["pub_pem"].encode(), backend=default_backend())
        except Exception:
            pass
    candidate = os.path.join(KEYS_DIR, "server_public.pem")
    if os.path.exists(candidate):
        with open(candidate,"rb") as fh:
            try:
                return serialization.load_pem_public_key(fh.read(), backend=default_backend())
            except Exception:
                pass
    return None

def sign_header(privkey, header_bytes):
    if privkey is None:
        return None
    return privkey.sign(
        header_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_header(pubkey, header_bytes, signature):
    if pubkey is None or signature is None:
        return None
    try:
        pubkey.verify(signature, header_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# DB helpers
def connect_db():
    if not os.path.exists(DB):
        raise FileNotFoundError(f"Database not found at {DB}")
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_verification_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS verification_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      test_id TEXT,
      submission_id TEXT NOT NULL,
      issuance_id INTEGER,
      student_id INTEGER,
      ground_truth TEXT,
      header_hash TEXT,
      answer_hash TEXT,
      signature_valid INTEGER,
      gcm_auth_valid INTEGER,
      duplicate_flag INTEGER,
      duplicate_of_submission_id INTEGER,
      t_issued DATETIME,
      t_verification_start DATETIME,
      t_verification_end DATETIME,
      latency_ms INTEGER,
      notes TEXT
    )""")
    conn.commit()

# Issuance/submission insertion functions (adapt to your schema if necessary)
def create_issuance(conn, assignment_id, student_id, plaintext_bytes, privkey=None):
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    # in real test use actual template bytes; for harness keep TEST_TEMPLATE
    template_hash = sha256_hex(b"TEST_TEMPLATE")
    header = {
        "assignmentID": str(assignment_id),
        "studentID": str(student_id),
        "issueTimestamp": datetime.datetime.utcnow().isoformat(),
        "templateHash": template_hash
    }
    header_bytes = canonicalize(header)
    header_hash_hex = sha256_hex(header_bytes)
    sig = sign_header(privkey, header_bytes)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext_bytes, header_bytes)
    tag = ciphertext_with_tag[-16:]
    ct = ciphertext_with_tag[:-16]
    fname = f"issued_{assignment_id}_{student_id}_{secrets.token_hex(6)}.bin"
    fpath = os.path.join(UPLOAD_DIR, fname)
    with open(fpath,"wb") as fh:
        fh.write(ct)
    cur = conn.cursor()
    # Attempt to insert into 'issuances' table; if your schema differs, adapt column names
    cur.execute("""
    INSERT INTO issuances (assignment_id, student_id, header_json, signature_b64, iv_b64, ciphertext_path, tag_b64, aes_key_b64, created_at)
    VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        assignment_id, student_id, json.dumps(header), b64e(sig) if sig else None,
        b64e(iv), fpath, b64e(tag), b64e(key), datetime.datetime.utcnow().isoformat()
    ))
    conn.commit()
    return cur.lastrowid, header, b64e(sig) if sig else None

def insert_submission(conn, issuance_id, student_id, answer_region_bytes):
    ah = sha256_hex(answer_region_bytes)
    cur = conn.cursor()
    # Insert into 'submissions' table; if column names differ, adapt
    cur.execute("INSERT INTO submissions (issuance_id, student_id, answer_hash, created_at) VALUES (?,?,?,?)",
                (issuance_id, student_id, ah, datetime.datetime.utcnow().isoformat()))
    conn.commit()
    return cur.lastrowid, ah

# Functions that inject faults
def tamper_ciphertext_file(issuance_row):
    path = issuance_row["ciphertext_path"]
    if not path or not os.path.exists(path):
        return False, "ciphertext not found"
    with open(path,"r+b") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return False, "empty file"
        pos = max(0, size-1)
        fh.seek(pos)
        b = fh.read(1)
        fh.seek(pos)
        fh.write(bytes([b[0] ^ 0xFF]))
    return True, None

def corrupt_signature_in_db(conn, issuance_id):
    cur = conn.cursor()
    cur.execute("SELECT signature_b64 FROM issuances WHERE id=?", (issuance_id,))
    row = cur.fetchone()
    if not row or not row["signature_b64"]:
        return False
    sig = b64d(row["signature_b64"])
    if not sig:
        return False
    sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    cur.execute("UPDATE issuances SET signature_b64=? WHERE id=?", (b64e(sig), issuance_id))
    conn.commit()
    return True

# Verification flow (reads DB, ciphertexts, verifies, logs)
def run_verification(conn, test_id=None):
    ensure_verification_table(conn)
    cur = conn.cursor()
    # explicitly select and alias columns to avoid ambiguity
    cur.execute("""SELECT
        s.id as sub_id,
        s.issuance_id,
        s.student_id,
        s.answer_hash,
        s.ground_truth,
        s.created_at as submission_created_at,
        i.header_json,
        i.signature_b64,
        i.iv_b64,
        i.tag_b64,
        i.aes_key_b64,
        i.ciphertext_path,
        i.created_at as issuance_created_at
        FROM submissions s
        LEFT JOIN issuances i ON s.issuance_id=i.id
    """)
    rows = cur.fetchall()
    pub = load_public_key()
    priv = load_private_key()
    results = []
    for r in rows:
        t0 = perf_counter()
        t0_dt = datetime.datetime.utcnow().isoformat()
        signature_valid = None
        gcm_auth_valid = None
        header_hash = None
        header_bytes = None        # initialize to avoid UnboundLocalError
        notes = ""
        try:
            if r["header_json"]:
                header_bytes = canonicalize(json.loads(r["header_json"]))
                header_hash = sha256_hex(header_bytes)
            sig_b64 = r["signature_b64"]
            sig = b64d(sig_b64) if sig_b64 else None
            if pub and sig and header_bytes:
                ok = verify_header(pub, header_bytes, sig)
                signature_valid = 1 if ok else 0
            else:
                signature_valid = None
            iv = b64d(r["iv_b64"]) if r["iv_b64"] else None
            tag = b64d(r["tag_b64"]) if r["tag_b64"] else None
            key = b64d(r["aes_key_b64"]) if r["aes_key_b64"] else None
            ct_path = r["ciphertext_path"]
            if ct_path and os.path.exists(ct_path) and key and iv:
                with open(ct_path,"rb") as fh:
                    ct = fh.read()
                aesgcm = AESGCM(key)
                try:
                    plain = aesgcm.decrypt(iv, ct + (tag if tag else b''), header_bytes if header_bytes else None)
                    gcm_auth_valid = 1
                except Exception as e:
                    gcm_auth_valid = 0
                    notes += f"gcm_err:{e};"
            else:
                gcm_auth_valid = None
        except Exception as e:
            notes += f"exc:{e};"
        # duplicate detection
        dup_flag = 0
        dup_of = None
        try:
            cur.execute("SELECT id FROM submissions WHERE answer_hash=? AND id!=?", (r["answer_hash"], r["sub_id"]))
            d = cur.fetchone()
            if d:
                dup_flag = 1
                dup_of = d["id"]
        except Exception:
            pass
        t1 = perf_counter()
        t1_dt = datetime.datetime.utcnow().isoformat()
        latency_ms = int((t1 - t0) * 1000)
        # insert into verification_logs
        cur2 = conn.cursor()
        cur2.execute("""INSERT INTO verification_logs (
            test_id, submission_id, issuance_id, student_id, ground_truth,
            header_hash, answer_hash, signature_valid, gcm_auth_valid,
            duplicate_flag, duplicate_of_submission_id, t_issued,
            t_verification_start, t_verification_end, latency_ms, notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            test_id, str(r["sub_id"]), r["issuance_id"], r["student_id"], (r["ground_truth"] if "ground_truth" in r.keys() else None),
            header_hash, r["answer_hash"], signature_valid, gcm_auth_valid,
            dup_flag, dup_of, (r["issuance_created_at"] if "issuance_created_at" in r.keys() else None),
            t0_dt, t1_dt, latency_ms, notes
        ))
        conn.commit()
        results.append({
            "sub_id": r["sub_id"], "signature_valid": signature_valid, "gcm_auth_valid": gcm_auth_valid,
            "duplicate_flag": dup_flag, "latency_ms": latency_ms
        })
    return results

def compute_metrics(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM verification_logs")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE signature_valid=1")
    sig_ok = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE gcm_auth_valid=1")
    gcm_ok = cur.fetchone()[0]
    cur.execute("SELECT latency_ms FROM verification_logs WHERE latency_ms IS NOT NULL")
    latrows = [r[0] for r in cur.fetchall()]
    avg_lat = sum(latrows)/len(latrows) if latrows else None
    p95 = None
    if latrows:
        latrows_sorted = sorted(latrows)
        idx = max(0, int(len(latrows_sorted)*0.95)-1)
        p95 = latrows_sorted[idx]
    # confusion (requires ground_truth inserted during generation)
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE ground_truth='duplicate' AND duplicate_flag=1")
    tp = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE (ground_truth!='duplicate' OR ground_truth IS NULL) AND duplicate_flag=1")
    fp = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE ground_truth='duplicate' AND duplicate_flag=0")
    fn = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM verification_logs WHERE (ground_truth!='duplicate' OR ground_truth IS NULL) AND duplicate_flag=0")
    tn = cur.fetchone()[0]
    precision = tp/(tp+fp) if (tp+fp)>0 else None
    recall = tp/(tp+fn) if (tp+fn)>0 else None
    accuracy = (tp+tn)/(tp+tn+fp+fn) if (tp+tn+fp+fn)>0 else None
    fpr = fp/(fp+tn) if (fp+tn)>0 else None
    return {
        "total_logs": total, "signature_ok": sig_ok, "gcm_ok": gcm_ok,
        "avg_latency_ms": avg_lat, "p95_latency_ms": p95,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "accuracy": accuracy, "fpr": fpr
    }

def generate_dataset(conn, n_unique=50, n_duplicates=10, n_tampered=5, n_sig_corrupt=5, n_large=2, large_size_mb=10, start_student=10000):
    priv = load_private_key()
    print("Private key available for signing:", bool(priv))
    created = {"issuances": [], "submissions": []}
    sid = start_student
    # unique small files
    for i in range(n_unique):
        plaintext = os.urandom(1024*10)  # 10KB
        issuance_id, header, sig = create_issuance(conn, 1, sid, plaintext, privkey=priv)
        sub_id, ah = insert_submission(conn, issuance_id, sid, plaintext[:512])
        cur = conn.cursor(); cur.execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("unique", sub_id)); conn.commit()
        created["issuances"].append(issuance_id); created["submissions"].append(sub_id)
        sid += 1
    # duplicate pairs
    for i in range(n_duplicates):
        answer = os.urandom(512)
        issuance_id1, h1, s1 = create_issuance(conn, 1, sid, os.urandom(1024*10), privkey=priv)
        sub1, ah1 = insert_submission(conn, issuance_id1, sid, answer)
        conn.cursor().execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("duplicate", sub1)); conn.commit()
        sid += 1
        issuance_id2, h2, s2 = create_issuance(conn, 1, sid, os.urandom(1024*10), privkey=priv)
        sub2, ah2 = insert_submission(conn, issuance_id2, sid, answer)
        conn.cursor().execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("duplicate", sub2)); conn.commit()
        sid += 1
        created["issuances"].extend([issuance_id1, issuance_id2]); created["submissions"].extend([sub1, sub2])
    # tampered: flip ciphertext byte
    for i in range(n_tampered):
        plaintext = os.urandom(1024*10)
        issuance_id, header, sig = create_issuance(conn, 1, sid, plaintext, privkey=priv)
        sub_id, ah = insert_submission(conn, issuance_id, sid, plaintext[:512])
        cur = conn.cursor(); cur.execute("SELECT * FROM issuances WHERE id=?", (issuance_id,)); row = cur.fetchone()
        if row and row["ciphertext_path"] and os.path.exists(row["ciphertext_path"]):
            with open(row["ciphertext_path"], "r+b") as fh:
                fh.seek(0, os.SEEK_END)
                pos = max(0, fh.tell()-1)
                fh.seek(pos); b = fh.read(1); fh.seek(pos); fh.write(bytes([b[0] ^ 0xFF]))
        conn.cursor().execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("tampered", sub_id)); conn.commit()
        created["issuances"].append(issuance_id); created["submissions"].append(sub_id)
        sid += 1
    # signature corrupted cases
    for i in range(n_sig_corrupt):
        plaintext = os.urandom(1024*10)
        issuance_id, header, sig = create_issuance(conn, 1, sid, plaintext, privkey=priv)
        sub_id, ah = insert_submission(conn, issuance_id, sid, plaintext[:512])
        # corrupt signature in DB
        cur = conn.cursor(); cur.execute("SELECT signature_b64 FROM issuances WHERE id=?", (issuance_id,)); row = cur.fetchone()
        if row and row["signature_b64"]:
            sigb = b64d(row["signature_b64"])
            if sigb:
                sigb = bytes([sigb[0] ^ 0xFF]) + sigb[1:]
                cur.execute("UPDATE issuances SET signature_b64=? WHERE id=?", (b64e(sigb), issuance_id))
                conn.commit()
        conn.cursor().execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("sig_corrupted", sub_id)); conn.commit()
        created["issuances"].append(issuance_id); created["submissions"].append(sub_id)
        sid += 1
    # large files
    for i in range(n_large):
        plaintext = os.urandom(large_size_mb * 1024 * 1024)
        issuance_id, header, sig = create_issuance(conn, 1, sid, plaintext, privkey=priv)
        sub_id, ah = insert_submission(conn, issuance_id, sid, plaintext[:1024])
        conn.cursor().execute("UPDATE submissions SET ground_truth=? WHERE id=?", ("large", sub_id)); conn.commit()
        created["issuances"].append(issuance_id); created["submissions"].append(sub_id)
        sid += 1
    print("Generated dataset counts:", {k: len(v) for k,v in created.items()})
    return created

def main():
    parser = argparse.ArgumentParser(description="DocuTrack test harness")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--n_unique", type=int, default=50)
    parser.add_argument("--n_duplicates", type=int, default=10)
    parser.add_argument("--n_tampered", type=int, default=5)
    parser.add_argument("--n_sig_corrupt", type=int, default=5)
    parser.add_argument("--n_large", type=int, default=2)
    parser.add_argument("--large_size_mb", type=int, default=10)
    parser.add_argument("--start_student", type=int, default=10000)
    args = parser.parse_args()

    conn = connect_db()
    ensure_verification_table(conn)
    if args.generate:
        print("Generating dataset into DB:", DB)
        generate_dataset(conn,
                         n_unique=args.n_unique,
                         n_duplicates=args.n_duplicates,
                         n_tampered=args.n_tampered,
                         n_sig_corrupt=args.n_sig_corrupt,
                         n_large=args.n_large,
                         large_size_mb=args.large_size_mb,
                         start_student=args.start_student)
        print("Generation complete.")

    if args.verify:
        print("Running verification...")
        results = run_verification(conn, test_id=f"test_{datetime.datetime.utcnow().isoformat()}")
        print("Verification done. Submissions processed:", len(results))
        metrics = compute_metrics(conn)
        print("\n==== Summary Metrics ====")
        for k,v in metrics.items():
            print(f"{k}: {v}")
        print("=========================")
    conn.close()

if __name__ == "__main__":
    main()
