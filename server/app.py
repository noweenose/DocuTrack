# server/app.py
import os, json, shutil, datetime, base64, zipfile, io, csv
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException
from fastapi import status
from fastapi import Body
from sqlalchemy import text
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import (
    create_engine, Column, Integer, String, LargeBinary, Text, DateTime, ForeignKey
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

from server.crypto import (
    sha256_bytes, generate_rsa_keypair, rsa_sign_pss, rsa_verify_pss,
    aes256gcm_encrypt, aes256gcm_decrypt, canonicalize_header, b64e, b64d
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse




# ======== Config ========
SECRET = os.getenv("SECRET", "dev-secret-for-jwt")
ALGO = "HS256"
ACCESS_MINUTES = 60 * 8

BASE_DIR = os.path.dirname(__file__)
STORE = os.path.join(BASE_DIR, "storage")
for d in ["templates", "ciphertext", "decrypted", "submissions"]:
    os.makedirs(os.path.join(STORE, d), exist_ok=True)

# ======== DB ========
DB_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "docutrack.db")
)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    future=True
)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base = declarative_base()

# ======== Auth & Models ========
pwdctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    name = Column(String)
    role = Column(String)  # 'professor' | 'student'
    password_hash = Column(String)

class Assignment(Base):
    __tablename__ = "assignments"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    template_path = Column(String)
    template_hash = Column(String)
    created_by_prof_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Issuance(Base):
    __tablename__ = "issuances"
    id = Column(Integer, primary_key=True)
    assignment_id = Column(Integer, ForeignKey("assignments.id"))
    student_id = Column(Integer, ForeignKey("users.id"))
    header_json = Column(Text)          # stored canonical header with signature (or separate signature)
    signature_b64 = Column(Text)
    iv_b64 = Column(Text)
    ciphertext_path = Column(String)
    tag_b64 = Column(Text)
    aes_key_b64 = Column(Text)          # demo: store plaintext; for prod encrypt with KMS
    status = Column(String, default="ISSUED")  # ISSUED | DOWNLOADED | SUBMITTED

class Submission(Base):
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True)
    issuance_id = Column(Integer, ForeignKey("issuances.id"))
    student_id = Column(Integer, ForeignKey("users.id"))
    file_path = Column(String)
    answer_hash = Column(String)
    status = Column(String)  # ACCEPTED | DUPLICATE | TAMPERED
    submitted_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(engine)

# ======== RSA keys (demo system-wide professor keypair) ========
# For demo simplicity, a single professor key pair lives in memory/disk.
KEYS_PATH = os.path.join(BASE_DIR, "prof_keys.json")
if not os.path.exists(KEYS_PATH):
    from cryptography.hazmat.primitives import serialization
    priv, pub = generate_rsa_keypair()
    prv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    json.dump({"private_pem": prv_pem, "public_pem": pub_pem}, open(KEYS_PATH,"w"))
else:
    data = json.load(open(KEYS_PATH))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    priv = serialization.load_pem_private_key(data["private_pem"].encode(), password=None, backend=default_backend())
    pub = serialization.load_pem_public_key(data["public_pem"].encode(), backend=default_backend())

# ======== FastAPI ========
app = FastAPI(title="DocuTrack Local Server", version="1.0")

# ======== MOUNT =========
BASE_DIR = os.path.dirname(__file__)
WEB_DIR = os.path.join(os.path.dirname(BASE_DIR), "web")

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

@app.get("/")
def root():
    return FileResponse("web/index.html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# ======== Helpers ========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def jwt_create(user: User):
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_MINUTES)
    return jwt.encode({"sub": user.email, "role": user.role, "uid": user.id, "exp": exp}, SECRET, algorithm=ALGO)

def jwt_current(db: Session, token: str):
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
        email = payload.get("sub")
        user = db.query(User).filter(User.email==email).first()
        if not user: raise HTTPException(401, "Invalid user")
        return user
    except JWTError:
        raise HTTPException(401, "Invalid token")

# ======== Schemas ========
class RegisterIn(BaseModel):
    email: EmailStr
    name: str
    role: str
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str


# ======== Page Routes ========
@app.get("/")
def home():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))

@app.get("/login")
def login():
    return FileResponse(os.path.join(WEB_DIR, "login.html"))

@app.get("/professor")
def professor():
    return FileResponse(os.path.join(WEB_DIR, "professor.html"))

@app.get("/student")
def student():
    return FileResponse(os.path.join(WEB_DIR, "student.html"))

# ======== Auth Routes ========
@app.post("/auth/register")
def register(inp: RegisterIn, db: Session = Depends(get_db)):
    if inp.role not in ("professor","student"):
        raise HTTPException(400, "role must be 'professor' or 'student'")
    if db.query(User).filter(User.email==inp.email).first():
        raise HTTPException(400, "email already exists")
    user = User(email=inp.email, name=inp.name, role=inp.role, password_hash=pwdctx.hash(inp.password))
    db.add(user); db.commit()
    return {"ok": True}

@app.post("/auth/login")
def login(inp: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email==inp.email).first()
    if not user or not pwdctx.verify(inp.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return {"token": jwt_create(user), "role": user.role, "name": user.name}

@app.get("/users/students")
def list_students(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor": raise HTTPException(403, "professor only")
    return [{"id": u.id, "email": u.email, "name": u.name} for u in db.query(User).filter(User.role=="student").all()]

# ======== Professor: Upload Template and Issue ========
# ---- Admin Reset: clear issued files and DB rows (keeps users & templates) ----
@app.post("/admin/reset")
def admin_reset(
    token: str,
    confirm: str = Body(..., embed=True),           # expects {"confirm":"RESET"}
    scope: str = Body("issuances", embed=True),     # "issuances" | "all"
    db: Session = Depends(get_db),
):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")
    if confirm != "RESET":
        raise HTTPException(400, "To proceed, set confirm to 'RESET'")

    # helpers
    def safe_rm(path):
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def clear_folder(name):
        p = os.path.join(STORE, name)
        if os.path.isdir(p):
            for n in os.listdir(p):
                safe_rm(os.path.join(p, n))

    # 1) delete submission files & rows first (FK to issuances)
    subs = db.query(Submission).all()
    for s in subs:
        safe_rm(s.file_path)
        db.delete(s)

    # 2) delete issuance ciphertext & rows
    iss_list = db.query(Issuance).all()
    for i in iss_list:
        safe_rm(i.ciphertext_path)
        db.delete(i)

    deleted_assignments = 0
    # 3) optionally delete assignments & templates
    if scope == "all":
        for a in db.query(Assignment).all():
            safe_rm(a.template_path)
            db.delete(a)
            deleted_assignments += 1

    db.commit()

    # 4) clear storage folders on disk
    clear_folder("ciphertext")
    clear_folder("decrypted")
    clear_folder("submissions")
    if scope == "all":
        clear_folder("templates")

    # 5) try VACUUM to shrink sqlite (best effort)
    try:
        db.execute(text("VACUUM"))
        db.commit()
    except Exception:
        pass

    return {
        "ok": True,
        "scope": scope,
        "deleted": {
            "issuances": len(iss_list),
            "submissions": len(subs),
            "assignments": deleted_assignments if scope == "all" else 0,
        },
        "message": "System reset completed."
    }

@app.post("/prof/assignments/upload")
def upload_assignment(
    token: str,
    title: Optional[str] = Form(None),           # allow blank; fallback to filename
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # 1) auth: must be professor
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    # 2) validate file
    if file is None or not getattr(file, "filename", ""):
        raise HTTPException(422, "Missing file upload")

    # 3) ensure storage/templates exists (in case it was deleted after startup)
    tmpl_dir = os.path.join(STORE, "templates")
    os.makedirs(tmpl_dir, exist_ok=True)

    # 4) safe filename + path
    original_name = os.path.basename(file.filename)
    if not original_name:
        original_name = "template.pdf"
    # timestamp prefix to avoid collisions
    ts = str(int(datetime.datetime.utcnow().timestamp()))
    safe_name = f"{ts}_{original_name}"
    tmpl_path = os.path.join(tmpl_dir, safe_name)

    # 5) write file to disk
    try:
        with open(tmpl_path, "wb") as out:
            shutil.copyfileobj(file.file, out)
    except Exception as e:
        raise HTTPException(500, f"Failed to save file: {e}")

    # 6) compute template hash
    try:
        with open(tmpl_path, "rb") as f:
            template_hash = sha256_bytes(f.read())
    except Exception as e:
        # cleanup partial file if hashing failed
        try:
            os.remove(tmpl_path)
        except Exception:
            pass
        raise HTTPException(500, f"Failed to hash file: {e}")

    # 7) fallback title to filename if empty/None
    if not title or not title.strip():
        title = original_name

    # 8) insert DB row
    a = Assignment(
        title=title.strip(),
        template_path=tmpl_path,
        template_hash=template_hash,
        created_by_prof_id=me.id,
    )
    db.add(a)
    db.commit()

    return {
        "ok": True,
        "assignment_id": a.id,
        "title": a.title,
        "template_hash": template_hash,
        "stored_as": safe_name,
        "created_at": a.created_at.isoformat(),
    }


class IssueIn(BaseModel):
    assignment_id: int
    student_ids: List[int]


@app.get("/prof/assignments")
def prof_assignments_all(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")
    rows = db.query(Assignment).order_by(Assignment.created_at.desc()).all()
    return [{
        "id": a.id,
        "title": a.title,
        "template_hash": a.template_hash,
        "created_at": a.created_at.isoformat(),
    } for a in rows]

@app.post("/prof/assignments/issue")
def issue_assignment(inp: IssueIn, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor": raise HTTPException(403, "professor only")
    a = db.query(Assignment).get(inp.assignment_id)
    if not a: raise HTTPException(404, "assignment not found")

    # read template bytes
    file_bytes = open(a.template_path,"rb").read()

    issued = []
    for sid in inp.student_ids:
        student = db.query(User).get(sid)
        if not student: continue

        # Build header (immutable)
        header = {
            "assignmentID": a.id,
            "studentID": sid,
            "issueTimestamp": datetime.datetime.utcnow().isoformat()+"Z",
            "templateHash": a.template_hash,
            "algorithm": "AES-256-GCM + RSA-PSS-SHA256",
        }
        header_bytes = canonicalize_header(header)
        signature = rsa_sign_pss(priv, header_bytes)
        #header_hash = sha256_bytes(header_bytes)
        #signature = rsa_sign_pss(priv, bytes.fromhex(header_hash))

        # AES encrypt content with header as AAD
        import os
        key = os.urandom(32)  # 256-bit
        iv  = os.urandom(12)  # 96-bit
        ciphertext, tag = aes256gcm_encrypt(key, iv, file_bytes, header_bytes)

        # store ciphertext
        cpath = os.path.join(STORE, "ciphertext", f"ass{a.id}_stu{sid}_{int(datetime.datetime.utcnow().timestamp())}.bin")
        with open(cpath,"wb") as f: f.write(ciphertext)

        iss = Issuance(
            assignment_id=a.id, student_id=sid,
            header_json=header_bytes.decode(),
            signature_b64=b64e(signature),
            iv_b64=b64e(iv),
            ciphertext_path=cpath,
            tag_b64=b64e(tag),
            aes_key_b64=b64e(key),
            status="ISSUED"
        )
        db.add(iss); db.commit()
        issued.append({"issuance_id": iss.id, "student_id": sid})
    return {"ok": True, "issued": issued}
    
@app.get("/prof/issuances")
def prof_list_issuances_all(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    rows = db.query(Issuance).all()
    out = []
    for i in rows:
        stu = db.query(User).get(i.student_id)
        a = db.query(Assignment).get(i.assignment_id)
        sub = db.query(Submission).filter(Submission.issuance_id == i.id)\
                                  .order_by(Submission.submitted_at.desc()).first()
        hdr = json.loads(i.header_json)
        issued_at = hdr.get("issueTimestamp")

        out.append({
            "issuance_id": i.id,
            "assignment_id": i.assignment_id,
            "assignment_title": a.title if a else f"#{i.assignment_id}",
            "student": {"id": stu.id, "name": stu.name, "email": stu.email},
            "issued_at": issued_at,
            "status": i.status,   # ISSUED / DOWNLOADED / DECRYPTED / SUBMITTED
            "submission": None if not sub else {
                "submitted_at": sub.submitted_at.isoformat(),
                "status": sub.status,  # ACCEPTED / DUPLICATE / TAMPERED
                "answer_hash": (sub.answer_hash[:16] + "...") if sub.answer_hash else None,
                "file": os.path.basename(sub.file_path) if sub.file_path else None
            }
        })

    # newest issued first, then by student name
    out.sort(key=lambda r: (r["issued_at"] or "", r["student"]["name"].lower()), reverse=True)
    return out

@app.get("/prof/issuances/csv")
def prof_list_issuances_all_csv(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    data = prof_list_issuances_all(token, db)
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["IssuanceID","AssignmentID","AssignmentTitle","StudentName","StudentEmail","IssuedAt","IssuanceStatus","SubmissionStatus","SubmittedAt","AnswerHash","File"])
    for r in data:
        sub = r.get("submission") or {}
        w.writerow([
            r["issuance_id"], r["assignment_id"], r["assignment_title"],
            r["student"]["name"], r["student"]["email"],
            r.get("issued_at") or "",
            r["status"],
            sub.get("status") or "",
            sub.get("submitted_at") or "",
            sub.get("answer_hash") or "",
            sub.get("file") or "",
        ])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="issuances_all.csv"'})

@app.get("/prof/submissions")
def prof_list_submissions_all(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    subs = db.query(Submission).order_by(Submission.submitted_at.desc()).all()
    out = []
    for s in subs:
        iss = db.query(Issuance).get(s.issuance_id)
        a = db.query(Assignment).get(iss.assignment_id) if iss else None
        stu = db.query(User).get(s.student_id) if s.student_id else None
        out.append({
            "issuance_id": iss.id if iss else None,
            "assignment_id": iss.assignment_id if iss else None,
            "assignment_title": a.title if a else (f"#{iss.assignment_id}" if iss else "-"),
            "student": {"id": stu.id if stu else None, "name": (stu.name if stu else "-"), "email": (stu.email if stu else "-")},
            "submitted_at": s.submitted_at.isoformat(),
            "status": s.status,   # ACCEPTED / DUPLICATE / TAMPERED
            "answer_hash": (s.answer_hash[:16] + "...") if s.answer_hash else None,
            "file": os.path.basename(s.file_path) if s.file_path else None,
        })
    return out

@app.get("/prof/submissions/csv")
def prof_list_submissions_all_csv(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    data = prof_list_submissions_all(token, db)
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["IssuanceID","AssignmentID","AssignmentTitle","StudentName","StudentEmail","SubmittedAt","SubmissionStatus","AnswerHash","File"])
    for r in data:
        w.writerow([
            r.get("issuance_id") or "",
            r.get("assignment_id") or "",
            r.get("assignment_title") or "",
            r["student"]["name"], r["student"]["email"],
            r.get("submitted_at") or "",
            r["status"], r.get("answer_hash") or "", r.get("file") or "",
        ])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": 'attachment; filename="submissions_all.csv"'})



# ======== Student: My Issued Files ========
@app.get("/student/issued")
def student_issued(token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "student": raise HTTPException(403, "student only")
    q = db.query(Issuance).filter(Issuance.student_id==me.id).all()
    items = []
    for i in q:
        items.append({
            "issuance_id": i.id,
            "assignment_id": i.assignment_id,
            "header": json.loads(i.header_json),
            "issued_at": json.loads(i.header_json)["issueTimestamp"],
            "status": i.status
        })
    return items

# Download encrypted package (zip-like JSON for demo)
@app.get("/student/download/{issuance_id}")
def download_encrypted(issuance_id: int, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    i = db.query(Issuance).get(issuance_id)
    if not i or (me.role=="student" and i.student_id != me.id):
        raise HTTPException(404, "not found")

    # Build files for the package
    header_obj = json.loads(i.header_json)

    # For convenience, embed crypto fields in header.json too
    header_obj["signature_b64"] = i.signature_b64
    header_obj["iv_b64"] = i.iv_b64
    header_obj["tag_b64"] = i.tag_b64

    header_bytes = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature_bytes = base64.b64decode(i.signature_b64.encode())
    iv_bytes = base64.b64decode(i.iv_b64.encode())
    tag_bytes = base64.b64decode(i.tag_b64.encode())
    ct_bytes = open(i.ciphertext_path, "rb").read()

    # Create ZIP in memory
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("header.json", header_bytes)
        z.writestr("header.sig", signature_bytes)
        z.writestr("iv.bin", iv_bytes)
        z.writestr("tag.bin", tag_bytes)
        z.writestr("ciphertext.bin", ct_bytes)

    mem.seek(0)
    i.status = "DOWNLOADED"
    db.commit()

    # Nice filename: assignment_{id}_issuance_{id}.zip
    filename = f"assignment_{i.assignment_id}_issuance_{i.id}.zip"
    return StreamingResponse(mem, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


# Decrypt & stream plaintext (demo view)
@app.get("/student/decrypt/{issuance_id}")
def decrypt_and_stream(issuance_id: int, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    i = db.query(Issuance).get(issuance_id)
    if not i or (me.role=="student" and i.student_id != me.id):
        raise HTTPException(404, "not found")

    header_bytes = canonicalize_header(json.loads(i.header_json))
    signature = b64d(i.signature_b64)
    # verify signature first
    if not rsa_verify_pss(pub, header_bytes, signature):
        raise HTTPException(400, "Invalid header signature")
    #if not rsa_verify_pss(pub, bytes.fromhex(sha256_bytes(header_bytes)), signature):
        #raise HTTPException(400, "Invalid header signature")

    key = b64d(i.aes_key_b64)
    iv = b64d(i.iv_b64)
    tag = b64d(i.tag_b64)
    ct = open(i.ciphertext_path,"rb").read()

    try:
        pt = aes256gcm_decrypt(key, iv, ct, tag, header_bytes)
    except Exception:
        raise HTTPException(400, "Invalid tag/AAD: tampered or wrong key")

    # stream file
    # after successful decryption:
    out = os.path.join(STORE, "decrypted", f"issuance_{i.id}_decrypted.pdf")
    open(out,"wb").write(pt)

    # NEW: advance status if not yet submitted
    if i.status in ("ISSUED", "DOWNLOADED"):
        i.status = "DECRYPTED"
        db.commit()

    return FileResponse(out, filename=f"issuance_{i.id}_decrypted.pdf")
  

from fastapi.responses import StreamingResponse

@app.get("/student/view/{issuance_id}")
def view_decrypted_inline(issuance_id: int, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    i = db.query(Issuance).get(issuance_id)
    if not i or (me.role == "student" and i.student_id != me.id):
        raise HTTPException(404, "not found")

    # 1) verify header signature (immutability)
    header_bytes = canonicalize_header(json.loads(i.header_json))
    signature = b64d(i.signature_b64)
    if not rsa_verify_pss(pub, header_bytes, signature):
        raise HTTPException(400, "Invalid header signature")
    #if not rsa_verify_pss(pub, bytes.fromhex(sha256_bytes(header_bytes)), signature):
        #raise HTTPException(400, "Invalid header signature")

    # 2) decrypt in memory (no file saved)
    key = b64d(i.aes_key_b64)
    iv = b64d(i.iv_b64)
    tag = b64d(i.tag_b64)
    ct = open(i.ciphertext_path, "rb").read()
    try:
        pt = aes256gcm_decrypt(key, iv, ct, tag, header_bytes)
    except Exception:
        raise HTTPException(400, "Invalid tag/AAD: tampered or wrong key")

    # 3) update status
    if i.status in ("ISSUED", "DOWNLOADED"):
        i.status = "DECRYPTED"
        db.commit()

    # 4) stream inline as PDF (no download prompt)
    filename = f"issuance_{i.id}_decrypted.pdf"
    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "no-store",  # avoid caching
        "Pragma": "no-cache",
    }
    return StreamingResponse(io.BytesIO(pt), media_type="application/pdf", headers=headers)

@app.post("/student/decrypt/upload")
def decrypt_from_upload(token: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "student":
        raise HTTPException(403, "student only")

    # 1️⃣ Read uploaded ZIP into memory
    data = file.file.read()
    try:
        zbuf = io.BytesIO(data)
        with zipfile.ZipFile(zbuf, "r") as z:
            header_bytes_full = z.read("header.json")
            sig_bytes = z.read("header.sig")
            iv_bytes = z.read("iv.bin")
            tag_bytes = z.read("tag.bin")
            ct_bytes = z.read("ciphertext.bin")
    except Exception:
        raise HTTPException(400, "Invalid package: missing or corrupt files")

    # 2️⃣ Canonicalize header for signature & AAD
    try:
        header_full = json.loads(header_bytes_full.decode("utf-8"))
        header_canonical_obj = {
            "assignmentID": header_full["assignmentID"],
            "studentID": header_full["studentID"],
            "issueTimestamp": header_full["issueTimestamp"],
            "templateHash": header_full["templateHash"],
            "algorithm": header_full.get("algorithm", "AES-256-GCM + RSA-PSS-SHA256"),
        }
        header_bytes = canonicalize_header(header_canonical_obj)
    except Exception:
        raise HTTPException(400, "Invalid header.json")

    # 3️⃣ Verify RSA signature
    #if not rsa_verify_pss(pub, bytes.fromhex(sha256_bytes(header_bytes)), sig_bytes):
    if not rsa_verify_pss(pub, header_bytes, sig_bytes):
        # Mark tampered for audit
        try:
            candidate = db.query(Issuance).filter(
                Issuance.assignment_id == header_canonical_obj["assignmentID"],
                Issuance.student_id == me.id
            ).first()
            if candidate and candidate.status != "SUBMITTED":
                candidate.status = "TAMPERED"
                db.commit()
        except Exception:
            pass
        raise HTTPException(400, "Header signature verification failed (tampered)")

    # 4️⃣ Find matching issuance record
    assignment_id = int(header_canonical_obj["assignmentID"])
    student_id = int(header_canonical_obj["studentID"])
    issued_at = header_canonical_obj["issueTimestamp"]

    candidates = db.query(Issuance).filter(
        Issuance.assignment_id == assignment_id,
        Issuance.student_id == me.id
    ).all()

    target = None
    for i in candidates:
        try:
            h = json.loads(i.header_json)
            if (
                int(h["assignmentID"]) == assignment_id
                and int(h["studentID"]) == student_id
                and h["issueTimestamp"] == issued_at
            ):
                target = i
                break
        except Exception:
            continue

    if not target:
        raise HTTPException(404, "Matching issuance not found for this package")

    # 5️⃣ Verify templateHash matches DB
    a = db.query(Assignment).get(assignment_id)
    if not a:
        raise HTTPException(404, "Assignment not found")
    if header_canonical_obj["templateHash"] != a.template_hash:
        target.status = "TAMPERED"
        db.commit()
        raise HTTPException(400, "Template hash mismatch (package tampered)")

    # 6️⃣ AES-GCM decryption
    key = b64d(target.aes_key_b64)
    try:
        pt = aes256gcm_decrypt(key, iv_bytes, ct_bytes, tag_bytes, header_bytes)
    except Exception:
        target.status = "TAMPERED"
        db.commit()
        raise HTTPException(400, "Decryption failed (tampered or wrong key)")

    # 7️⃣ Update status after success
    if target.status in ("ISSUED", "DOWNLOADED"):
        target.status = "DECRYPTED"
        db.commit()

    # 8️⃣ Stream decrypted PDF inline
    filename = f"issuance_{target.id}_decrypted.pdf"
    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }
    return StreamingResponse(io.BytesIO(pt), media_type="application/pdf", headers=headers)




# ======== Student: Submit answers ========
@app.post("/student/submit/{issuance_id}")
def submit_answer(issuance_id: int, token: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "student": raise HTTPException(403, "student only")
    i = db.query(Issuance).get(issuance_id)
    if not i or i.student_id != me.id:
        raise HTTPException(404, "not found")

    # save submission
    spath = os.path.join(STORE, "submissions", f"iss{i.id}_{int(datetime.datetime.now(datetime.timezone.utc).timestamp())}_{file.filename}")
    with open(spath,"wb") as f: shutil.copyfileobj(file.file, f)

    # compute answerHash (hash of raw bytes for demo; your thesis uses answers/ region)
    answer_hash = sha256_bytes(open(spath,"rb").read())

    # duplicate check (same answerHash)
    dup = db.query(Submission).filter(Submission.answer_hash==answer_hash, Submission.issuance_id!=i.id).first() #duplicate across different issuances
    #dup = db.query(Submission).filter(Submission.answer_hash == answer_hash).first() #global duplicates
    status_flag = "DUPLICATE" if dup else "ACCEPTED"

    sub = Submission(issuance_id=i.id, student_id=me.id, file_path=spath, answer_hash=answer_hash, status=status_flag)
    i.status = "SUBMITTED"
    db.add(sub); db.commit()
    #return {"ok": True, "status": status_flag, "answer_hash": answer_hash}
    return {"status": status_flag}

# ======== Professor: View submissions ========
@app.get("/prof/submissions/{assignment_id}")
def prof_submissions(assignment_id: int, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor": raise HTTPException(403, "professor only")

    # collect by assignment
    out = []
    iss = db.query(Issuance).filter(Issuance.assignment_id==assignment_id).all()
    for i in iss:
        subs = db.query(Submission).filter(Submission.issuance_id==i.id).all()
        for s in subs:
            out.append({
                "issuance_id": i.id,
                "student_id": i.student_id,
                "submitted_at": s.submitted_at.isoformat(),
                "status": s.status,
                "answer_hash": s.answer_hash,
                "file": os.path.basename(s.file_path),
            })
    return out
    
@app.get("/prof/issuances/{assignment_id}")
def prof_list_issuances(assignment_id: int, token: str, db: Session = Depends(get_db)):
    me = jwt_current(db, token)
    if me.role != "professor":
        raise HTTPException(403, "professor only")

    rows = db.query(Issuance).filter(Issuance.assignment_id == assignment_id).all()
    out = []
    for i in rows:
        # student info
        stu = db.query(User).get(i.student_id)
        # last submission (if any)
        sub = db.query(Submission).filter(Submission.issuance_id == i.id)\
                                  .order_by(Submission.submitted_at.desc()).first()
        # issued_at from header
        hdr = json.loads(i.header_json)
        issued_at = hdr.get("issueTimestamp")

        out.append({
            "issuance_id": i.id,
            "assignment_id": i.assignment_id,
            "student": {
                "id": stu.id,
                "name": stu.name,
                "email": stu.email,
            },
            "issued_at": issued_at,
            "status": i.status,                     # ISSUED/DOWNLOADED/DECRYPTED/SUBMITTED
            "submission": None if not sub else {
                "submitted_at": sub.submitted_at.isoformat(),
                "status": sub.status,              # ACCEPTED / DUPLICATE / TAMPERED
                "answer_hash": sub.answer_hash[:16] + "..." if sub.answer_hash else None,
                "file": os.path.basename(sub.file_path) if sub.file_path else None
            }
        })
    # sort by student name for readability
    out.sort(key=lambda r: r["student"]["name"].lower())
    return out

# === Demo API for Crypto Lab ===
from fastapi import Form
from fastapi.responses import JSONResponse

def _canon_from_text(header_text: str) -> bytes:
    try:
        obj = json.loads(header_text)
    except Exception:
        raise HTTPException(400, "header_json is not valid JSON")
    # Only the immutable header fields belong to AAD/signature
    canon_obj = {
        "assignmentID": obj["assignmentID"],
        "studentID": obj["studentID"],
        "issueTimestamp": obj["issueTimestamp"],
        "templateHash": obj["templateHash"],
        "algorithm": obj.get("algorithm", "AES-256-GCM + RSA-PSS-SHA256"),
    }
    return canonicalize_header(canon_obj)

@app.post("/api/demo/sign-header")
def demo_sign_header(header_json: str = Form(...)):
    aad = _canon_from_text(header_json)
    # Sign the raw canonical bytes (matches the rest of your app now)
    sig = rsa_sign_pss(priv, aad)
    return {
        "canonicalAAD": aad.decode("utf-8"),
        "signatureHex": sig.hex(),
        "verified": rsa_verify_pss(pub, aad, sig),
    }

@app.post("/api/demo/verify-header")
def demo_verify_header(
    header_json: str = Form(...),
    signatureHex: str = Form(...)
):
    aad = _canon_from_text(header_json)
    try:
        sig = bytes.fromhex(signatureHex.strip())
    except Exception:
        raise HTTPException(400, "signatureHex must be hex")
    ok = rsa_verify_pss(pub, aad, sig)
    return {"canonicalAAD": aad.decode("utf-8"), "verified": ok}

@app.post("/api/demo/aes-gcm-encrypt")
def demo_aes_gcm_encrypt(header_json: str = Form(...), file: UploadFile = File(...)):
    aad = _canon_from_text(header_json)

    # read file
    data = file.file.read()
    key = os.urandom(32)
    iv  = os.urandom(12)
    ct, tag = aes256gcm_encrypt(key, iv, data, aad)

    # sign header for the ZIP (separate file header.sig)
    sig = rsa_sign_pss(priv, aad)

    # build a demo ZIP (same layout as your student download)
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("header.json", aad)      # canonical JSON only
        z.writestr("header.sig", sig)
        z.writestr("iv.bin", iv)
        z.writestr("tag.bin", tag)
        z.writestr("ciphertext.bin", ct)
    mem.seek(0)
    zip_b64 = base64.b64encode(mem.getvalue()).decode()

    return {
        "aad": aad.decode("utf-8"),
        "keyB64": base64.b64encode(key).decode(),
        "ivB64": base64.b64encode(iv).decode(),
        "ciphertextB64": base64.b64encode(ct).decode(),
        "tagB64": base64.b64encode(tag).decode(),
        "fileName": file.filename or "file",
        "fileSize": len(data),
        "zipB64": zip_b64,
    }

@app.post("/api/demo/aes-gcm-decrypt")
def demo_aes_gcm_decrypt(
    keyB64: str = Form(...),
    ivB64: str = Form(...),
    aad: str = Form(...),
    ciphertextB64: str = Form(...),
    tagB64: str = Form(...),
):
    try:
        key = base64.b64decode(keyB64)
        iv  = base64.b64decode(ivB64)
        ct  = base64.b64decode(ciphertextB64)
        tag = base64.b64decode(tagB64)
        aad_bytes = aad.encode("utf-8")
    except Exception:
        raise HTTPException(400, "Invalid base64 or inputs")

    try:
        pt = aes256gcm_decrypt(key, iv, ct, tag, aad_bytes)
    except Exception as e:
        return JSONResponse(status_code=400, content={"detail": "Decryption failed (AAD/tag mismatch or bad key)"})

    return {
        "plaintextSize": len(pt),
        "plaintextB64": base64.b64encode(pt).decode(),
    }



# ======== Seed demo users ========
@app.on_event("startup")
def seed_users():
    db = SessionLocal()
    try:
        def ensure(email, name, role):
            if not db.query(User).filter(User.email == email).first():
                db.add(User(
                    email=email,
                    name=name,
                    role=role,
                    password_hash=pwdctx.hash("Passw0rd!")
                ))

        ensure("prof.carig@docutrack.edu", "Dr. Nowee Carig", "professor")
        ensure("k.lewins@docutrack.edu", "Kurt Lewins", "student")
        ensure("t.capulong@docutrack.edu", "Timothy Capulong", "student")
        ensure("j.fabian@docutrack.edu", "Jeremy Fabian", "student")

        db.commit()
    finally:
        db.close()

