from __future__ import annotations
import os, json, uuid, io, zipfile
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from .crypto import (
    sha256_hex, canonical_json_bytes, rsa_pss_sign, rsa_pss_verify,
    aes_gcm_encrypt, load_private_key, load_public_key,
    build_issue_package_zip, hash_answers_dir_to_hex, recompute_plaintext_hash_from_zip,
    now_utc_iso
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- PATHS & SETUP ---
BASE = Path(__file__).resolve().parent
STORAGE = BASE / "storage"
KEYS = BASE / "keys"
STORAGE.mkdir(exist_ok=True)

PRIV_KEY_PATH = KEYS / "server_private.pem"
PUB_KEY_PATH = KEYS / "server_public.pem"

app = FastAPI(title="DocuTrack Local Demo API", version="1.2 (decrypt endpoint + meta)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # OK for local/LAN demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- STATE HANDLERS ---
def load_state() -> Dict[str, Any]:
    path = STORAGE / "state.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"assignments": {}, "submissions": []}

def save_state(state: Dict[str, Any]) -> None:
    (STORAGE / "state.json").write_text(json.dumps(state, indent=2))

def require_keys():
    if not PRIV_KEY_PATH.exists() or not PUB_KEY_PATH.exists():
        raise HTTPException(status_code=500, detail="Server keys not found. Run: python generate_keys.py")

# --- BASIC ROUTES ---
@app.get("/")
def root():
    return {"message": "DocuTrack API OK", "version": "1.2"}

@app.get("/api/public-key")
def get_public_key():
    require_keys()
    return JSONResponse({"publicKeyPEM": PUB_KEY_PATH.read_text()})

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...), role: str = Form("professor")):
    # Demo-only: accept any non-empty username/password; in production use Argon2id.
    if not username or not password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"ok": True, "role": role}

# --- CREATE ASSIGNMENT ---
@app.post("/api/assignments")
async def create_assignment(
    title: str = Form(...),
    roster_json: str = Form(...),
    template: UploadFile = File(...),
):
    """
    Stores the uploaded template, computes templateHash, saves roster and templateName.
    """
    require_keys()
    tpl_bytes = await template.read()
    template_name = template.filename or "template.bin"

    assignment_id = "A" + uuid.uuid4().hex[:6].upper()
    folder = STORAGE / assignment_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "template.bin").write_bytes(tpl_bytes)

    template_hash = sha256_hex(tpl_bytes)
    roster = json.loads(roster_json)
    (folder / "roster.json").write_text(json.dumps(roster, indent=2))

    state = load_state()
    state["assignments"][assignment_id] = {
        "title": title,
        "templateHash": template_hash,
        "templateName": template_name,
        "issued": False,
        "roster": roster,
    }
    save_state(state)
    return {
        "assignmentID": assignment_id,
        "title": title,
        "templateHash": template_hash,
        "templateName": template_name,
        "rosterCount": len(roster)
    }

# --- ISSUE ASSIGNMENT (include plaintext in ZIP + save AES key/iv meta) ---
@app.post("/api/assignments/{assignment_id}/issue")
def issue_assignment(assignment_id: str):
    """
    For each student:
      - header = { assignmentID, studentID, issueTimestamp, templateHash, templateName }
      - RSA-PSS-SHA256(header)
      - AES-256-GCM(template.bin, AAD=header)
      - ZIP contains: header.json, header.sig, iv.bin, ciphertext.bin, <templateName>, answers/
      - Save meta JSON per student: { key, iv, origName }
    """
    require_keys()
    state = load_state()
    info = state["assignments"].get(assignment_id)
    if not info:
        raise HTTPException(status_code=404, detail="Assignment not found")

    folder = STORAGE / assignment_id
    template_bytes = (folder / "template.bin").read_bytes()
    template_hash = info["templateHash"]
    template_name = info.get("templateName", "template.bin")

    priv = load_private_key(str(PRIV_KEY_PATH))
    packages_dir = folder / "packages"
    packages_dir.mkdir(exist_ok=True)

    count = 0
    for student_id in info["roster"]:
        header = {
            "assignmentID": assignment_id,
            "studentID": student_id,
            "issueTimestamp": now_utc_iso(),
            "templateHash": template_hash,
            "templateName": template_name,
        }
        header_c14n = canonical_json_bytes(header)
        sig = rsa_pss_sign(priv, header_c14n)

        key = os.urandom(32)  # 256-bit AES key
        iv = os.urandom(12)   # 96-bit IV
        ciphertext = aes_gcm_encrypt(key, iv, template_bytes, aad=header_c14n)

        # Build package: includes ciphertext and a readable plaintext copy for demo
        pkg_bytes = build_issue_package_zip(
            header_obj=header,
            signature=sig,
            iv=iv,
            ciphertext=ciphertext,
            plaintext_name=template_name,
            plaintext_bytes=template_bytes,
        )
        pkg_path = packages_dir / f"{assignment_id}_{student_id}.zip"
        pkg_path.write_bytes(pkg_bytes)

        # Save meta with key/iv so server can decrypt later on /view endpoint
        meta = {"key": key.hex(), "iv": iv.hex(), "origName": template_name}
        (packages_dir / f"{assignment_id}_{student_id}.meta.json").write_text(json.dumps(meta))

        count += 1

    info["issued"] = True
    save_state(state)
    return {"ok": True, "issuedTo": count, "templateName": template_name}

# --- DOWNLOAD PACKAGE ---
@app.get("/api/assignments/{assignment_id}/packages/{student_id}")
def download_package(assignment_id: str, student_id: str):
    file = STORAGE / assignment_id / "packages" / f"{assignment_id}_{student_id}.zip"
    if not file.exists():
        raise HTTPException(status_code=404, detail="Package not found")
    return FileResponse(str(file), media_type="application/zip", filename=file.name)

# --- NEW: VIEW (DECRYPT) ENDPOINT ---
@app.get("/api/assignments/{assignment_id}/view/{student_id}")
def view_plaintext(assignment_id: str, student_id: str):
    """
    Verifies header signature, decrypts ciphertext.bin with AES-256-GCM (AAD=header), streams PDF.
    Requires per-student .meta.json saved at issuance.
    """
    require_keys()
    folder = STORAGE / assignment_id / "packages"
    zip_path = folder / f"{assignment_id}_{student_id}.zip"
    meta_path = folder / f"{assignment_id}_{student_id}.meta.json"
    if not zip_path.exists() or not meta_path.exists():
        raise HTTPException(status_code=404, detail="Package or metadata not found")

    meta = json.loads(meta_path.read_text())
    key = bytes.fromhex(meta["key"])
    iv = bytes.fromhex(meta["iv"])
    orig_name = meta.get("origName", "template.bin")

    # Extract header/ciphertext and verify signature
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            header_obj = json.loads(z.read("header.json").decode("utf-8"))
            sig_hex = z.read("header.sig").decode("utf-8").strip()
            header_c14n = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ct = z.read("ciphertext.bin")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ZIP package")

    pub = load_public_key(str(PUB_KEY_PATH))
    if not rsa_pss_verify(pub, header_c14n, bytes.fromhex(sig_hex)):
        raise HTTPException(status_code=400, detail="Signature verification failed")

    # Decrypt
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ct, header_c14n)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed (auth tag mismatch)")

    # Stream as PDF if it looks like one, otherwise generic binary
    media = "application/pdf" if orig_name.lower().endswith(".pdf") else "application/octet-stream"
    return Response(
        content=plaintext,
        media_type=media,
        headers={"Content-Disposition": f'inline; filename="{orig_name}"'}
    )

# --- SUBMIT & VERIFY ---
@app.post("/api/submit")
async def submit_file(
    assignmentID: str = Form(...),
    studentID: str = Form(...),
    package: UploadFile = File(...),
):
    """
    Verifies:
      - header signature (RSA-PSS-SHA256)
      - IDs and templateHash (against server state)
      - recompute SHA-256 of included plaintext file <templateName> and compare to templateHash
      - compute answerHash (answers/ dir) and flag duplicates
    """
    require_keys()
    state = load_state()
    info = state["assignments"].get(assignmentID)
    if not info:
        raise HTTPException(status_code=404, detail="Assignment not found")

    pkg_bytes = await package.read()

    # Extract header + signature
    try:
        with zipfile.ZipFile(io.BytesIO(pkg_bytes), "r") as z:
            header_obj = json.loads(z.read("header.json").decode("utf-8"))
            sig_hex = z.read("header.sig").decode("utf-8").strip()
            header_c14n = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ZIP package")

    # Verify header signature
    pub = load_public_key(str(PUB_KEY_PATH))
    if not rsa_pss_verify(pub, header_c14n, bytes.fromhex(sig_hex)):
        return {"ok": False, "status": "INVALID_SIGNATURE"}

    # Metadata checks
    if header_obj.get("assignmentID") != assignmentID or header_obj.get("studentID") != studentID:
        return {"ok": False, "status": "MISMATCH_METADATA"}

    if header_obj.get("templateHash") != info["templateHash"]:
        return {"ok": False, "status": "WRONG_TEMPLATE"}

    # Tamper detection for plaintext copy: recompute hash of included template file
    template_name = header_obj.get("templateName") or info.get("templateName", "template.bin")
    recomputed = recompute_plaintext_hash_from_zip(pkg_bytes, template_name)
    if recomputed is None:
        return {"ok": False, "status": "MISSING_TEMPLATE_FILE"}
    if recomputed.lower() != info["templateHash"].lower():
        # student modified the readable template => tampered
        return {"ok": False, "status": "TAMPERED_TEMPLATE"}

    # Duplicate detection via answerHash
    answer_hash = hash_answers_dir_to_hex(pkg_bytes)
    dup = any(
        s["assignmentID"] == assignmentID and
        s["answerHash"] == answer_hash and
        s["studentID"] != studentID
        for s in state["submissions"]
    )

    record = {
        "assignmentID": assignmentID,
        "studentID": studentID,
        "answerHash": answer_hash,
        "status": "DUPLICATE" if dup else "ACCEPTED",
        "received": now_utc_iso()
    }
    state["submissions"].append(record)
    save_state(state)

    return {"ok": True, "duplicate": dup, "answerHash": answer_hash, "status": record["status"]}

# --- VIEW SUBMISSIONS ---
@app.get("/api/submissions/{assignment_id}")
def list_submissions(assignment_id: str):
    state = load_state()
    rows = [s for s in state["submissions"] if s["assignmentID"] == assignment_id]
    return {"count": len(rows), "items": rows}


# ========= DEMO / VISUALIZER ENDPOINTS (for defense only) =========
from fastapi import Body
from base64 import b64encode, b64decode
from io import BytesIO
import zipfile

def _b64(x: bytes) -> str: return b64encode(x).decode("ascii")
def _b(x: str) -> bytes: return b64decode(x.encode("ascii"))

@app.post("/api/demo/sign-header")
def demo_sign_header(header_json: str = Form(...)):
    """
    Input: header_json (string, any JSON) 
    Output: canonical JSON (AAD), signature (RSA-PSS-SHA256)
    """
    require_keys()
    try:
        hdr = json.loads(header_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    aad = canonical_json_bytes(hdr)
    priv = load_private_key(str(PRIV_KEY_PATH))
    sig = rsa_pss_sign(priv, aad)
    pub = load_public_key(str(PUB_KEY_PATH))
    ok = rsa_pss_verify(pub, aad, sig)
    return {
        "canonicalAAD": aad.decode("utf-8"),
        "signatureHex": sig.hex(),
        "verified": ok
    }

@app.post("/api/demo/verify-header")
def demo_verify_header(header_json: str = Form(...), signatureHex: str = Form(...)):
    """
    Verifies RSA-PSS over canonicalized header JSON.
    """
    require_keys()
    try:
        hdr = json.loads(header_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    aad = canonical_json_bytes(hdr)
    sig = bytes.fromhex(signatureHex.strip())
    pub = load_public_key(str(PUB_KEY_PATH))
    ok = rsa_pss_verify(pub, aad, sig)
    return {"canonicalAAD": aad.decode("utf-8"), "verified": ok}

@app.post("/api/demo/aes-gcm-encrypt")
async def demo_aes_gcm_encrypt(
    header_json: str = Form(...),
    file: UploadFile = File(...),
):
    """
    Encrypts the uploaded file with AES-256-GCM using canonical(header_json) as AAD.
    Returns base64 key, iv, aad, ciphertext, tag (separated).
    Also returns a demo ZIP for download.
    """
    try:
        hdr = json.loads(header_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid header JSON")

    aad = canonical_json_bytes(hdr)
    key = os.urandom(32)
    iv = os.urandom(12)
    data = await file.read()

    # AESGCM returns ciphertext||tag; split last 16 bytes
    ct_all = aes_gcm_encrypt(key, iv, data, aad=aad)
    ct, tag = ct_all[:-16], ct_all[-16:]

    # Build a demo ZIP (also includes plaintext to visualize round-trip)
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("header.json", json.dumps(hdr, indent=2))
        z.writestr("aad.txt", aad.decode("utf-8"))
        z.writestr("iv.bin", iv)
        z.writestr("ciphertext.bin", ct + tag)
        z.writestr("plaintext.bin", data)
        z.writestr("README.txt",
            "Crypto Lab demo package\n"
            "- header.json (visual AAD source)\n"
            "- aad.txt (canonical JSON used as AAD)\n"
            "- iv.bin\n"
            "- ciphertext.bin (AES-256-GCM; last 16 bytes are tag)\n"
            "- plaintext.bin (for human demo inspection)\n")

    return {
        "keyB64": _b64(key),
        "ivB64": _b64(iv),
        "aad": aad.decode("utf-8"),
        "ciphertextB64": _b64(ct),
        "tagB64": _b64(tag),
        "zipB64": _b64(zip_buf.getvalue()),
        "fileName": file.filename or "file.bin",
        "fileSize": len(data)
    }

@app.post("/api/demo/aes-gcm-decrypt")
def demo_aes_gcm_decrypt(
    keyB64: str = Form(...),
    ivB64: str = Form(...),
    aad: str = Form(...),
    ciphertextB64: str = Form(...),
    tagB64: str = Form(...),
):
    """
    Decrypts provided AES-256-GCM inputs. On success returns plaintext (base64).
    On failure raises 400 (auth tag mismatch).
    """
    key = _b(keyB64); iv = _b(ivB64); aad_bytes = aad.encode("utf-8")
    ct = _b(ciphertextB64); tag = _b(tagB64)
    ct_all = ct + tag
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(iv, ct_all, aad_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed (tag mismatch or wrong inputs)")
    return {"ok": True, "plaintextB64": _b64(pt), "plaintextSize": len(pt)}
