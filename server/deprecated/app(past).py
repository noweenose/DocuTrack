from __future__ import annotations
import os, json, uuid, io, zipfile
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

from .crypto import (
    sha256_hex, canonical_json_bytes, rsa_pss_sign, rsa_pss_verify,
    aes_gcm_encrypt, load_private_key, load_public_key,
    build_issue_package_zip, hash_answers_dir_to_hex, now_utc_iso
)

# --- PATHS & SETUP ---
BASE = Path(__file__).resolve().parent
STORAGE = BASE / "storage"
KEYS = BASE / "keys"
STORAGE.mkdir(exist_ok=True)

PRIV_KEY_PATH = KEYS / "server_private.pem"
PUB_KEY_PATH = KEYS / "server_public.pem"

app = FastAPI(title="DocuTrack Local Demo API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for local testing
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
    return {"message": "DocuTrack Local API running", "version": "1.0"}

@app.get("/api/public-key")
def get_public_key():
    require_keys()
    return JSONResponse({"publicKeyPEM": PUB_KEY_PATH.read_text()})

@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...), role: str = Form("professor")):
    """
    Simple local authentication for demo.
    In production, replace with Argon2id password check.
    """
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
    Creates a new assignment:
    - Stores uploaded template file.
    - Computes SHA-256 templateHash.
    - Saves student roster.
    """
    require_keys()
    tpl_bytes = await template.read()
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
        "issued": False,
        "roster": roster,
    }
    save_state(state)
    return {
        "assignmentID": assignment_id,
        "title": title,
        "templateHash": template_hash,
        "rosterCount": len(roster)
    }

# --- ISSUE ASSIGNMENT ---
@app.post("/api/assignments/{assignment_id}/issue")
def issue_assignment(assignment_id: str):
    """
    Issues personalized copies for all students:
    - Builds immutable header
    - RSA-PSS-SHA256 signature
    - AES-256-GCM encryption
    - Packages ZIP per student
    """
    require_keys()
    state = load_state()
    info = state["assignments"].get(assignment_id)
    if not info:
        raise HTTPException(status_code=404, detail="Assignment not found")

    folder = STORAGE / assignment_id
    template_bytes = (folder / "template.bin").read_bytes()
    template_hash = info["templateHash"]

    priv = load_private_key(str(PRIV_KEY_PATH))
    packages_dir = folder / "packages"
    packages_dir.mkdir(exist_ok=True)

    count = 0
    for student_id in info["roster"]:
        header = {
            "assignmentID": assignment_id,
            "studentID": student_id,
            "issueTimestamp": now_utc_iso(),
            "templateHash": template_hash
        }
        header_c14n = canonical_json_bytes(header)
        sig = rsa_pss_sign(priv, header_c14n)

        key = os.urandom(32)  # AES-256 key
        iv = os.urandom(12)   # 96-bit IV
        ciphertext = aes_gcm_encrypt(key, iv, template_bytes, aad=header_c14n)

        pkg_bytes = build_issue_package_zip(header, sig, iv, ciphertext)
        pkg_path = packages_dir / f"{assignment_id}_{student_id}.zip"
        pkg_path.write_bytes(pkg_bytes)
        count += 1

    info["issued"] = True
    save_state(state)
    return {"ok": True, "issuedTo": count}

# --- DOWNLOAD PACKAGE ---
@app.get("/api/assignments/{assignment_id}/packages/{student_id}")
def download_package(assignment_id: str, student_id: str):
    file = STORAGE / assignment_id / "packages" / f"{assignment_id}_{student_id}.zip"
    if not file.exists():
        raise HTTPException(status_code=404, detail="Package not found")
    return FileResponse(str(file), media_type="application/zip", filename=file.name)

# --- SUBMISSION & VERIFICATION ---
@app.post("/api/submit")
async def submit_file(
    assignmentID: str = Form(...),
    studentID: str = Form(...),
    package: UploadFile = File(...),
):
    """
    Verifies a submitted ZIP:
    - Validates header signature (RSA-PSS)
    - Checks templateHash and metadata
    - Computes answerHash (SHA-256)
    - Flags duplicates
    """
    require_keys()
    state = load_state()
    info = state["assignments"].get(assignmentID)
    if not info:
        raise HTTPException(status_code=404, detail="Assignment not found")

    pkg_bytes = await package.read()

    # Extract header and signature
    try:
        with zipfile.ZipFile(io.BytesIO(pkg_bytes), "r") as z:
            header_obj = json.loads(z.read("header.json").decode("utf-8"))
            sig_hex = z.read("header.sig").decode("utf-8").strip()
            header_c14n = json.dumps(header_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ZIP package")

    pub = load_public_key(str(PUB_KEY_PATH))
    if not rsa_pss_verify(pub, header_c14n, bytes.fromhex(sig_hex)):
        return {"ok": False, "status": "INVALID_SIGNATURE"}

    if header_obj.get("assignmentID") != assignmentID or header_obj.get("studentID") != studentID:
        return {"ok": False, "status": "MISMATCH_METADATA"}

    if header_obj.get("templateHash") != info["templateHash"]:
        return {"ok": False, "status": "WRONG_TEMPLATE"}

    # Compute answerHash
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
