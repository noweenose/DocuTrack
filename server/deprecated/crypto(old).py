from __future__ import annotations
import os, json, zipfile, io
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Hashing ----------
def sha256_bytes(data: bytes) -> bytes:
    d = hashes.Hash(hashes.SHA256())
    d.update(data)
    return d.finalize()

def sha256_hex(data: bytes) -> str:
    return sha256_bytes(data).hex()

# Canonical JSON: sorted keys, compact — used for signing and as AAD
def canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

# ---------- RSA-PSS (SHA-256) ----------
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def rsa_pss_sign(priv, message: bytes) -> bytes:
    return priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )

def rsa_pss_verify(pub, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# ---------- AES-256-GCM ----------
def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, plaintext, aad)  # ciphertext || tag

def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, aad)

# ---------- Answer hashing (from answers/ in ZIP) ----------
def hash_answers_dir_to_hex(zip_bytes: bytes) -> str:
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, "r") as z:
        entries: List[Tuple[str, str]] = []
        for name in z.namelist():
            if name.endswith("/"):
                continue
            parts = name.split("/")
            if len(parts) >= 2 and parts[0].lower() == "answers":
                data = z.read(name)
                h = sha256_hex(data)
                norm = "/".join(parts).lower()
                entries.append((norm, h))
        entries.sort(key=lambda t: t[0])
        combined = "\n".join([f"{p}|{h}" for p, h in entries]).encode("utf-8")
        return sha256_hex(combined)

# ---------- Tamper check: recompute template hash from included plaintext ----------
def recompute_plaintext_hash_from_zip(zip_bytes: bytes, expected_name: str) -> str | None:
    """
    Looks for the plaintext template (expected_name) at ZIP root and returns its SHA-256 hex.
    Returns None if not found.
    """
    buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(buf, "r") as z:
        names = {n: n for n in z.namelist() if not n.endswith("/")}
        target = None
        for n in names:
            if n.lower() == expected_name.lower():
                target = n
                break
        if target is None:
            return None
        return sha256_hex(z.read(target))

# ---------- Package builder ----------
def build_issue_package_zip(
    header_obj: Dict[str, Any],
    signature: bytes,
    iv: bytes,
    ciphertext: bytes,
    plaintext_name: str,
    plaintext_bytes: bytes,
) -> bytes:
    """
    Build a ZIP containing:
      - header.json, header.sig, iv.bin, ciphertext.bin
      - <plaintext_name> (readable copy of the template for demo)
      - answers/README.txt and README.txt
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("header.json", json.dumps(header_obj, indent=2))
        z.writestr("header.sig", signature.hex())
        z.writestr("iv.bin", iv)
        z.writestr("ciphertext.bin", ciphertext)
        z.writestr(plaintext_name, plaintext_bytes)
        z.writestr("answers/README.txt", "Place your answers here before re-zipping.")
        z.writestr(
            "README.txt",
            "DocuTrack Issued Package\n"
            "- header.json is immutable and RSA-PSS-SHA256 signed.\n"
            "- ciphertext.bin is the AES-256-GCM encrypted template (tamper-evident).\n"
            "- A readable copy of the template is included for demo.\n"
            "- Put your files inside 'answers/' then re-zip for submission.\n"
        )
    return buf.getvalue()

# ---------- Time helper ----------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
