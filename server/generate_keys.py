from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEY_DIR = Path(__file__).resolve().parent / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)

priv_path = KEY_DIR / "server_private.pem"
pub_path = KEY_DIR / "server_public.pem"

if priv_path.exists():
    print("Keys already exist.")
    raise SystemExit(0)

print("Generating RSA-3072 keypair... (this may take a minute)")
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
priv_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
priv_path.write_bytes(priv_pem)
pub_path.write_bytes(pub_pem)
print("Created:", priv_path, pub_path)
