"""Generates an RSA keypair for local dev/testing only, and writes:
  - dev/jwks/private_key.pem  (used by scripts/mint_token.py to sign test JWTs)
  - dev/jwks/jwks.json        (served by the jwks-mock nginx container)

Not for production use — Aegis's real deployments point tenant_configs at the
customer's actual IdP (Okta/Entra) JWKS endpoints.
"""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parent.parent
JWKS_DIR = ROOT / "dev" / "jwks"
KID = "dev-key-1"


def b64url_uint(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def main() -> None:
    JWKS_DIR.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (JWKS_DIR / "private_key.pem").write_bytes(private_pem)

    public_numbers = key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": b64url_uint(public_numbers.n),
                "e": b64url_uint(public_numbers.e),
            }
        ]
    }
    (JWKS_DIR / "jwks.json").write_text(json.dumps(jwks, indent=2))
    print(f"wrote {JWKS_DIR / 'private_key.pem'} and {JWKS_DIR / 'jwks.json'}")


if __name__ == "__main__":
    main()
