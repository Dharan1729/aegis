"""Mints a test JWT signed with dev/jwks/private_key.pem, matching the `kid`
in dev/jwks/jwks.json so aegis-server's PyJWKClient can verify it.

Usage:
    python scripts/mint_token.py --sub alice --role Analyst
    python scripts/mint_token.py --sub agent-1 --agent_name sql_agent
    python scripts/mint_token.py --sub you --iss https://idp.aegis-admin.test \\
        --scope aegis:admin  # dev admin token — see app/config.py's admin_oidc_* settings
"""

import argparse
import functools
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parent.parent
KEY_PATH = ROOT / "dev" / "jwks" / "private_key.pem"
KID = "dev-key-1"


@functools.cache
def _private_key():
    # Parsed once: parsing the PEM on every call made minting ~45 ms/token.
    return load_pem_private_key(KEY_PATH.read_bytes(), password=None)


def mint(sub: str, ttl_seconds: int = 300, iss: str | None = None, **extra_claims: str) -> str:
    now = int(time.time())
    claims = {
        "sub": sub,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
        **extra_claims,
    }
    if iss:
        claims["iss"] = iss
    return jwt.encode(claims, _private_key(), algorithm="RS256", headers={"kid": KID})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sub", required=True)
    parser.add_argument("--role", default="")
    parser.add_argument("--department", default="")
    parser.add_argument("--agent_name", default="")
    parser.add_argument("--iss", default="")
    parser.add_argument("--scope", default="", help="e.g. aegis:admin, for minting a dev admin token")
    args = parser.parse_args()

    extra = {k: v for k, v in vars(args).items() if k not in ("sub", "iss") and v}
    print(mint(args.sub, iss=args.iss or None, **extra))
