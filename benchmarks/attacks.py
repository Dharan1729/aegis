"""Attacks against a live aegis-server, and what each one gets back.

Every case is something a caller of /v1/evaluate could send. An attack
passes if it is refused (DENY, or a 4xx with no decision) and the server
does not error (no 5xx). Control cases check that legitimate requests are
still allowed with the right obligations, so a server that denies
everything cannot score well.

    python -m benchmarks.attacks          # needs the docker-compose stack
"""

import base64
import hashlib
import hmac
import json
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from benchmarks._stack import (
    KID,
    _private_key,
    evaluate_request,
    issuers,
    mint,
    setup_tenant,
    token_pair,
    write_result,
)

TENANT = "attacks"
OTHER_TENANT = "attacks-other"

POLICY = """
permit(principal, action == Action::"read_report", resource)
when { principal.role == "Analyst" };

permit(principal, action == Action::"export_all", resource)
when { context.agent_id == "trusted-batch-agent" };

@mask_fields("ssn")
permit(principal, action == Action::"read_employee", resource)
when { principal.role == "Analyst" };

@mask_fields("salary")
@approval_required("true")
permit(principal, action == Action::"read_employee", resource)
when { principal.department == "Finance" };

@approval_required("true")
@risk_tier("high")
permit(principal, action == Action::"wire_large_funds", resource)
when { principal.role == "Analyst" };

permit(principal, action == Action::"delete_audit_log", resource)
when { principal.role == "Analyst" };
forbid(principal, action == Action::"delete_audit_log", resource);
"""

ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _claims(iss: str, **extra) -> dict:
    now = int(time.time())
    return {
        "sub": "alice",
        "iss": iss,
        "iat": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
        "role": "Analyst",
        **extra,
    }


def _hs256_with_public_key(iss: str) -> str:
    """Algorithm confusion: sign with HMAC, using the server's *public* RSA
    key as the HMAC secret, hoping the verifier uses the key it fetched
    without pinning the algorithm."""
    public_pem = (
        _private_key()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    payload = _b64(json.dumps(_claims(iss)).encode())
    sig = hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(sig)}"


def _alg_none(iss: str) -> str:
    header = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": KID}).encode())
    return f"{header}.{_b64(json.dumps(_claims(iss)).encode())}."


def _cases() -> list[dict]:
    h_iss, s_iss = issuers(TENANT)
    o_h_iss, o_s_iss = issuers(OTHER_TENANT)
    now = int(time.time())

    def pair(**kw):
        return token_pair(TENANT, **kw)

    replay_h, replay_s = pair()
    cases = [
        # Controls: legitimate requests that must still work.
        {
            "name": "control: analyst reads a report",
            "kind": "control",
            "expect": "ALLOW",
            "req": evaluate_request(TENANT, *pair(), "read_report"),
        },
        {
            "name": "control: overlapping permits combine their obligations",
            "kind": "control",
            "expect": "ALLOW",
            "expect_mask": ["salary", "ssn"],
            "req": evaluate_request(TENANT, *pair(), "read_employee"),
        },
        {
            "name": "control: trusted agent may export",
            "kind": "control",
            "expect": "ALLOW",
            "req": evaluate_request(TENANT, pair()[0], mint("trusted-batch-agent", iss=s_iss), "export_all"),
        },
        # Policy.
        {
            "name": "role not permitted (default deny)",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(TENANT, *pair(role="Junior Analyst"), "read_report"),
        },
        {
            "name": "forbid overrides a matching permit",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(TENANT, *pair(), "delete_audit_log"),
        },
        {
            "name": "high-risk action refused by the approver",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(TENANT, *pair(), "wire_large_funds"),
        },
        {
            "name": "agent impersonation through request context",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT,
                *pair(),
                "export_all",
                context={
                    "agent_id": "trusted-batch-agent",
                    "agent": {"__entity": {"type": "Agent", "id": "trusted-batch-agent"}},
                },
            ),
        },
        {
            "name": "Cedar syntax injected into the action name",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(TENANT, *pair(), 'export_all" || principal == Human::"x'),
        },
        {
            "name": "Cedar syntax injected into the resource",
            "kind": "policy",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT, *pair(role="Intern"), "read_report", urn='x"; permit(principal, action, resource); //'
            ),
        },
        # Identity.
        {
            "name": "token signed by an attacker's key",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT,
                jwt.encode(_claims(h_iss), ATTACKER_KEY, "RS256", headers={"kid": KID}),
                pair()[1],
                "read_report",
            ),
        },
        {
            "name": "algorithm confusion (HS256 with the public key)",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(TENANT, _hs256_with_public_key(h_iss), pair()[1], "read_report"),
        },
        {
            "name": "unsigned token (alg none)",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(TENANT, _alg_none(h_iss), pair()[1], "read_report"),
        },
        {
            "name": "token from another issuer",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT, mint("alice", iss="https://evil.test", role="Analyst"), pair()[1], "read_report"
            ),
        },
        {
            "name": "another tenant's valid tokens under this tenant's header",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT, mint("alice", iss=o_h_iss, role="Analyst"), mint("bot", iss=o_s_iss), "read_report"
            ),
        },
        {
            "name": "service token presented as the user token",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT, mint("alice", iss=s_iss, role="Analyst"), pair()[1], "read_report"
            ),
        },
        {
            "name": "expired token",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT, mint("alice", iss=h_iss, role="Analyst", ttl_seconds=-10), pair()[1], "read_report"
            ),
        },
        {
            "name": "token issued in the future",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT,
                jwt.encode(
                    _claims(h_iss, iat=now + 600, exp=now + 900),
                    _private_key(),
                    "RS256",
                    headers={"kid": KID},
                ),
                pair()[1],
                "read_report",
            ),
        },
        {
            "name": "token without a jti (single-use tenant)",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(
                TENANT,
                jwt.encode(
                    {k: v for k, v in _claims(h_iss).items() if k != "jti"},
                    _private_key(),
                    "RS256",
                    headers={"kid": KID},
                ),
                pair()[1],
                "read_report",
            ),
        },
        {
            "name": "replay: first use",
            "kind": "control",
            "expect": "ALLOW",
            "req": evaluate_request(TENANT, replay_h, replay_s, "read_report"),
        },
        {
            "name": "replay: same tokens again",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(TENANT, replay_h, replay_s, "read_report"),
        },
        {
            "name": "unknown tenant",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request("no-such-tenant", *pair(), "read_report"),
        },
        {
            "name": "garbage token",
            "kind": "identity",
            "expect": "DENY",
            "req": evaluate_request(TENANT, "not.a.jwt", pair()[1], "read_report"),
        },
    ]
    missing_bearer = evaluate_request(TENANT, *pair(), "read_report")
    missing_bearer["headers"]["Authorization"] = "Token abc"
    cases.append(
        {
            "name": "Authorization header without Bearer",
            "kind": "identity",
            "expect": "REFUSED",
            "req": missing_bearer,
        }
    )
    return cases


def run() -> dict:
    setup_tenant(TENANT, POLICY)
    setup_tenant(OTHER_TENANT, "permit(principal, action, resource);")
    rows = []
    with httpx.Client(timeout=10.0) as client:
        for case in _cases():
            resp = client.post(**case["req"])
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            decision = body.get("decision")
            got = decision or f"HTTP {resp.status_code}"
            if case["expect"] == "REFUSED":
                ok = 400 <= resp.status_code < 500 and decision != "ALLOW"
            else:
                ok = resp.status_code == 200 and decision == case["expect"]
            if ok and "expect_mask" in case:
                mask_fields = (body.get("execution_policy") or {}).get("mask_fields")
                ok = mask_fields == case["expect_mask"]
                got += f" mask={mask_fields}"
            rows.append(
                {
                    "name": case["name"],
                    "kind": case["kind"],
                    "expected": case["expect"],
                    "got": got,
                    "status": resp.status_code,
                    "passed": ok,
                }
            )

    attacks = [r for r in rows if r["kind"] != "control"]
    summary = {
        "cases": len(rows),
        "attacks": len(attacks),
        "attacks_refused": sum(r["passed"] for r in attacks),
        "attacks_allowed": sum(1 for r in attacks if r["got"].startswith("ALLOW")),
        "controls": len(rows) - len(attacks),
        "controls_passed": sum(r["passed"] for r in rows if r["kind"] == "control"),
        "server_errors": sum(1 for r in rows if r["status"] >= 500),
    }
    return {"summary": summary, "cases": rows}


def main() -> None:
    result = run()
    width = max(len(r["name"]) for r in result["cases"])
    for r in result["cases"]:
        mark = "ok  " if r["passed"] else "FAIL"
        print(f"{mark} {r['kind']:<8} {r['name']:<{width}}  expected {r['expected']:<7} got {r['got']}")
    print(json.dumps(result["summary"], indent=2))
    print("wrote", write_result("attacks", result))
    if not all(r["passed"] for r in result["cases"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
