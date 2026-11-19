"""Token attacks against the execution-principal check, with keys made in
the test. Each case is something a caller could try; each must be refused."""

import time
import uuid
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app import principal_validator as pv

TRUSTED = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISS_H, ISS_S = "https://idp.example/human", "https://idp.example/service"


class FakeJwks:
    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=TRUSTED.public_key())


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(pv, "_jwks_client", lambda uri: FakeJwks())
    seen = set()

    async def nonce(tenant_id, jti, exp):
        if jti in seen:
            raise pv.PrincipalValidationError("nonce replay detected")
        seen.add(jti)

    monkeypatch.setattr(pv, "_check_and_record_nonce", nonce)


def tenant(**kw):
    base = {
        "jwks_uri_human": "https://idp.example/jwks",
        "jwks_uri_service": "https://idp.example/jwks",
        "expected_issuer_human": ISS_H,
        "expected_issuer_service": ISS_S,
        "expected_audience_human": None,
        "expected_audience_service": None,
        "single_use_tokens": True,
    }
    return SimpleNamespace(**{**base, **kw})


class Session:
    def __init__(self, cfg):
        self.cfg = cfg

    async def get(self, model, key):
        return self.cfg


def token(iss, key=TRUSTED, alg="RS256", drop=(), **claims):
    now = int(time.time())
    body = {
        "sub": "alice",
        "iss": iss,
        "iat": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
        "role": "Analyst",
    }
    body.update(claims)
    for k in drop:
        body.pop(k)
    return jwt.encode(body, key, algorithm=alg)


async def check(cfg, human, service):
    return await pv.validate_principal(Session(cfg), "t", human, service)


async def test_valid_pair_is_accepted():
    ident = await check(tenant(), token(ISS_H), token(ISS_S, sub="bot"))
    assert (ident.human_id, ident.agent_id) == ("alice", "bot")


async def test_unknown_tenant_is_refused():
    with pytest.raises(pv.PrincipalValidationError, match="unknown tenant"):
        await check(None, token(ISS_H), token(ISS_S))


async def test_tenant_without_issuer_is_refused():
    with pytest.raises(pv.PrincipalValidationError, match="no expected issuer"):
        await check(tenant(expected_issuer_human=None), token(ISS_H), token(ISS_S))


@pytest.mark.parametrize(
    "human",
    [
        pytest.param(lambda: token(ISS_H, key=ATTACKER), id="signed-by-another-key"),
        pytest.param(lambda: token("https://evil.example"), id="wrong-issuer"),
        pytest.param(lambda: token(ISS_S), id="service-issuer-as-human"),
        pytest.param(lambda: token(ISS_H, exp=int(time.time()) - 10), id="expired"),
        pytest.param(lambda: token(ISS_H, iat=int(time.time()) + 600), id="issued-in-future"),
        pytest.param(
            lambda: token(ISS_H, iat=int(time.time()) - 3600, exp=int(time.time()) + 60), id="too-old"
        ),
        pytest.param(lambda: token(ISS_H, drop=("jti",)), id="no-jti"),
        pytest.param(lambda: token(ISS_H, drop=("sub",)), id="no-sub"),
        pytest.param(lambda: token(ISS_H, key="secret", alg="HS256"), id="hs256-confusion"),
        pytest.param(lambda: token(ISS_H, key=None, alg="none"), id="alg-none"),
        pytest.param(lambda: "not.a.jwt", id="garbage"),
    ],
)
async def test_bad_human_token_is_refused(human):
    with pytest.raises(pv.PrincipalValidationError):
        await check(tenant(), human(), token(ISS_S))


async def test_bad_service_token_is_refused_too():
    with pytest.raises(pv.PrincipalValidationError):
        await check(tenant(), token(ISS_H), token(ISS_S, key=ATTACKER))


async def test_replayed_token_is_refused_in_single_use_mode():
    human, service = token(ISS_H), token(ISS_S)
    await check(tenant(), human, service)
    with pytest.raises(pv.PrincipalValidationError, match="replay"):
        await check(tenant(), human, token(ISS_S))


async def test_reusable_mode_accepts_reuse_and_ordinary_idp_tokens():
    cfg = tenant(single_use_tokens=False)
    old = int(time.time()) - 3600
    human = token(ISS_H, iat=old, exp=old + 7200, drop=("jti",))
    service = token(ISS_S, sub="bot")
    await check(cfg, human, service)
    await check(cfg, human, service)


async def test_reusable_mode_still_checks_signature_issuer_and_expiry():
    cfg = tenant(single_use_tokens=False)
    for bad in (
        token(ISS_H, key=ATTACKER),
        token("https://evil.example"),
        token(ISS_H, exp=int(time.time()) - 5),
    ):
        with pytest.raises(pv.PrincipalValidationError):
            await check(cfg, bad, token(ISS_S))


async def test_audience_is_enforced_when_configured():
    cfg = tenant(expected_audience_human="aegis")
    await check(cfg, token(ISS_H, aud="aegis"), token(ISS_S))
    for bad in (token(ISS_H, aud="another-app"), token(ISS_H)):
        with pytest.raises(pv.PrincipalValidationError):
            await check(cfg, bad, token(ISS_S))
