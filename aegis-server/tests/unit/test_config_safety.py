import pytest

from app.config import DEV_AUDIT_SECRET, Settings, UnsafeConfigurationError

SAFE = {
    "environment": "production",
    "audit_chain_hmac_secret": "s" * 48,
    "admin_oidc_issuer": "https://login.example.com",
    "admin_oidc_jwks_uri": "https://login.example.com/jwks",
    "console_cors_origins": ["https://console.example.com"],
}


def test_development_accepts_the_defaults():
    Settings(environment="development").check_production_safety()


def test_safe_production_settings_start():
    Settings(**SAFE).check_production_safety()


@pytest.mark.parametrize(
    "override,complaint",
    [
        ({"audit_chain_hmac_secret": DEV_AUDIT_SECRET}, "development default"),
        ({"audit_chain_hmac_secret": "short"}, "shorter than"),
        ({"admin_oidc_issuer": "https://idp.aegis-admin.test"}, "ADMIN_OIDC_ISSUER"),
        ({"admin_oidc_jwks_uri": "http://jwks-mock:80/jwks.json"}, "ADMIN_OIDC_JWKS_URI"),
        ({"console_cors_origins": ["http://localhost:5173"]}, "localhost"),
    ],
)
def test_production_refuses_dev_defaults(override, complaint):
    with pytest.raises(UnsafeConfigurationError, match=complaint):
        Settings(**{**SAFE, **override}).check_production_safety()
