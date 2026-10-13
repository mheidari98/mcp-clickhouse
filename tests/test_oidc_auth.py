import pytest

from mcp_clickhouse import auth
from mcp_clickhouse.auth import GroupAwareJWTVerifier, _resolve_auth
from mcp_clickhouse.mcp_env import MCPServerConfig

OIDC_ENV = {
    "CLICKHOUSE_MCP_SERVER_TRANSPORT": "http",
    "CLICKHOUSE_MCP_OIDC_ENABLED": "true",
    "CLICKHOUSE_MCP_OIDC_DISCOVERY_URL": "https://idp.example.com/realms/test/.well-known/openid-configuration",
    "CLICKHOUSE_MCP_OIDC_CLIENT_ID": "mcp-clickhouse",
    "CLICKHOUSE_MCP_OIDC_CLIENT_SECRET": "secret",
    "CLICKHOUSE_MCP_BASE_URL": "https://mcp.example.com",
}


@pytest.fixture
def oidc_env(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "CLICKHOUSE_MCP_AUTH_TOKEN",
        "CLICKHOUSE_MCP_AUTH_DISABLED",
        "FASTMCP_SERVER_AUTH",
        "CLICKHOUSE_MCP_ALLOWED_GROUPS",
        "CLICKHOUSE_MCP_OIDC_SCOPES",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in OIDC_ENV.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def make_verifier(allowed_groups, claims, monkeypatch):
    class _Token:
        def __init__(self, claims):
            self.claims = claims

    async def fake_load(self, token):
        return _Token(claims) if claims is not None else None

    monkeypatch.setattr(auth.JWTVerifier, "load_access_token", fake_load)
    return GroupAwareJWTVerifier(
        jwks_uri="https://idp.example.com/jwks", issuer="https://idp.example.com", allowed_groups=allowed_groups
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "allowed, claims, accepted",
    [
        (["team-a"], {"groups": ["/team-a"]}, True),
        (["team-a"], {"groups": ["team-a", "other"]}, True),
        (["team-a"], {"groups": ["other"]}, False),
        (["team-a"], {}, False),
        ([], {"groups": []}, True),
        (["team-a"], None, False),
    ],
)
async def test_group_aware_verifier(monkeypatch, allowed, claims, accepted):
    verifier = make_verifier(allowed, claims, monkeypatch)

    result = await verifier.load_access_token("token")

    assert (result is not None) is accepted


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", []),
        ("openid profile email offline_access", ["openid", "profile", "email", "offline_access"]),
        ("openid, offline_access", ["openid", "offline_access"]),
    ],
)
def test_oidc_scopes_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("CLICKHOUSE_MCP_OIDC_SCOPES", raw)

    assert MCPServerConfig().oidc_scopes == expected


def test_allowed_groups_parsing(monkeypatch):
    monkeypatch.setenv("CLICKHOUSE_MCP_ALLOWED_GROUPS", "team-a, team-b,")

    assert MCPServerConfig().allowed_groups == ["team-a", "team-b"]


def test_oidc_mode_is_exclusive_with_static_token(oidc_env):
    oidc_env.setenv("CLICKHOUSE_MCP_AUTH_TOKEN", "token")

    with pytest.raises(ValueError, match="mutually exclusive"):
        _resolve_auth(MCPServerConfig(), transport="http")


def test_oidc_mode_requires_settings(oidc_env):
    oidc_env.delenv("CLICKHOUSE_MCP_OIDC_CLIENT_SECRET")

    with pytest.raises(ValueError, match="CLICKHOUSE_MCP_OIDC_CLIENT_SECRET"):
        _resolve_auth(MCPServerConfig(), transport="http")


def test_oidc_mode_builds_proxy_with_forced_scopes(oidc_env, monkeypatch):
    oidc_env.setenv("CLICKHOUSE_MCP_OIDC_SCOPES", "openid offline_access")
    oidc_env.setenv("CLICKHOUSE_MCP_ALLOWED_GROUPS", "team-a")
    captured = {}

    class _Discovery:
        jwks_uri = "https://idp.example.com/jwks"
        issuer = "https://idp.example.com"

    class _FakeProxy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        auth.OIDCConfiguration, "get_oidc_configuration", classmethod(lambda cls, *a, **k: _Discovery())
    )
    monkeypatch.setattr(auth, "OIDCProxy", _FakeProxy)

    result = _resolve_auth(MCPServerConfig(), transport="http")

    assert isinstance(result["auth"], _FakeProxy)
    assert captured["extra_authorize_params"] == {"scope": "openid offline_access"}
    assert captured["enable_cimd"] is False
    assert isinstance(captured["token_verifier"], GroupAwareJWTVerifier)
    assert captured["base_url"] == "https://mcp.example.com"
