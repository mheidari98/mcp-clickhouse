import pytest

from mcp_clickhouse.mcp_env import MCPServerConfig
from mcp_clickhouse.mcp_server import _drop_zero_refresh_expiry


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", []),
        ("openid profile email offline_access", ["openid", "profile", "email", "offline_access"]),
        ("openid, offline_access", ["openid", "offline_access"]),
        ("  openid  ", ["openid"]),
    ],
)
def test_oidc_scopes_parsing(monkeypatch: pytest.MonkeyPatch, raw: str, expected: list):
    monkeypatch.setenv("CLICKHOUSE_MCP_OIDC_SCOPES", raw)

    assert MCPServerConfig().oidc_scopes == expected


def test_oidc_scopes_default_empty(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CLICKHOUSE_MCP_OIDC_SCOPES", raising=False)

    assert MCPServerConfig().oidc_scopes == []


def test_zero_refresh_expiry_is_dropped():
    response = {
        "access_token": "a",
        "refresh_token": "r",
        "expires_in": 300,
        "refresh_expires_in": 0,
    }

    result = _drop_zero_refresh_expiry(response)

    assert "refresh_expires_in" not in result
    assert result["expires_in"] == 300


@pytest.mark.parametrize("response", [{"refresh_expires_in": 1800}, {"expires_in": 300}])
def test_real_refresh_expiry_is_kept(response):
    assert _drop_zero_refresh_expiry(dict(response)) == response


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["fetch_token", "refresh_token"])
async def test_offline_token_client_drops_zero_refresh_expiry(monkeypatch, method):
    from mcp_clickhouse.mcp_server import KeycloakOfflineTokenClient, fastmcp_oauth_proxy

    async def fake_token_call(self, *args, **kwargs):
        return {"access_token": "a", "refresh_token": "r", "refresh_expires_in": 0}

    monkeypatch.setattr(fastmcp_oauth_proxy.AsyncOAuth2Client, method, fake_token_call)
    client = KeycloakOfflineTokenClient(client_id="client")

    result = await getattr(client, method)("https://idp.example/token")

    assert "refresh_expires_in" not in result
    assert result["refresh_token"] == "r"
