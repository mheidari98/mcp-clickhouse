import base64
import json

import pytest

from mcp_clickhouse import mcp_server
from mcp_clickhouse.mcp_server import (
    MAX_APPROVED_CLIENTS,
    BoundedConsentOIDCProxy,
    _approving_client_key,
)


@pytest.fixture
def proxy():
    # Skip OIDCProxy.__init__ (it fetches the discovery document over the network).
    instance = object.__new__(BoundedConsentOIDCProxy)
    instance._sign_cookie = lambda payload_b64: payload_b64
    return instance


def decode(encoded: str) -> list:
    return json.loads(base64.b64decode(encoded))


def test_small_list_is_unchanged(proxy):
    values = [f"client-{i}:http://127.0.0.1:{i}/callback" for i in range(5)]

    assert decode(proxy._encode_list_cookie(values)) == values


def test_list_over_cap_is_truncated_and_keeps_approving_client(proxy):
    values = sorted(f"client-{i:03d}:http://127.0.0.1:{i}/callback" for i in range(100))
    approving = values[-1]
    token = _approving_client_key.set(approving)
    try:
        encoded = decode(proxy._encode_list_cookie(values))
    finally:
        _approving_client_key.reset(token)

    assert len(encoded) == MAX_APPROVED_CLIENTS
    assert approving in encoded
    assert len(set(encoded)) == MAX_APPROVED_CLIENTS


def test_list_over_cap_without_approving_client_is_truncated(proxy):
    values = [f"client-{i}:http://127.0.0.1:{i}/callback" for i in range(100)]

    encoded = decode(proxy._encode_list_cookie(values))

    assert len(encoded) == MAX_APPROVED_CLIENTS


def test_cookie_stays_under_proxy_buffer_budget(proxy):
    values = [
        f"{'0' * 8}-{i:04d}-4000-8000-{'a' * 12}:http://127.0.0.1:{30000 + i}/callback"
        for i in range(1000)
    ]

    encoded = proxy._encode_list_cookie(values)

    assert len(encoded) < 4096


class _FakeRequest:
    async def form(self):
        return {"txn_id": "txn-1"}


class _FakeTxn:
    def model_dump(self):
        return {"client_id": "abc", "client_redirect_uri": "http://127.0.0.1:1234/callback"}


class _FakeStore:
    def __init__(self, txn):
        self._txn = txn

    async def get(self, key):
        return self._txn if key == "txn-1" else None


@pytest.mark.asyncio
async def test_submit_consent_tracks_approving_client(proxy, monkeypatch):
    proxy._transaction_store = _FakeStore(_FakeTxn())
    proxy._make_client_key = lambda client_id, uri: f"{client_id}:{uri}"
    seen = []

    async def fake_submit(self, request):
        seen.append(_approving_client_key.get())

    monkeypatch.setattr(mcp_server.OIDCProxy, "_submit_consent", fake_submit)

    await proxy._submit_consent(_FakeRequest())

    assert seen == ["abc:http://127.0.0.1:1234/callback"]
    assert _approving_client_key.get() is None


@pytest.mark.asyncio
async def test_submit_consent_unknown_txn_falls_through(proxy, monkeypatch):
    proxy._transaction_store = _FakeStore(None)
    seen = []

    async def fake_submit(self, request):
        seen.append(_approving_client_key.get())

    monkeypatch.setattr(mcp_server.OIDCProxy, "_submit_consent", fake_submit)

    await proxy._submit_consent(_FakeRequest())

    assert seen == [None]
