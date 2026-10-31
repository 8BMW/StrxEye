import httpx
import pytest
import respx

from strxeye.config import Settings, load_settings, save_settings, set_value
from strxeye.net import (
    FetchError,
    UnsafeTargetError,
    ensure_public_host,
    fetch,
    is_public_address,
)


def test_settings_roundtrip(tmp_path):
    path = tmp_path / "config.toml"
    settings = set_value(Settings(), "dns.nameservers", "1.1.1.1, 9.9.9.9")
    settings = set_value(settings, "collection.allow_direct", "true")
    save_settings(settings, path)
    loaded = load_settings(path)
    assert loaded.dns.nameservers == ["1.1.1.1", "9.9.9.9"]
    assert loaded.collection.allow_direct is True


def test_set_value_validates():
    with pytest.raises(KeyError, match="unknown setting"):
        set_value(Settings(), "network.nope", "1")
    with pytest.raises(ValueError):
        set_value(Settings(), "network.timeout", "-5")
    with pytest.raises(ValueError):
        set_value(Settings(), "collection.allow_direct", "maybe")


@pytest.mark.parametrize("address,public", [
    ("8.8.8.8", True), ("2606:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("::1", False),
    ("fe80::1", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False),
])
def test_is_public_address(address, public):
    assert is_public_address(address) is public


async def test_ensure_public_host_blocks_private_literal():
    with pytest.raises(UnsafeTargetError):
        await ensure_public_host("169.254.169.254")


async def test_ensure_public_host_blocks_names_resolving_privately(monkeypatch):
    import asyncio

    async def fake_getaddrinfo(self, host, port, **kw):
        return [(2, 1, 6, "", ("10.0.0.5", port)), (2, 1, 6, "", ("93.184.215.14", port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(UnsafeTargetError, match="10.0.0.5"):
        await ensure_public_host("evil.example")


@respx.mock
async def test_fetch_retries_transient_errors(monkeypatch):
    monkeypatch.setattr("strxeye.net._backoff", lambda attempt: 0)
    route = respx.get("https://src.test/x").mock(side_effect=[
        httpx.Response(503, headers={"Retry-After": "0"}), httpx.Response(200, json={"ok": 1})])
    async with httpx.AsyncClient() as client:
        response = await fetch(client, "https://src.test/x", retries=2)
    assert response.json() == {"ok": 1}
    assert route.call_count == 2


@respx.mock
async def test_fetch_does_not_retry_client_errors():
    route = respx.get("https://src.test/x").mock(return_value=httpx.Response(403))
    async with httpx.AsyncClient() as client:
        with pytest.raises(FetchError, match="HTTP 403"):
            await fetch(client, "https://src.test/x", retries=3)
    assert route.call_count == 1


@respx.mock
async def test_fetch_allowed_status_is_returned():
    respx.get("https://src.test/x").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        response = await fetch(client, "https://src.test/x", allow_statuses=(404,))
    assert response.status_code == 404
