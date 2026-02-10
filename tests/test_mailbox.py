"""Tests for clawbuddy.mailbox — HTTP client with respx mocking."""

import httpx
import respx

from clawbuddy.mailbox import (
    delete_message,
    get_handshake,
    get_messages,
    post_handshake,
    post_message,
)

BASE = "https://mailbox.test"


@respx.mock
def test_post_handshake():
    route = respx.put(f"{BASE}/channel/ch1/handshake").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    result = post_handshake(BASE, "ch1", "pubkey_b64")
    assert result == {"ok": True}
    assert route.called


@respx.mock
def test_get_handshake_found():
    respx.get(f"{BASE}/channel/ch1/handshake").mock(
        return_value=httpx.Response(200, json={"public_key": "abc"})
    )
    assert get_handshake(BASE, "ch1") == {"public_key": "abc"}


@respx.mock
def test_get_handshake_404():
    respx.get(f"{BASE}/channel/ch1/handshake").mock(
        return_value=httpx.Response(404)
    )
    assert get_handshake(BASE, "ch1") is None


@respx.mock
def test_post_message():
    route = respx.post(f"{BASE}/channel/ch1/messages").mock(
        return_value=httpx.Response(200, json={"seq": 1})
    )
    result = post_message(BASE, "ch1", "payload_b64")
    assert result == {"seq": 1}
    assert route.called


@respx.mock
def test_get_messages():
    respx.get(f"{BASE}/channel/ch1/messages").mock(
        return_value=httpx.Response(200, json=[{"channel_id": "ch1", "seq": 1, "payload": "x"}])
    )
    result = get_messages(BASE, "ch1")
    assert len(result) == 1
    assert result[0]["seq"] == 1


@respx.mock
def test_get_messages_404():
    respx.get(f"{BASE}/channel/ch1/messages").mock(
        return_value=httpx.Response(404)
    )
    assert get_messages(BASE, "ch1") == []


@respx.mock
def test_delete_message():
    route = respx.delete(f"{BASE}/channel/ch1/messages/5").mock(
        return_value=httpx.Response(200)
    )
    delete_message(BASE, "ch1", 5)
    assert route.called
