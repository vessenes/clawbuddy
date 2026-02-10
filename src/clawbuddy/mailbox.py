"""HTTP client for the Cloudflare Worker mailbox API."""

from __future__ import annotations

import httpx


def _client(mailbox_url: str) -> httpx.Client:
    return httpx.Client(base_url=mailbox_url, timeout=30)


def post_handshake(mailbox_url: str, channel_id: str, public_key_b64: str) -> dict:
    with _client(mailbox_url) as c:
        r = c.put(f"/channel/{channel_id}/handshake", json={"public_key": public_key_b64})
        r.raise_for_status()
        return r.json()


def get_handshake(mailbox_url: str, channel_id: str) -> dict | None:
    with _client(mailbox_url) as c:
        r = c.get(f"/channel/{channel_id}/handshake")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


def post_message(mailbox_url: str, channel_id: str, payload_b64: str) -> dict:
    with _client(mailbox_url) as c:
        r = c.post(f"/channel/{channel_id}/messages", json={"payload": payload_b64})
        r.raise_for_status()
        return r.json()


def get_messages(mailbox_url: str, channel_id: str) -> list[dict]:
    with _client(mailbox_url) as c:
        r = c.get(f"/channel/{channel_id}/messages")
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()


def delete_message(mailbox_url: str, channel_id: str, seq: int) -> None:
    with _client(mailbox_url) as c:
        r = c.delete(f"/channel/{channel_id}/messages/{seq}")
        r.raise_for_status()
