"""Integration test — full invite → handshake → send → receive flow.

Hits the real Cloudflare Worker mailbox. Requires CLAWBUDDY_MAILBOX_URL
or uses the default endpoint.

Run:  uv run pytest tests/test_integration.py -v -s --log-cli-level=INFO
Skip: set SKIP_INTEGRATION=1 to skip when offline.
"""

from __future__ import annotations

import logging
import os
import secrets

import pytest

from clawbuddy import crypto, mailbox, schema

log = logging.getLogger("clawbuddy.integration")

pytestmark = pytest.mark.skipif(
    os.environ.get("SKIP_INTEGRATION") == "1",
    reason="SKIP_INTEGRATION=1",
)

MAILBOX_URL = os.environ.get(
    "CLAWBUDDY_MAILBOX_URL", "https://clawbuddy-mailbox.peter-078.workers.dev"
)


def test_full_channel_lifecycle():
    channel_id = f"test-{secrets.token_urlsafe(12)}"
    log.info("channel_id=%s  mailbox=%s", channel_id, MAILBOX_URL)

    # ── Alice: generate keypair ──────────────────────────────────
    alice_priv, alice_pub = crypto.generate_keypair()
    alice_pub_b64 = crypto.pub_to_base64(alice_pub)
    log.info("alice pub=%s", alice_pub_b64)

    # ── Alice: build invite URL (simulated) ──────────────────────
    invite_url = f"{MAILBOX_URL}/invite?channel={channel_id}&pub={alice_pub_b64}"
    log.info("invite_url=%s", invite_url)

    # ── Bob: parse invite, generate keypair, post handshake ──────
    bob_priv, bob_pub = crypto.generate_keypair()
    bob_pub_b64 = crypto.pub_to_base64(bob_pub)
    log.info("bob pub=%s", bob_pub_b64)

    hs_resp = mailbox.post_handshake(MAILBOX_URL, channel_id, bob_pub_b64)
    log.info("bob posted handshake: %s", hs_resp)

    # ── Alice: poll handshake to discover Bob's public key ───────
    hs = mailbox.get_handshake(MAILBOX_URL, channel_id)
    assert hs is not None, "handshake should exist after Bob posted"
    assert hs["public_key"] == bob_pub_b64
    log.info("alice got handshake: their_pub=%s", hs["public_key"])

    # ── Alice: encrypt and send a message to Bob ─────────────────
    their_pub = crypto.base64_to_pub(hs["public_key"])
    msg = schema.DecryptedMessage(
        unsafe_subject="ping",
        unsafe_body="hello from alice",
        unsafe_metadata={"test": True},
    )
    ct = crypto.encrypt(msg.to_bytes(), alice_priv, their_pub)
    payload_b64 = schema.encode_payload(ct)
    post_resp = mailbox.post_message(MAILBOX_URL, channel_id, payload_b64)
    log.info("alice posted message: %s", post_resp)

    # ── Bob: poll messages, decrypt ──────────────────────────────
    messages = mailbox.get_messages(MAILBOX_URL, channel_id)
    assert len(messages) >= 1, f"expected >=1 message, got {len(messages)}"
    log.info("bob got %d message(s)", len(messages))

    wire = schema.WireMessage.from_dict(messages[0])
    ct_recv = schema.decode_payload(wire.payload)
    pt = crypto.decrypt(ct_recv, bob_priv, alice_pub)
    decrypted = schema.DecryptedMessage.from_bytes(pt)

    log.info("bob decrypted: subject=%s body=%s meta=%s",
             decrypted.unsafe_subject, decrypted.unsafe_body,
             decrypted.unsafe_metadata)

    assert decrypted.unsafe_subject == "ping"
    assert decrypted.unsafe_body == "hello from alice"
    assert decrypted.unsafe_metadata == {"test": True}

    # ── Bob: ack (delete) the message ────────────────────────────
    mailbox.delete_message(MAILBOX_URL, channel_id, wire.seq)
    log.info("bob acked seq=%d", wire.seq)

    remaining = mailbox.get_messages(MAILBOX_URL, channel_id)
    assert len(remaining) == 0, f"expected 0 messages after ack, got {len(remaining)}"
    log.info("channel clean — no remaining messages")

    log.info("PASS")
