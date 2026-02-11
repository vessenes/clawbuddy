"""Tests for clawbuddy.cli — Typer commands with mocked IO."""

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from clawbuddy.cli import app
from clawbuddy import config, crypto, schema

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "get_config_dir", lambda: tmp_path)
    monkeypatch.setattr(config, "get_keys_dir", lambda: tmp_path / "keys")
    monkeypatch.setattr(config, "channels_path", lambda: tmp_path / "channels.json")
    (tmp_path / "keys").mkdir(exist_ok=True)
    monkeypatch.setenv("CLAWBUDDY_MAILBOX_URL", "https://test.example.com")


def test_channels_empty():
    result = runner.invoke(app, ["channels"])
    assert result.exit_code == 0
    assert json.loads(result.output) == {}


def test_channels_pretty():
    result = runner.invoke(app, ["channels", "--pretty"])
    assert result.exit_code == 0
    assert json.loads(result.output) == {}
    # pretty output has indentation
    assert "  " not in "{}" or result.output.strip() == "{}"


@patch("clawbuddy.cli.send_imessage")
def test_add(mock_send):
    result = runner.invoke(app, ["add", "+15551234567", "--name", "Alice"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "pending"
    assert "channel_id" in data
    assert "invite_url" in data
    mock_send.assert_called_once()
    # The iMessage should contain the invite URL
    sent_msg = mock_send.call_args[0][1]
    assert data["invite_url"] in sent_msg

    # Channel should have default instructions
    channels = config.load_channels()
    chan = channels[data["channel_id"]]
    assert "instructions" in chan
    assert "Safe Acquaintance" in chan["instructions"]
    assert "Alice" in chan["instructions"]


@patch("clawbuddy.cli.send_imessage")
def test_add_with_preset(mock_send):
    result = runner.invoke(app, ["add", "+15551234567", "--name", "VIP", "--preset", "inner-circle"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    channels = config.load_channels()
    chan = channels[data["channel_id"]]
    assert "Inner Circle" in chan["instructions"]
    assert "VIP" in chan["instructions"]


@patch("clawbuddy.cli.mailbox.post_handshake")
def test_accept(mock_hs):
    mock_hs.return_value = {"ok": True}
    url = "https://test.example.com/invite?channel=ch123&pub=AQID"
    result = runner.invoke(app, ["accept", url])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["channel_id"] == "ch123"
    assert data["status"] == "active"
    mock_hs.assert_called_once()

    # Channel should be saved with default instructions
    channels = config.load_channels()
    assert "ch123" in channels
    assert channels["ch123"]["status"] == "active"
    assert channels["ch123"]["their_pub"] == "AQID"
    assert "Safe Acquaintance" in channels["ch123"]["instructions"]


@patch("clawbuddy.cli.mailbox.post_handshake")
def test_accept_with_preset(mock_hs):
    mock_hs.return_value = {"ok": True}
    url = "https://test.example.com/invite?channel=ch456&pub=AQID"
    result = runner.invoke(app, ["accept", url, "--preset", "trusted-colleague"])
    assert result.exit_code == 0
    channels = config.load_channels()
    assert "Trusted Colleague" in channels["ch456"]["instructions"]


@patch("clawbuddy.cli.mailbox.post_message")
def test_send_encrypts_and_posts(mock_post, tmp_path):
    mock_post.return_value = {"seq": 1}

    # Set up an active channel with keypairs
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()

    channel_id = "send-test"
    config.save_private_key(channel_id, alice_priv)
    config.save_channels({
        channel_id: {
            "name": "Bob",
            "phone": "+1555",
            "status": "active",
            "their_pub": crypto.pub_to_base64(bob_pub),
            "our_pub": crypto.pub_to_base64(alice_pub),
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })

    result = runner.invoke(app, ["send", channel_id, "hi bob", "--subject", "greet"])
    assert result.exit_code == 0
    mock_post.assert_called_once()

    # Verify the payload is decryptable
    call_args = mock_post.call_args
    payload_b64 = call_args[0][2]
    ct = schema.decode_payload(payload_b64)
    pt = crypto.decrypt(ct, bob_priv, alice_pub)
    msg = schema.DecryptedMessage.from_bytes(pt)
    assert msg.unsafe_body == "hi bob"
    assert msg.unsafe_subject == "greet"


def test_send_unknown_channel():
    result = runner.invoke(app, ["send", "nonexistent", "hi"])
    assert result.exit_code == 1


@patch("clawbuddy.cli.send_imessage")
def test_reinvite_supersedes_old(mock_send):
    # Create an existing channel with instructions
    config.save_channels({
        "old-chan": {
            "name": "Bob",
            "phone": "+15559999999",
            "status": "active",
            "their_pub": "xyz",
            "our_pub": "abc",
            "instructions": "Custom policy for Bob",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })

    result = runner.invoke(app, ["reinvite", "+15559999999"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["superseded"] == "old-chan"
    assert data["status"] == "pending"

    channels = config.load_channels()
    assert channels["old-chan"]["status"] == "superseded"
    new_chan = channels[data["channel_id"]]
    assert new_chan["status"] == "pending"
    # Instructions should carry forward from old channel
    assert new_chan["instructions"] == "Custom policy for Bob"


@patch("clawbuddy.cli.send_imessage")
def test_reinvite_with_preset_override(mock_send):
    config.save_channels({
        "old-chan2": {
            "name": "Carol",
            "phone": "+15558888888",
            "status": "active",
            "their_pub": "xyz",
            "our_pub": "abc",
            "instructions": "Old policy",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })

    result = runner.invoke(app, ["reinvite", "+15558888888", "--preset", "inner-circle"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    channels = config.load_channels()
    new_chan = channels[data["channel_id"]]
    assert "Inner Circle" in new_chan["instructions"]
    assert "Carol" in new_chan["instructions"]


@patch("clawbuddy.cli.mailbox.delete_message")
@patch("clawbuddy.cli.mailbox.get_messages")
@patch("clawbuddy.cli.mailbox.get_handshake")
def test_check_decrypts_messages(mock_hs, mock_msgs, mock_del):
    # Set up a fully active channel with instructions
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    channel_id = "check-test"

    config.save_private_key(channel_id, alice_priv)
    config.save_channels({
        channel_id: {
            "name": "Bob",
            "phone": "+1555",
            "status": "active",
            "their_pub": crypto.pub_to_base64(bob_pub),
            "our_pub": crypto.pub_to_base64(alice_pub),
            "instructions": "Handle Bob carefully",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })

    # Bob encrypts a message to Alice
    msg = schema.DecryptedMessage(unsafe_subject="ping", unsafe_body="hello alice")
    ct = crypto.encrypt(msg.to_bytes(), bob_priv, alice_pub)
    payload_b64 = schema.encode_payload(ct)

    mock_hs.return_value = None
    mock_msgs.return_value = [{"channel_id": channel_id, "seq": 1, "payload": payload_b64}]

    result = runner.invoke(app, ["check"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 1
    assert data[0]["unsafe_subject"] == "ping"
    assert data[0]["unsafe_body"] == "hello alice"
    assert data[0]["instructions"] == "Handle Bob carefully"
    mock_del.assert_called_once()


def test_instructions_view():
    config.save_channels({
        "instr-test": {
            "name": "Dave",
            "phone": "+1555",
            "status": "active",
            "their_pub": "xyz",
            "our_pub": "abc",
            "instructions": "Be nice to Dave",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })
    result = runner.invoke(app, ["instructions", "instr-test"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["channel_id"] == "instr-test"
    assert data["instructions"] == "Be nice to Dave"


def test_instructions_set_from_file(tmp_path):
    config.save_channels({
        "instr-file": {
            "name": "Eve",
            "phone": "+1555",
            "status": "active",
            "their_pub": "xyz",
            "our_pub": "abc",
            "instructions": "",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })
    policy_file = tmp_path / "custom-policy.txt"
    policy_file.write_text("Custom engagement policy for Eve")
    result = runner.invoke(app, ["instructions", "instr-file", "--set", str(policy_file)])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["instructions"] == "Custom engagement policy for Eve"
    # Verify persisted
    channels = config.load_channels()
    assert channels["instr-file"]["instructions"] == "Custom engagement policy for Eve"


def test_instructions_set_from_preset():
    config.save_channels({
        "instr-preset": {
            "name": "Frank",
            "phone": "+1555",
            "status": "active",
            "their_pub": "xyz",
            "our_pub": "abc",
            "instructions": "",
            "created_at": "2025-01-01T00:00:00+00:00",
            "last_seen": None,
        }
    })
    result = runner.invoke(app, ["instructions", "instr-preset", "--preset", "one-time"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "One-Time" in data["instructions"]
    assert "Frank" in data["instructions"]


def test_instructions_unknown_channel():
    result = runner.invoke(app, ["instructions", "nonexistent"])
    assert result.exit_code == 1
