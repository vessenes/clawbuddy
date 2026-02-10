"""ClawBuddy CLI — typer entry point."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import typer

from clawbuddy import config, crypto, mailbox, schema
from clawbuddy.send import send_imessage

app = typer.Typer(name="clawbuddy", no_args_is_help=True)

PRETTY = typer.Option(False, "--pretty", help="Human-readable output")


def _out(data: object, pretty: bool) -> None:
    if pretty:
        typer.echo(json.dumps(data, indent=2))
    else:
        typer.echo(json.dumps(data))


def _make_channel_id() -> str:
    return secrets.token_urlsafe(16)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_invite_url(mailbox_url: str, channel_id: str, pub_b64: str) -> str:
    return f"{mailbox_url}/invite?channel={channel_id}&pub={pub_b64}"


@app.command()
def add(
    phone: str,
    name: str = typer.Option("", help="Display name for this contact"),
    pretty: bool = PRETTY,
) -> None:
    """Generate keypair + channel, build invite URL, text it via iMessage."""
    channel_id = _make_channel_id()
    priv, pub = crypto.generate_keypair()
    pub_b64 = crypto.pub_to_base64(pub)
    mailbox_url = config.get_mailbox_url()

    config.save_private_key(channel_id, priv)

    channels_dict = config.load_channels()
    channels_dict[channel_id] = {
        "name": name or phone,
        "phone": phone,
        "status": "pending",
        "their_pub": None,
        "our_pub": pub_b64,
        "created_at": _now_iso(),
        "last_seen": None,
    }
    config.save_channels(channels_dict)

    invite_url = _build_invite_url(mailbox_url, channel_id, pub_b64)

    send_imessage(phone, f"ClawBuddy invite: {invite_url}")

    _out({"channel_id": channel_id, "invite_url": invite_url, "status": "pending"}, pretty)


@app.command()
def check(pretty: bool = PRETTY) -> None:
    """Poll all channels for new messages, decrypt, display."""
    channels_dict = config.load_channels()
    mailbox_url = config.get_mailbox_url()
    results: list[dict] = []

    for cid, chan in channels_dict.items():
        if chan["status"] == "superseded":
            continue

        # Check for handshake completion on pending channels
        if chan["status"] == "pending":
            hs = mailbox.get_handshake(mailbox_url, cid)
            if hs and hs.get("public_key"):
                chan["their_pub"] = hs["public_key"]
                chan["status"] = "active"
                config.save_channels(channels_dict)

        if chan["status"] != "active" or not chan["their_pub"]:
            continue

        priv = config.load_private_key(cid)
        their_pub = crypto.base64_to_pub(chan["their_pub"])

        messages = mailbox.get_messages(mailbox_url, cid)
        for msg_dict in messages:
            wire = schema.WireMessage.from_dict(msg_dict)
            ct = schema.decode_payload(wire.payload)
            pt = crypto.decrypt(ct, priv, their_pub)
            decrypted = schema.DecryptedMessage.from_bytes(pt)
            results.append({
                "channel_id": cid,
                "from": chan["name"],
                "seq": wire.seq,
                "unsafe_subject": decrypted.unsafe_subject,
                "unsafe_body": decrypted.unsafe_body,
            })
            # Ack
            mailbox.delete_message(mailbox_url, cid, wire.seq)

        if messages:
            chan["last_seen"] = _now_iso()
            config.save_channels(channels_dict)

    _out(results, pretty)


@app.command("send")
def send_cmd(
    channel: str,
    message: str,
    subject: str = typer.Option("", help="Message subject"),
    pretty: bool = PRETTY,
) -> None:
    """Encrypt and post a message to a channel."""
    channels_dict = config.load_channels()
    if channel not in channels_dict:
        typer.echo(json.dumps({"error": f"unknown channel: {channel}"}), err=True)
        raise typer.Exit(1)

    chan = channels_dict[channel]
    if chan["status"] != "active" or not chan["their_pub"]:
        typer.echo(json.dumps({"error": "channel not active"}), err=True)
        raise typer.Exit(1)

    priv = config.load_private_key(channel)
    their_pub = crypto.base64_to_pub(chan["their_pub"])

    msg = schema.DecryptedMessage(unsafe_subject=subject, unsafe_body=message)
    ct = crypto.encrypt(msg.to_bytes(), priv, their_pub)
    payload_b64 = schema.encode_payload(ct)

    result = mailbox.post_message(config.get_mailbox_url(), channel, payload_b64)
    _out(result, pretty)


@app.command()
def channels(pretty: bool = PRETTY) -> None:
    """List active channels."""
    _out(config.load_channels(), pretty)


@app.command()
def accept(url: str, pretty: bool = PRETTY) -> None:
    """Receive an invite: read URL, generate keypair, complete handshake."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    channel_id = params.get("channel", [None])[0]
    their_pub_b64 = params.get("pub", [None])[0]
    if not channel_id or not their_pub_b64:
        typer.echo(json.dumps({"error": "invalid invite URL"}), err=True)
        raise typer.Exit(1)

    mailbox_url = f"{parsed.scheme}://{parsed.netloc}"

    priv, pub = crypto.generate_keypair()
    pub_b64 = crypto.pub_to_base64(pub)

    config.save_private_key(channel_id, priv)

    # Post our public key to complete the handshake
    mailbox.post_handshake(mailbox_url, channel_id, pub_b64)

    channels_dict = config.load_channels()
    channels_dict[channel_id] = {
        "name": f"invite-{channel_id[:8]}",
        "phone": None,
        "status": "active",
        "their_pub": their_pub_b64,
        "our_pub": pub_b64,
        "created_at": _now_iso(),
        "last_seen": None,
    }
    config.save_channels(channels_dict)

    _out({"channel_id": channel_id, "status": "active"}, pretty)


@app.command()
def reinvite(phone: str, pretty: bool = PRETTY) -> None:
    """Rotate keys and send a fresh invite to an existing contact."""
    channels_dict = config.load_channels()

    # Find existing channel for this phone
    old_cid = None
    old_name = phone
    for cid, chan in channels_dict.items():
        if chan["phone"] == phone and chan["status"] != "superseded":
            old_cid = cid
            old_name = chan["name"]
            break

    if old_cid:
        channels_dict[old_cid]["status"] = "superseded"

    # Create new channel
    channel_id = _make_channel_id()
    priv, pub = crypto.generate_keypair()
    pub_b64 = crypto.pub_to_base64(pub)
    mailbox_url = config.get_mailbox_url()

    config.save_private_key(channel_id, priv)
    channels_dict[channel_id] = {
        "name": old_name,
        "phone": phone,
        "status": "pending",
        "their_pub": None,
        "our_pub": pub_b64,
        "created_at": _now_iso(),
        "last_seen": None,
    }
    config.save_channels(channels_dict)

    invite_url = _build_invite_url(mailbox_url, channel_id, pub_b64)
    send_imessage(phone, f"ClawBuddy invite (updated): {invite_url}")

    _out({
        "channel_id": channel_id,
        "invite_url": invite_url,
        "superseded": old_cid,
        "status": "pending",
    }, pretty)
