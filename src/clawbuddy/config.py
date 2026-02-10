"""Channel state management in ~/.config/clawbuddy/."""

from __future__ import annotations

import json
from pathlib import Path


def get_config_dir() -> Path:
    d = Path.home() / ".config" / "clawbuddy"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_keys_dir() -> Path:
    d = get_config_dir() / "keys"
    d.mkdir(parents=True, exist_ok=True)
    return d


def channels_path() -> Path:
    return get_config_dir() / "channels.json"


def load_channels() -> dict:
    p = channels_path()
    if p.exists():
        return json.loads(p.read_text())
    return {}


def save_channels(channels: dict) -> None:
    p = channels_path()
    p.write_text(json.dumps(channels, indent=2) + "\n")


def save_private_key(channel_id: str, key_bytes: bytes) -> None:
    p = get_keys_dir() / f"{channel_id}.key"
    p.write_bytes(key_bytes)
    p.chmod(0o600)


def load_private_key(channel_id: str) -> bytes:
    p = get_keys_dir() / f"{channel_id}.key"
    return p.read_bytes()


def get_mailbox_url() -> str:
    """Read mailbox endpoint from config.toml, fall back to env or default."""
    import os
    import tomllib

    config_file = get_config_dir() / "config.toml"
    if config_file.exists():
        cfg = tomllib.loads(config_file.read_text())
        url = cfg.get("mailbox_url")
        if url:
            return url
    return os.environ.get("CLAWBUDDY_MAILBOX_URL", "https://clawbuddy-mailbox.workers.dev")
