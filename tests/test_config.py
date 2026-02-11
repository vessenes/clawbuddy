"""Tests for clawbuddy.config — channels, keys, and mailbox URL resolution."""

import pytest

from clawbuddy import config


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    """Redirect config dir to tmp_path so tests never touch real HOME."""
    monkeypatch.setattr(config, "get_config_dir", lambda: tmp_path)
    monkeypatch.setattr(config, "get_keys_dir", lambda: tmp_path / "keys")
    monkeypatch.setattr(config, "channels_path", lambda: tmp_path / "channels.json")
    (tmp_path / "keys").mkdir(exist_ok=True)


def test_load_channels_empty():
    assert config.load_channels() == {}


def test_save_load_channels_roundtrip():
    data = {"ch1": {"name": "alice", "status": "active"}}
    config.save_channels(data)
    assert config.load_channels() == data


def test_save_load_private_key_roundtrip():
    key = b"\x01" * 32
    config.save_private_key("chan-1", key)
    assert config.load_private_key("chan-1") == key


def test_private_key_permissions(tmp_path):
    config.save_private_key("chan-perm", b"\x02" * 32)
    key_path = tmp_path / "keys" / "chan-perm.key"
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_get_mailbox_url_env_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAWBUDDY_MAILBOX_URL", "https://custom.example.com")
    # Ensure no config.toml exists
    toml_path = tmp_path / "config.toml"
    if toml_path.exists():
        toml_path.unlink()
    assert config.get_mailbox_url() == "https://custom.example.com"


def test_get_mailbox_url_from_toml(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAWBUDDY_MAILBOX_URL", raising=False)
    toml_path = tmp_path / "config.toml"
    toml_path.write_text('mailbox_url = "https://toml.example.com"\n')
    assert config.get_mailbox_url() == "https://toml.example.com"


def test_get_mailbox_url_default(tmp_path, monkeypatch):
    monkeypatch.delenv("CLAWBUDDY_MAILBOX_URL", raising=False)
    assert config.get_mailbox_url() == "https://clawbuddy-mailbox.peter-078.workers.dev"
