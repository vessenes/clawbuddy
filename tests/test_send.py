"""Tests for clawbuddy.send — iMessage via osascript."""

from unittest.mock import patch

from clawbuddy.send import send_imessage


@patch("clawbuddy.send.subprocess.run")
def test_send_imessage_calls_osascript(mock_run):
    send_imessage("+15551234567", "Hello there")
    mock_run.assert_called_once()
    args = mock_run.call_args
    assert args[0][0][0] == "osascript"
    assert args[0][0][1] == "-e"


@patch("clawbuddy.send.subprocess.run")
def test_send_imessage_contains_phone_and_message(mock_run):
    send_imessage("+15559876543", "Test msg")
    script = mock_run.call_args[0][0][2]
    assert "+15559876543" in script
    assert "Test msg" in script
