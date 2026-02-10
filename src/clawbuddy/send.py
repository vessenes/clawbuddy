"""Send iMessage via macOS osascript."""

from __future__ import annotations

import subprocess


def send_imessage(phone: str, message: str) -> None:
    """Send an iMessage using AppleScript. macOS only."""
    script = (
        f'tell application "Messages"\n'
        f'  set targetService to 1st account whose service type = iMessage\n'
        f'  set targetBuddy to participant "{phone}" of targetService\n'
        f'  send "{message}" to targetBuddy\n'
        f'end tell'
    )
    subprocess.run(["osascript", "-e", script], check=True)
