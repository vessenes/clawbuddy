"""Message schema with unsafe_* fields for prompt-injection awareness."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field


@dataclass
class DecryptedMessage:
    """Decrypted message content. Fields prefixed unsafe_ to signal untrusted data."""

    unsafe_subject: str = ""
    unsafe_body: str = ""
    unsafe_metadata: dict = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        return json.dumps({
            "unsafe_subject": self.unsafe_subject,
            "unsafe_body": self.unsafe_body,
            "unsafe_metadata": self.unsafe_metadata,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> DecryptedMessage:
        d = json.loads(data)
        return cls(
            unsafe_subject=d.get("unsafe_subject", ""),
            unsafe_body=d.get("unsafe_body", ""),
            unsafe_metadata=d.get("unsafe_metadata", {}),
        )


@dataclass
class WireMessage:
    """On-the-wire message format (encrypted payload)."""

    channel_id: str
    seq: int
    payload: str  # base64-encoded encrypted bytes

    def to_dict(self) -> dict:
        return {"channel_id": self.channel_id, "seq": self.seq, "payload": self.payload}

    @classmethod
    def from_dict(cls, d: dict) -> WireMessage:
        return cls(channel_id=d["channel_id"], seq=d["seq"], payload=d["payload"])


def encode_payload(encrypted: bytes) -> str:
    return base64.b64encode(encrypted).decode()


def decode_payload(b64: str) -> bytes:
    return base64.b64decode(b64)
