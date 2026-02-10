"""Tests for clawbuddy.schema — message serialisation and payload encoding."""

from clawbuddy.schema import (
    DecryptedMessage,
    WireMessage,
    decode_payload,
    encode_payload,
)


def test_decrypted_message_roundtrip():
    msg = DecryptedMessage(
        unsafe_subject="hi",
        unsafe_body="body text",
        unsafe_metadata={"key": "val"},
    )
    raw = msg.to_bytes()
    restored = DecryptedMessage.from_bytes(raw)
    assert restored.unsafe_subject == "hi"
    assert restored.unsafe_body == "body text"
    assert restored.unsafe_metadata == {"key": "val"}


def test_decrypted_message_defaults():
    msg = DecryptedMessage()
    assert msg.unsafe_subject == ""
    assert msg.unsafe_body == ""
    assert msg.unsafe_metadata == {}
    restored = DecryptedMessage.from_bytes(msg.to_bytes())
    assert restored.unsafe_subject == ""


def test_wire_message_roundtrip():
    wm = WireMessage(channel_id="ch1", seq=42, payload="AQID")
    d = wm.to_dict()
    assert d == {"channel_id": "ch1", "seq": 42, "payload": "AQID"}
    restored = WireMessage.from_dict(d)
    assert restored.channel_id == "ch1"
    assert restored.seq == 42
    assert restored.payload == "AQID"


def test_encode_decode_payload_roundtrip():
    data = b"\x00\x01\x02\xff"
    b64 = encode_payload(data)
    assert isinstance(b64, str)
    assert decode_payload(b64) == data
