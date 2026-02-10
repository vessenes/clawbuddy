"""Tests for clawbuddy.crypto — keypair gen, base64 roundtrip, encrypt/decrypt."""

from nacl.exceptions import CryptoError
import pytest

from clawbuddy.crypto import (
    base64_to_pub,
    decrypt,
    encrypt,
    generate_keypair,
    pub_to_base64,
)


def test_generate_keypair_lengths():
    priv, pub = generate_keypair()
    assert len(priv) == 32
    assert len(pub) == 32


def test_pub_base64_roundtrip():
    _, pub = generate_keypair()
    b64 = pub_to_base64(pub)
    assert isinstance(b64, str)
    assert base64_to_pub(b64) == pub


def test_encrypt_decrypt_roundtrip():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    plaintext = b"hello from alice"
    ct = encrypt(plaintext, alice_priv, bob_pub)
    assert ct != plaintext
    pt = decrypt(ct, bob_priv, alice_pub)
    assert pt == plaintext


def test_encrypt_decrypt_reverse_direction():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    plaintext = b"hello from bob"
    ct = encrypt(plaintext, bob_priv, alice_pub)
    pt = decrypt(ct, alice_priv, bob_pub)
    assert pt == plaintext


def test_decrypt_wrong_key_raises():
    alice_priv, alice_pub = generate_keypair()
    _, bob_pub = generate_keypair()
    eve_priv, _ = generate_keypair()

    ct = encrypt(b"secret", alice_priv, bob_pub)
    with pytest.raises(CryptoError):
        decrypt(ct, eve_priv, alice_pub)
