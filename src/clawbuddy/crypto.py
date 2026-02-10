"""X25519 keypair generation and NaCl box encrypt/decrypt."""

from __future__ import annotations

import base64

from nacl.public import Box, PrivateKey, PublicKey


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes)."""
    sk = PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def pub_to_base64(pub: bytes) -> str:
    return base64.urlsafe_b64encode(pub).decode()


def base64_to_pub(b64: str) -> bytes:
    return base64.urlsafe_b64decode(b64)


def encrypt(plaintext: bytes, my_private: bytes, their_public: bytes) -> bytes:
    """Encrypt plaintext using NaCl Box (X25519 + XSalsa20-Poly1305)."""
    box = Box(PrivateKey(my_private), PublicKey(their_public))
    return box.encrypt(plaintext)


def decrypt(ciphertext: bytes, my_private: bytes, their_public: bytes) -> bytes:
    """Decrypt ciphertext using NaCl Box."""
    box = Box(PrivateKey(my_private), PublicKey(their_public))
    return box.decrypt(ciphertext)
