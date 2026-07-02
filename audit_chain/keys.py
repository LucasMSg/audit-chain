"""RSA key helpers.

Thin wrappers around ``cryptography`` for loading keys from PEM and for
generating a throwaway keypair (used by the demo and the test suite).

In production, generate the keypair out of band, keep the **private** key in a
restricted file or a hardware token, and give the application only the path to
it. The public key can live anywhere -- ship it with verifiers freely.
"""
from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)


def generate_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """Generate an RSA keypair and return ``(private_pem, public_pem)``."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(pem: bytes, password: bytes | None = None) -> RSAPrivateKey:
    """Load an RSA private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


def load_public_key(pem: bytes) -> RSAPublicKey:
    """Load an RSA public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("Expected an RSA public key")
    return key
