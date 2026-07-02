"""Cryptographic primitives for the tamper-evident audit chain.

Three layers of tamper detection are built from these primitives:

* ``entry_hash``   -- SHA-256 over an entry's *content*. Editing any content
  field changes the hash, so silent edits are detectable.
* ``chained_hash`` -- SHA-256 over ``previous_chained_hash || entry_hash``.
  Inserting, deleting or reordering rows breaks the chain.
* ``signature``    -- RSA (PKCS#1 v1.5, SHA-256) signature over the
  ``chained_hash``. Rewriting the whole chain requires the private key, so a
  reader holding only the public key can still detect a forged rewrite.

The functions here are deliberately small and free of any storage, framework
or configuration dependency so they are easy to read, test and reuse.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

# Fixed seed used as the "previous hash" of the very first entry.
GENESIS_SEED = b"genesis"


def genesis_hash() -> str:
    """Return the hex digest used to seed the first link in the chain."""
    return hashlib.sha256(GENESIS_SEED).hexdigest()


def _canonical_timestamp(occurred_at: datetime) -> str:
    """Normalise a timestamp to a deterministic UTC ISO-8601 string.

    Naive datetimes are assumed to be UTC. Microseconds are dropped because
    several database backends silently truncate sub-second precision on save,
    which would otherwise make a re-read hash disagree with the stored one.
    """
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=timezone.utc)
    occurred_at = occurred_at.astimezone(timezone.utc).replace(microsecond=0)
    return occurred_at.isoformat()


def compute_entry_hash(
    event: str,
    actor: Optional[str],
    metadata: Mapping[str, Any],
    occurred_at: datetime,
) -> str:
    """SHA-256 over the deterministic, canonical form of an entry's content.

    ``metadata`` is hashed in full, so any event-specific context is covered
    by the integrity guarantee rather than left unprotected.
    """
    canonical = json.dumps(
        {
            "event": event,
            "actor": actor,
            "metadata": dict(metadata or {}),
            "occurred_at": _canonical_timestamp(occurred_at),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_chained_hash(
    previous_chained_hash: Optional[str],
    entry_hash: str,
) -> str:
    """Link an entry to its predecessor.

    ``chained = SHA-256(previous_chained_hash_bytes || entry_hash_bytes)``.
    When there is no predecessor the genesis seed is used.
    """
    if previous_chained_hash is None:
        previous_chained_hash = genesis_hash()
    combined = bytes.fromhex(previous_chained_hash) + bytes.fromhex(entry_hash)
    return hashlib.sha256(combined).hexdigest()


def sign_hash(chained_hash: str, private_key: RSAPrivateKey) -> str:
    """Sign a chained hash, returning a Base64-encoded RSA signature."""
    signature = private_key.sign(
        bytes.fromhex(chained_hash),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_hash(
    chained_hash: str,
    signature: str,
    public_key: RSAPublicKey,
) -> bool:
    """Verify a Base64-encoded RSA signature against a chained hash.

    Needs only the public key, so verification can be delegated to any party.
    """
    try:
        public_key.verify(
            base64.b64decode(signature),
            bytes.fromhex(chained_hash),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False
