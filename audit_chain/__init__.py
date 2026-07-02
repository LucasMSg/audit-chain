"""audit_chain -- a tamper-evident, hash-chained, signed audit log.

Quick start::

    from audit_chain import AuditLog, InMemoryStore, generate_keypair
    from audit_chain import load_private_key, load_public_key

    priv_pem, pub_pem = generate_keypair()
    log = AuditLog(
        InMemoryStore(),
        load_private_key(priv_pem),
        load_public_key(pub_pem),
    )

    log.append("user.login", actor="alice", metadata={"ip": "10.0.0.1"})
    report = log.verify()
    assert report.ok
"""
from .chain import AuditLog, Anomaly, TamperError, VerificationReport
from .crypto import (
    compute_chained_hash,
    compute_entry_hash,
    genesis_hash,
    sign_hash,
    verify_hash,
)
from .keys import generate_keypair, load_private_key, load_public_key
from .models import AuditEntry
from .store import AuditStore, InMemoryStore, SQLiteStore

__all__ = [
    "AuditLog",
    "AuditEntry",
    "Anomaly",
    "VerificationReport",
    "TamperError",
    "AuditStore",
    "InMemoryStore",
    "SQLiteStore",
    "generate_keypair",
    "load_private_key",
    "load_public_key",
    "compute_entry_hash",
    "compute_chained_hash",
    "sign_hash",
    "verify_hash",
    "genesis_hash",
]

__version__ = "0.1.0"
