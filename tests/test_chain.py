"""Tests for the audit chain: happy path + each tamper-detection layer."""
import pytest

from audit_chain import (
    AuditLog,
    InMemoryStore,
    SQLiteStore,
    compute_entry_hash,
    generate_keypair,
    load_private_key,
    load_public_key,
)


@pytest.fixture
def keys():
    priv_pem, pub_pem = generate_keypair()
    return load_private_key(priv_pem), load_public_key(pub_pem)


@pytest.fixture
def log(keys):
    private_key, public_key = keys
    log = AuditLog(InMemoryStore(), private_key, public_key)
    log.append("user.login", actor="alice", metadata={"ip": "10.0.0.1"})
    log.append("user.created", actor="alice", metadata={"target": "bob"})
    log.append("user.deleted", actor="alice", metadata={"target": "carol"})
    return log


def test_intact_chain_verifies(log):
    report = log.verify()
    assert report.ok
    assert report.checked == 3
    assert report.anomalies == []


def test_content_edit_is_detected(log):
    log.store._entries[1].metadata["target"] = "mallory"
    report = log.verify()
    assert not report.ok
    assert any(a.kind == "entry_hash_mismatch" for a in report.anomalies)


def test_deletion_is_detected(log):
    del log.store._entries[1]
    report = log.verify()
    assert not report.ok
    assert any(a.kind == "broken_chain" for a in report.anomalies)


def test_forgery_without_key_is_detected(log):
    forged = log.store._entries[2]
    forged.event = "user.promoted"
    forged.entry_hash = compute_entry_hash(
        forged.event, forged.actor, forged.metadata, forged.occurred_at
    )
    # entry_hash now matches content, but chained_hash/signature do not.
    report = log.verify()
    assert not report.ok
    kinds = {a.kind for a in report.anomalies}
    assert "broken_chain" in kinds or "invalid_signature" in kinds


def test_metadata_is_covered_by_hash(log):
    # Editing only metadata (not other content) must still be caught.
    log.store._entries[0].metadata["ip"] = "6.6.6.6"
    assert not log.verify().ok


def test_sqlite_backend_roundtrips(keys, tmp_path):
    private_key, public_key = keys
    store = SQLiteStore(str(tmp_path / "audit.db"))
    log = AuditLog(store, private_key, public_key)
    log.append("a", actor="x", metadata={"n": 1})
    log.append("b", actor="y", metadata={"n": 2})

    report = log.verify()
    assert report.ok
    assert report.checked == 2

    # Reopen from disk and re-verify against the same keys.
    store2 = SQLiteStore(str(tmp_path / "audit.db"))
    log2 = AuditLog(store2, private_key, public_key)
    assert log2.verify().ok
    store.close()
    store2.close()
