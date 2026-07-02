"""Runnable demonstration of the audit chain.

    python -m examples.demo

Appends a few events, verifies the chain is intact, then tampers with it three
different ways and shows that each kind of tampering is detected.
"""
from audit_chain import (
    AuditLog,
    InMemoryStore,
    generate_keypair,
    load_private_key,
    load_public_key,
)


def build_log():
    priv_pem, pub_pem = generate_keypair()
    store = InMemoryStore()
    log = AuditLog(store, load_private_key(priv_pem), load_public_key(pub_pem))
    log.append("user.login", actor="alice", metadata={"ip": "10.0.0.1"})
    log.append("user.created", actor="alice", metadata={"target": "bob"})
    log.append("user.deleted", actor="alice", metadata={"target": "carol"})
    return store, log


def show(label, report):
    print(f"\n{label}")
    print(f"  status:   {report.status}")
    print(f"  checked:  {report.checked}")
    for a in report.anomalies:
        print(f"  anomaly:  [entry {a.seq}] {a.kind} -- {a.detail}")


def main():
    store, log = build_log()
    show("1) Untouched chain", log.verify())

    # Edit content in place.
    store._entries[1].metadata["target"] = "mallory"
    show("2) Content of entry 2 edited", log.verify())

    # Delete a record.
    store, log = build_log()
    del store._entries[1]
    show("3) Entry 2 deleted", log.verify())

    # Forge a record without the private key (signature can't be reproduced).
    store, log = build_log()
    forged = store._entries[2]
    forged.event = "user.promoted"
    forged.entry_hash = __import__("audit_chain").compute_entry_hash(
        forged.event, forged.actor, forged.metadata, forged.occurred_at
    )
    show("4) Entry 3 forged (content + entry_hash rewritten, no re-sign)",
         log.verify())


if __name__ == "__main__":
    main()
