# audit-chain

A small, dependency-light library for a **tamper-evident audit log**: an
append-only record of sensitive actions where any later modification,
deletion, insertion or reordering is detectable.

It uses three independent layers:

| Layer | Mechanism | Catches |
|-------|-----------|---------|
| `entry_hash` | SHA-256 over an entry's content | editing any field of a row |
| `chained_hash` | SHA-256(`prev_chained_hash` ‖ `entry_hash`) | inserting / deleting / reordering rows |
| `signature` | RSA (PKCS#1 v1.5, SHA-256) over `chained_hash` | rewriting the whole chain (requires the private key) |

Verification needs only the **public** key, so any party can independently
check the full history.

## Install

```bash
pip install -e .
```

## Usage

```python
from audit_chain import (
    AuditLog, InMemoryStore, generate_keypair,
    load_private_key, load_public_key,
)

priv_pem, pub_pem = generate_keypair()          # do this once, out of band
log = AuditLog(
    InMemoryStore(),                             # or SQLiteStore("audit.db")
    load_private_key(priv_pem),
    load_public_key(pub_pem),
)

log.append("user.login",   actor="alice", metadata={"ip": "10.0.0.1"})
log.append("user.deleted", actor="alice", metadata={"target": "bob"})

report = log.verify()
print(report.status)        # "ok" or "tampered"
print(report.anomalies)     # list of (seq, kind, detail)
```

Run the demonstration of all three detection layers:

```bash
python -m examples.demo
pytest
```

## Design

```
append(event, actor, metadata)
        │
        ▼
  lock the store (serialise concurrent appends)
        │
        ├─ re-verify the current tail entry      (continuous check)
        ├─ entry_hash   = SHA-256(content)
        ├─ chained_hash = SHA-256(prev_chained ‖ entry_hash)
        ├─ signature    = RSA-sign(chained_hash)
        ▼
  persist the new entry
```

Storage is pluggable via the `AuditStore` interface. Two reference backends
ship in the box: `InMemoryStore` and `SQLiteStore`. Implementing one for
Postgres/MySQL/etc. is a single subclass.

## Security model and limitations

This is honest about what the design does and does not give you:

- **Signing key location.** The integrity guarantee against a *full rewrite*
  holds only as long as the attacker does not have the private key. If the
  signing key and the data live on the same compromised host, an attacker can
  rewrite and re-sign the chain. Keep the private key in a restricted file, a
  hardware token, or a dedicated signing service.
- **No external time anchor.** Timestamps are self-asserted by the writer.
  Anchoring the periodic chain head to an external notary (e.g.
  [OpenTimestamps](https://opentimestamps.org/)) would make backdating
  detectable too.
- **Continuous check is shallow.** The on-write check re-verifies only the
  current tail entry; run `verify()` periodically (e.g. on a schedule) for a
  full-history check.
- **Append ordering.** Sequence numbers reflect insertion order, not
  wall-clock event order, if appends are made concurrently from unordered
  callers. Append synchronously within the action's transaction if strict
  ordering matters.

## Notes on provenance

This is a clean, framework-agnostic reimplementation of a hash-chained audit
log I designed. Compared with the original it:

- drops all application-specific coupling (web framework, ORM, config, and
  unrelated services) so the cryptographic core stands alone;
- hashes the full event metadata, closing a gap where some context fields were
  not covered by `entry_hash`;
- removes a "per-user HMAC signature" experiment whose key was carried inside
  the session token — a symmetric secret reachable by anyone holding the
  token, which did not deliver the non-repudiation it was meant to. (Happy to
  revisit a corrected design that keeps the user's key client-side.)

## License

MIT — see [LICENSE](LICENSE).
