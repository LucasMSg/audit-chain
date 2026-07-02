"""The audit log: ties the crypto primitives to a storage backend.

``AuditLog.append`` computes an entry's three integrity values and persists it.
``AuditLog.verify`` walks the whole chain and recomputes everything, reporting
any anomaly it finds.

Two verification moments exist:

* *Continuous* -- before appending, the current tail entry is re-checked, so
  recent tampering is caught at write time (configurable via ``check_tail``).
* *On demand / scheduled* -- :meth:`verify` re-validates the entire history.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from . import crypto
from .models import AuditEntry
from .store import AuditStore

logger = logging.getLogger("audit_chain")


class TamperError(RuntimeError):
    """Raised when the continuous tail check detects tampering on append."""


@dataclass
class Anomaly:
    seq: Optional[int]
    kind: str
    detail: str


@dataclass
class VerificationReport:
    status: str
    checked: int
    anomalies: List[Anomaly] = field(default_factory=list)
    verified_at: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class AuditLog:
    def __init__(
        self,
        store: AuditStore,
        private_key,
        public_key,
        *,
        check_tail: bool = True,
        raise_on_tail_tamper: bool = False,
    ) -> None:
        self.store = store
        self.private_key = private_key
        self.public_key = public_key
        self.check_tail = check_tail
        self.raise_on_tail_tamper = raise_on_tail_tamper

    # -- writing --------------------------------------------------------------

    def append(
        self,
        event: str,
        actor: Optional[str] = None,
        metadata: Optional[dict] = None,
        occurred_at: Optional[datetime] = None,
    ) -> AuditEntry:
        """Append a new audited event and return the stored entry."""
        metadata = metadata or {}
        occurred_at = occurred_at or datetime.now(timezone.utc)

        with self.store.lock():
            last = self.store.latest()

            if self.check_tail and last is not None:
                self._check_tail(last)

            previous_chained = last.chained_hash if last else None
            entry_hash = crypto.compute_entry_hash(
                event, actor, metadata, occurred_at
            )
            chained_hash = crypto.compute_chained_hash(previous_chained, entry_hash)
            signature = crypto.sign_hash(chained_hash, self.private_key)

            entry = AuditEntry(
                event=event,
                actor=actor,
                metadata=metadata,
                occurred_at=occurred_at,
                entry_hash=entry_hash,
                chained_hash=chained_hash,
                signature=signature,
            )
            self.store.append(entry)
            return entry

    def _check_tail(self, last: AuditEntry) -> None:
        recomputed = crypto.compute_entry_hash(
            last.event, last.actor, last.metadata, last.occurred_at
        )
        sig_ok = crypto.verify_hash(
            last.chained_hash, last.signature, self.public_key
        )
        if recomputed != last.entry_hash or not sig_ok:
            msg = f"Integrity violation at entry {last.seq} before appending"
            logger.critical(msg)
            if self.raise_on_tail_tamper:
                raise TamperError(msg)

    # -- verification ---------------------------------------------------------

    def verify(self) -> VerificationReport:
        """Recompute and re-validate the entire chain."""
        anomalies: List[Anomaly] = []
        previous_chained: Optional[str] = None
        checked = 0

        for entry in self.store.all():
            checked += 1

            # 1. Content integrity.
            expected_entry_hash = crypto.compute_entry_hash(
                entry.event, entry.actor, entry.metadata, entry.occurred_at
            )
            if expected_entry_hash != entry.entry_hash:
                anomalies.append(
                    Anomaly(entry.seq, "entry_hash_mismatch",
                            f"Content of entry {entry.seq} was modified.")
                )

            # 2. Chain continuity.
            expected_chained = crypto.compute_chained_hash(
                previous_chained, entry.entry_hash
            )
            if expected_chained != entry.chained_hash:
                anomalies.append(
                    Anomaly(entry.seq, "broken_chain",
                            f"Chain broken at entry {entry.seq}: an entry was "
                            "inserted, deleted or reordered.")
                )

            # 3. Signature.
            if not entry.signature:
                anomalies.append(
                    Anomaly(entry.seq, "missing_signature",
                            f"Entry {entry.seq} is unsigned.")
                )
            elif not crypto.verify_hash(
                entry.chained_hash, entry.signature, self.public_key
            ):
                anomalies.append(
                    Anomaly(entry.seq, "invalid_signature",
                            f"Signature on entry {entry.seq} is invalid: the "
                            "chain may have been rewritten.")
                )

            previous_chained = entry.chained_hash

        return VerificationReport(
            status="tampered" if anomalies else "ok",
            checked=checked,
            anomalies=anomalies,
            verified_at=datetime.now(timezone.utc).isoformat(),
        )
