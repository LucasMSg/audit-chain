"""Pluggable, append-only storage for the audit chain.

The chain logic doesn't care *where* entries live, only that the backend can:

* hand back the most recent entry (to chain onto / re-verify),
* iterate all entries in insertion order (to verify the whole chain),
* append a new entry, and
* serialise concurrent appends so two writers can't fork the chain.

Two reference backends are provided: an in-memory one (handy for tests and
demos) and a SQLite one (a self-contained, on-disk example). Swapping in
Postgres, MySQL or anything else is just another subclass.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, List, Optional

from .models import AuditEntry


class AuditStore(ABC):
    """Append-only storage interface for audit entries."""

    @abstractmethod
    @contextmanager
    def lock(self) -> Iterator[None]:
        """Serialise appends so the chain can't fork under concurrency."""
        raise NotImplementedError

    @abstractmethod
    def latest(self) -> Optional[AuditEntry]:
        """Return the most recently appended entry, or ``None`` if empty."""
        raise NotImplementedError

    @abstractmethod
    def append(self, entry: AuditEntry) -> int:
        """Persist ``entry`` and return its assigned sequence number."""
        raise NotImplementedError

    @abstractmethod
    def all(self) -> Iterator[AuditEntry]:
        """Yield every entry in insertion order."""
        raise NotImplementedError


class InMemoryStore(AuditStore):
    """Process-local store backed by a list. Not durable; great for tests."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()

    @contextmanager
    def lock(self) -> Iterator[None]:
        with self._lock:
            yield

    def latest(self) -> Optional[AuditEntry]:
        return self._entries[-1] if self._entries else None

    def append(self, entry: AuditEntry) -> int:
        entry.seq = len(self._entries) + 1
        self._entries.append(entry)
        return entry.seq

    def all(self) -> Iterator[AuditEntry]:
        yield from self._entries


class SQLiteStore(AuditStore):
    """Durable, single-file SQLite store.

    Concurrency is handled with ``BEGIN IMMEDIATE``, which takes a reserved
    lock for the duration of the append so two writers can't read the same
    tail and chain onto it twice.
    """

    def __init__(self, path: str = "audit.db") -> None:
        # check_same_thread=False lets the connection be shared; the lock()
        # context manager provides the actual mutual exclusion.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                event        TEXT    NOT NULL,
                actor        TEXT,
                metadata     TEXT    NOT NULL,
                occurred_at  TEXT    NOT NULL,
                entry_hash   TEXT    NOT NULL,
                chained_hash TEXT    NOT NULL,
                signature    TEXT    NOT NULL
            )
            """
        )
        self._conn.commit()

    @contextmanager
    def lock(self) -> Iterator[None]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            event=row["event"],
            actor=row["actor"],
            metadata=json.loads(row["metadata"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            seq=row["seq"],
            entry_hash=row["entry_hash"],
            chained_hash=row["chained_hash"],
            signature=row["signature"],
        )

    def latest(self) -> Optional[AuditEntry]:
        row = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def append(self, entry: AuditEntry) -> int:
        occurred = entry.occurred_at or datetime.now(timezone.utc)
        cur = self._conn.execute(
            """
            INSERT INTO audit_log
                (event, actor, metadata, occurred_at,
                 entry_hash, chained_hash, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.event,
                entry.actor,
                json.dumps(entry.metadata, sort_keys=True),
                occurred.isoformat(),
                entry.entry_hash,
                entry.chained_hash,
                entry.signature,
            ),
        )
        entry.seq = int(cur.lastrowid)
        return entry.seq

    def all(self) -> Iterator[AuditEntry]:
        for row in self._conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
            yield self._row_to_entry(row)

    def close(self) -> None:
        self._conn.close()
