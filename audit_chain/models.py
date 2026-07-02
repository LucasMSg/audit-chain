"""The audit entry data structure."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class AuditEntry:
    """A single record in the audit chain.

    The first four fields are *content*: they are what ``entry_hash`` commits
    to. The remaining fields are computed by :class:`audit_chain.chain.AuditLog`
    when the entry is appended and are what make the record tamper-evident.
    """

    event: str
    actor: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    occurred_at: Optional[datetime] = None

    # Populated on append.
    seq: Optional[int] = None
    entry_hash: Optional[str] = None
    chained_hash: Optional[str] = None
    signature: Optional[str] = None
