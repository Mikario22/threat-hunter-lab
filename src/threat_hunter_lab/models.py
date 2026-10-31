"""Immutable event and finding models for offline threat hunting."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    event_type: str
    account: str
    source_ip: str
    host: str
    outcome: str
    privileged: bool
    change_reference: str = ""

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule: str
    severity: str
    technique_ids: tuple[str, ...]
    timestamp: str
    account: str
    source_ip: str
    explanation: str
    evidence_ids: tuple[str, ...]
    recommended_review: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
