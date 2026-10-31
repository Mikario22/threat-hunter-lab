"""Strict, bounded JSONL parsing. Input is data, never executable instructions."""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path

from .models import Event

ALLOWED_EVENT_TYPES = frozenset({"login", "role_change"})
ALLOWED_OUTCOMES = frozenset({"success", "failed"})
FIELDS = frozenset({"event_id", "timestamp", "event_type", "account", "source_ip", "host", "outcome", "privileged", "change_reference"})
REQUIRED = FIELDS - {"change_reference"}


def parse_events(path: str | Path, *, max_events: int = 500_000) -> tuple[Event, ...]:
    if type(max_events) is not int or not 1 <= max_events <= 500_000:
        raise ValueError("max_events must be an integer in 1..500000")
    events: list[Event] = []
    identifiers: set[str] = set()
    with Path(path).open("r", encoding="utf-8-sig") as stream:
        for line_number, raw in enumerate(stream, start=1):
            if not raw.strip():
                continue
            if len(events) >= max_events:
                raise ValueError(f"event limit exceeded at line {line_number}")
            try:
                row = json.loads(raw)
                if not isinstance(row, dict) or not REQUIRED <= set(row) or not set(row) <= FIELDS:
                    raise ValueError("invalid field set")
                for field in ("event_id", "timestamp", "account", "source_ip", "host"):
                    if not isinstance(row[field], str) or not row[field].strip() or len(row[field]) > 256:
                        raise ValueError(f"invalid {field}")
                if not isinstance(row["event_type"], str) or row["event_type"] not in ALLOWED_EVENT_TYPES:
                    raise ValueError("invalid event_type")
                if not isinstance(row["outcome"], str) or row["outcome"] not in ALLOWED_OUTCOMES:
                    raise ValueError("invalid outcome")
                if type(row["privileged"]) is not bool:
                    raise ValueError("privileged must be boolean")
                reference = row.get("change_reference", "")
                if not isinstance(reference, str) or len(reference) > 256:
                    raise ValueError("invalid change_reference")
                stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    raise ValueError("timestamp must include UTC offset")
                ipaddress.ip_address(row["source_ip"])
                if row["event_id"] in identifiers:
                    raise ValueError("duplicate event_id")
                identifiers.add(row["event_id"])
                events.append(Event(
                    row["event_id"], stamp, row["event_type"], row["account"],
                    row["source_ip"], row["host"], row["outcome"],
                    row["privileged"], reference,
                ))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid JSONL line {line_number}: {exc}") from exc
    return tuple(sorted(events, key=lambda e: (e.timestamp, e.event_id)))
