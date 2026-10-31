"""Deterministic defensive detection and bounded event correlation.

ATT&CK mappings describe *possible behaviors*, not attack attribution.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from datetime import timedelta, timezone
from typing import Sequence

from .models import Event, Finding


def _make_finding(rule: str, severity: str, techniques: tuple[str, ...],
                  event: Event, evidence: Sequence[Event], explanation: str,
                  review: str) -> Finding:
    ids = tuple(sorted({item.event_id for item in evidence}))
    key = "|".join((rule, event.account.casefold(), event.source_ip, *ids))
    return Finding(
        "TH-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12].upper(),
        rule, severity, techniques, event.timestamp.astimezone(timezone.utc).isoformat(),
        event.account, event.source_ip, explanation, ids, review,
    )


def hunt(events: Sequence[Event], *, spray_accounts: int = 4,
         brute_failures: int = 3, window_minutes: int = 10,
         chain_window_minutes: int = 30) -> list[Finding]:
    """Detect password spraying, failure→success, unreferenced changes and chains."""
    for name, value, minimum, maximum in (
        ("spray_accounts", spray_accounts, 2, 100),
        ("brute_failures", brute_failures, 2, 100),
        ("window_minutes", window_minutes, 1, 1440),
        ("chain_window_minutes", chain_window_minutes, 1, 1440),
    ):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{name} must be integer in {minimum}..{maximum}")
    if any(e.timestamp.tzinfo is None or e.timestamp.utcoffset() is None for e in events):
        raise ValueError("all timestamps must be timezone-aware")
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("event IDs must be unique")

    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    window = timedelta(minutes=window_minutes)
    chain_window = timedelta(minutes=chain_window_minutes)
    spray: dict[str, deque[Event]] = defaultdict(deque)
    failures: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    prior_compromise: dict[tuple[str, str], deque[tuple[Event, tuple[Event, ...]]]] = defaultdict(deque)
    active_spray: set[str] = set()
    result: list[Finding] = []

    for event in ordered:
        account_key = (event.account.casefold(), event.source_ip)
        if event.event_type == "login" and event.outcome == "failed":
            pending = failures[account_key]
            pending.append(event)
            while pending and event.timestamp - pending[0].timestamp > window:
                pending.popleft()
            source = spray[event.source_ip]
            source.append(event)
            while source and event.timestamp - source[0].timestamp > window:
                source.popleft()
            unique_accounts = {item.account.casefold() for item in source}
            if len(unique_accounts) < spray_accounts:
                active_spray.discard(event.source_ip)
            if len(unique_accounts) >= spray_accounts and event.source_ip not in active_spray:
                result.append(_make_finding(
                    "POTENTIAL_PASSWORD_SPRAY", "high", ("T1110.003",), event, tuple(source),
                    f"{len(unique_accounts)} distinct accounts failed authentication from one source in {window_minutes} minutes",
                    "Verify source ownership, sign-in policy and affected users before containment.",
                ))
                active_spray.add(event.source_ip)

        if event.event_type == "login" and event.outcome == "success":
            pending = failures[account_key]
            while pending and event.timestamp - pending[0].timestamp > window:
                pending.popleft()
            if len(pending) >= brute_failures:
                supporting = tuple(pending) + (event,)
                result.append(_make_finding(
                    "FAILURE_TO_SUCCESS", "high", ("T1110.001",), event, supporting,
                    f"Successful sign-in followed {len(pending)} failed attempts from the same account and source",
                    "Review MFA, session and user-confirmed activity; do not assume compromise.",
                ))
                prior_compromise[account_key].append((event, supporting))
            pending.clear()

        if event.event_type == "role_change" and event.outcome == "success" and event.privileged:
            if not event.change_reference.strip():
                result.append(_make_finding(
                    "PRIVILEGE_CHANGE_NO_REFERENCE", "high", ("T1098",), event, (event,),
                    "Privileged account change recorded without a change reference",
                    "Request the ticket and independently verify authorization and change details.",
                ))
            recent = prior_compromise[account_key]
            while recent and event.timestamp - recent[0][0].timestamp > chain_window:
                recent.popleft()
            if recent:
                success, supporting = recent[-1]
                if 0 <= (event.timestamp - success.timestamp).total_seconds() <= chain_window.total_seconds():
                    result.append(_make_finding(
                        "CREDENTIAL_TO_PRIVILEGE_CHAIN", "critical", ("T1110.001", "T1098"),
                        event, supporting + (event,),
                        "Failed logins then success followed by a privileged change on the same account/source",
                        "Urgently correlate approvals and identity/session telemetry with an authorized responder.",
                    ))
                    recent.clear()
    return sorted(result, key=lambda f: (f.timestamp, f.rule, f.finding_id))
