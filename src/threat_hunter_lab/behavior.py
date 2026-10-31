"""Offline account behavior baselines and adaptive multi-signal login detection.

Training is a separate, earlier dataset: future events never update a profile.
A separate operator-reviewed policy file may suppress only this anomaly rule.
Neither a login's self-reported change_reference nor an API can grant approval.
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

from .detection import _make_finding
from .models import Event, Finding

ANOMALY_RULE = "BEHAVIOR_LOGIN_ANOMALY"


@dataclass(frozen=True)
class BehaviorProfile:
    account: str
    samples: int
    active_days: int
    known_sources: tuple[str, ...]
    known_hosts: tuple[str, ...]
    typical_hours_utc: tuple[int, ...]
    required_signals: int
    trained_before: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ApprovedWindow:
    policy_id: str
    account: str
    source_ip: str
    host: str
    starts_at: datetime
    ends_at: datetime
    ticket: str
    approved_by: str

    def matches(self, event: Event) -> bool:
        return (
            self.account.casefold() == event.account.casefold()
            and self.source_ip == event.source_ip
            and self.host.casefold() == event.host.casefold()
            and self.starts_at <= event.timestamp <= self.ends_at
        )


@dataclass(frozen=True)
class Decision:
    event_id: str
    account: str
    decision: str
    signals: tuple[str, ...]
    score: int
    required_signals: int
    reason: str
    policy_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class BehavioralResult:
    findings: tuple[Finding, ...]
    decisions: tuple[Decision, ...]
    trained_profiles: tuple[BehaviorProfile, ...]
    unknown_accounts: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "findings": [item.to_dict() for item in self.findings],
            "decisions": [item.to_dict() for item in self.decisions],
            "trained_profiles": [item.to_dict() for item in self.trained_profiles],
            "unknown_accounts": list(self.unknown_accounts),
        }


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _validate_integer(value: int, name: str, lo: int, hi: int) -> None:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be integer in {lo}..{hi}")


def parse_cutoff(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("cutoff must be an ISO timestamp with timezone") from exc
    if not _aware(ts):
        raise ValueError("cutoff must include timezone")
    return ts


def build_profiles(
    training: Sequence[Event], *,
    cutoff: datetime,
    min_successes: int = 6,
    min_days: int = 3,
    lookback_days: int = 30,
    hour_tolerance: int = 1,
) -> dict[str, BehaviorProfile]:
    """Fit only on earlier successful logins, never on evaluation events.

    Typical UTC hours include a circular +/- tolerance around observed hours.
    Accounts with fewer than min_successes or distinct days get no profile.
    """
    _validate_integer(min_successes, "min_successes", 2, 1000)
    _validate_integer(min_days, "min_days", 1, 90)
    _validate_integer(lookback_days, "lookback_days", 1, 365)
    _validate_integer(hour_tolerance, "hour_tolerance", 0, 3)
    if not _aware(cutoff):
        raise ValueError("cutoff must be timezone-aware")
    oldest = cutoff - timedelta(days=lookback_days)
    groups: dict[str, list[Event]] = defaultdict(list)
    seen: set[str] = set()
    for event in training:
        if event.event_id in seen:
            raise ValueError("training contains duplicate event_id")
        seen.add(event.event_id)
        if not _aware(event.timestamp):
            raise ValueError("training timestamps must be timezone-aware")
        if event.timestamp >= cutoff:
            raise ValueError("training event at/after cutoff would leak evaluation data")
        if oldest <= event.timestamp and event.event_type == "login" and event.outcome == "success":
            groups[event.account.casefold()].append(event)
    result: dict[str, BehaviorProfile] = {}
    for account, samples in sorted(groups.items()):
        days = {item.timestamp.astimezone(timezone.utc).date() for item in samples}
        if len(samples) < min_successes or len(days) < min_days:
            continue
        hours = {item.timestamp.astimezone(timezone.utc).hour for item in samples}
        extended = sorted({(hour + delta) % 24 for hour in hours
                           for delta in range(-hour_tolerance, hour_tolerance + 1)})
        ips = tuple(sorted({item.source_ip for item in samples}))
        hosts = tuple(sorted({item.host.casefold() for item in samples}))
        # Mobile/distributed accounts need 3 independent novelty signals.
        required = 3 if len(ips) >= 3 else 2
        result[account] = BehaviorProfile(
            account, len(samples), len(days), ips, hosts,
            tuple(extended), required, cutoff.isoformat(),
        )
    return result


def _match_policy(event: Event, windows: Sequence[ApprovedWindow]) -> ApprovedWindow | None:
    return next((window for window in windows if window.matches(event)), None)


def detect_behavior(
    events: Sequence[Event],
    profiles: dict[str, BehaviorProfile],
    *,
    cutoff: datetime,
    approvals: Sequence[ApprovedWindow] = (),
    cooldown_minutes: int = 60,
) -> BehavioralResult:
    """Evaluate events after the cutoff, with separate suppression evidence.

    Two signals are required for stable accounts; users with >=3 historical
    source IPs need all three. A recorded ticket in an event does NOT suppress.
    Other signature/correlation rules are deliberately outside this policy.
    """
    if not _aware(cutoff):
        raise ValueError("cutoff must be timezone-aware")
    _validate_integer(cooldown_minutes, "cooldown_minutes", 0, 1440)
    if len({item.event_id for item in events}) != len(events):
        raise ValueError("duplicate event_id in evaluation events")
    if any(not _aware(item.timestamp) for item in events):
        raise ValueError("evaluation timestamps must be timezone-aware")
    if any(profile.trained_before != cutoff.isoformat() for profile in profiles.values()):
        raise ValueError("profiles must be trained against the same cutoff")
    last_alert: dict[tuple[str, str], datetime] = {}
    findings: list[Finding] = []
    decisions: list[Decision] = []
    unknown: set[str] = set()
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        if event.timestamp < cutoff:
            continue
        if event.event_type != "login" or event.outcome != "success":
            continue
        account = event.account.casefold()
        profile = profiles.get(account)
        if profile is None:
            unknown.add(account)
            decisions.append(Decision(event.event_id, event.account, "insufficient_history", (), 0, 0,
                                      "No sufficiently supported historical account baseline"))
            continue
        hour = event.timestamp.astimezone(timezone.utc).hour
        signals: list[str] = []
        if event.source_ip not in profile.known_sources:
            signals.append("new_source_ip")
        if hour not in profile.typical_hours_utc:
            signals.append("unusual_utc_hour")
        if event.host.casefold() not in profile.known_hosts:
            signals.append("new_target_host")
        score = min(100, 35 + 25 * ("new_source_ip" in signals)
                    + 20 * ("unusual_utc_hour" in signals)
                    + 20 * ("new_target_host" in signals))
        if len(signals) < profile.required_signals:
            decisions.append(Decision(event.event_id, event.account, "below_threshold",
                                      tuple(signals), score, profile.required_signals,
                                      "Not enough independent deviations to alert"))
            continue
        policy = _match_policy(event, approvals)
        if policy is not None:
            decisions.append(Decision(event.event_id, event.account, "suppressed_by_policy",
                                      tuple(signals), score, profile.required_signals,
                                      "Operator-reviewed exception matched account, IP, host and time",
                                      policy.policy_id))
            continue
        key = (account, event.source_ip)
        previous = last_alert.get(key)
        if previous is not None and event.timestamp - previous <= timedelta(minutes=cooldown_minutes):
            decisions.append(Decision(event.event_id, event.account, "cooldown",
                                      tuple(signals), score, profile.required_signals,
                                      "A similar anomaly for this account/source was already reported"))
            continue
        last_alert[key] = event.timestamp
        review = "Verify account owner, source and session context; confirm any approval separately."
        findings.append(_make_finding(
            ANOMALY_RULE, "high", ("T1078",), event, (event,),
            f"Historical account baseline exceeded ({len(signals)}/{profile.required_signals} signals: "
            + ", ".join(signals) + f"; heuristic score {score}/100)",
            review,
        ))
        decisions.append(Decision(event.event_id, event.account, "alert",
                                  tuple(signals), score, profile.required_signals,
                                  "Novel signals exceeded the adaptive per-account threshold"))
    return BehavioralResult(
        tuple(findings), tuple(decisions),
        tuple(sorted(profiles.values(), key=lambda profile: profile.account)),
        tuple(sorted(unknown)),
    )


def load_approved_windows(path: str | Path) -> tuple[ApprovedWindow, ...]:
    """Parse a tightly scoped, *operator-reviewed* exception manifest.

    Schema validation does not independently verify approval signatures.
    These entries must be approved outside of Threat Hunter Lab.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"windows"} or not isinstance(raw["windows"], list):
        raise ValueError("policy must contain a windows array")
    if len(raw["windows"]) > 100:
        raise ValueError("too many approved windows")
    required = {"policy_id", "account", "source_ip", "host", "from", "until",
                "ticket", "approved_by"}
    windows: list[ApprovedWindow] = []
    ids: set[str] = set()
    for item in raw["windows"]:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("invalid policy fields")
        if any(not isinstance(item[key], str) or not item[key].strip() or len(item[key]) > 256
               for key in required):
            raise ValueError("policy fields must be nonempty bounded strings")
        if any("*" in item[key] for key in ("account", "source_ip", "host")):
            raise ValueError("invalid policy scope: wildcards are prohibited")
        if item["policy_id"] in ids:
            raise ValueError("duplicate policy_id")
        ids.add(item["policy_id"])
        try:
            ipaddress.ip_address(item["source_ip"])
            start, end = parse_cutoff(item["from"]), parse_cutoff(item["until"])
        except ValueError as exc:
            raise ValueError("invalid policy source or interval") from exc
        if not start < end or end - start > timedelta(hours=24):
            raise ValueError("approved window must last >0 and <=24 hours")
        windows.append(ApprovedWindow(
            item["policy_id"], item["account"], item["source_ip"], item["host"],
            start, end, item["ticket"], item["approved_by"],
        ))
    return tuple(windows)
