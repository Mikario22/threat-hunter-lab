"""CLI for read-only signature and historical behavioral threat hunting."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .behavior import build_profiles, detect_behavior, load_approved_windows, parse_cutoff
from .detection import hunt
from .ingest import parse_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Hunter Lab: explainable offline identity threat hunting")
    parser.add_argument("command", choices=["hunt"])
    parser.add_argument("events", type=Path, help="JSONL file with known event schema")
    parser.add_argument("--output", type=Path, help="Write report to local JSON file")
    parser.add_argument("--spray-accounts", type=int, default=4)
    parser.add_argument("--brute-failures", type=int, default=3)
    parser.add_argument("--baseline-events", type=Path, help="Separate historical JSONL training events")
    parser.add_argument("--baseline-cutoff", help="Timezone-aware ISO time dividing training from evaluation")
    parser.add_argument("--approved-windows", type=Path, help="Operator-reviewed exception policy JSON")
    parser.add_argument("--min-baseline-successes", type=int, default=6)
    parser.add_argument("--min-baseline-days", type=int, default=3)
    parser.add_argument("--baseline-lookback-days", type=int, default=30)
    parser.add_argument("--cooldown-minutes", type=int, default=60)
    args = parser.parse_args()

    if bool(args.baseline_events) != bool(args.baseline_cutoff):
        parser.error("--baseline-events and --baseline-cutoff must be supplied together")
    if args.approved_windows is not None and args.baseline_events is None:
        parser.error("--approved-windows requires historical baseline inputs")

    events = parse_events(args.events)
    findings = hunt(events, spray_accounts=args.spray_accounts, brute_failures=args.brute_failures)
    payload = {
        "records_analyzed": len(events),
        "findings_count": len(findings),
        "severity_breakdown": dict(Counter(item.severity for item in findings)),
        "findings": [item.to_dict() for item in findings],
        "disclaimer": "Possible behaviors, not confirmed incidents or attribution. Human review required.",
    }
    if args.baseline_events:
        cutoff = parse_cutoff(args.baseline_cutoff)
        training = parse_events(args.baseline_events)
        profiles = build_profiles(training, cutoff=cutoff,
                                  min_successes=args.min_baseline_successes,
                                  min_days=args.min_baseline_days,
                                  lookback_days=args.baseline_lookback_days)
        policies = (load_approved_windows(args.approved_windows)
                    if args.approved_windows else ())
        behavior = detect_behavior(events, profiles, cutoff=cutoff,
                                   approvals=policies, cooldown_minutes=args.cooldown_minutes)
        findings.extend(behavior.findings)
        findings.sort(key=lambda f: (f.timestamp, f.rule, f.finding_id))
        payload["findings"] = [item.to_dict() for item in findings]
        payload["findings_count"] = len(findings)
        payload["severity_breakdown"] = dict(Counter(item.severity for item in findings))
        payload["behavior"] = behavior.to_dict()
        payload["behavior"]["cutoff"] = cutoff.isoformat()
        payload["behavior"]["training_records"] = len(training)
        payload["behavior"]["approved_policy_windows"] = len(policies)

    report = json.dumps(payload, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
