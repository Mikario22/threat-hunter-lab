"""CLI for offline, read-only hunting of synthetic JSONL events."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .detection import hunt
from .ingest import parse_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Threat Hunter Lab: explainable offline identity threat hunting")
    parser.add_argument("command", choices=["hunt"])
    parser.add_argument("events", type=Path, help="JSONL file with known event schema")
    parser.add_argument("--output", type=Path, help="Write report to local JSON file")
    parser.add_argument("--spray-accounts", type=int, default=4)
    parser.add_argument("--brute-failures", type=int, default=3)
    args = parser.parse_args()
    events = parse_events(args.events)
    findings = hunt(events, spray_accounts=args.spray_accounts,
                    brute_failures=args.brute_failures)
    payload = {"records_analyzed": len(events), "findings_count": len(findings),
               "severity_breakdown": dict(Counter(item.severity for item in findings)),
               "findings": [item.to_dict() for item in findings],
               "disclaimer": "Possible behaviors, not confirmed incidents or attribution. Human review required."}
    report = json.dumps(payload, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
