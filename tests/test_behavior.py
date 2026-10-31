"""Behavior v2 tests using fabricated records and offline policies only."""
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_hunter_lab.behavior import (
    ANOMALY_RULE, ApprovedWindow, build_profiles, detect_behavior,
    load_approved_windows, parse_cutoff,
)
from threat_hunter_lab.ingest import parse_events

ROOT = Path(__file__).resolve().parents[1] / "samples"
CUTOFF = parse_cutoff("2026-10-30T00:00:00+02:00")


class BehaviorTests(unittest.TestCase):
    def setUp(self):
        self.training = parse_events(ROOT / "behavior_training.jsonl")
        self.events = parse_events(ROOT / "behavior_evaluation.jsonl")
        self.profiles = build_profiles(self.training, cutoff=CUTOFF)
        self.approvals = load_approved_windows(ROOT / "approved_windows.json")

    def test_profiles_are_historical_and_per_account(self):
        self.assertEqual(set(self.profiles), {"synthetic-analyst", "synthetic-operator"})
        stable = self.profiles["synthetic-analyst"]
        mobile = self.profiles["synthetic-operator"]
        self.assertEqual((stable.samples, stable.active_days, stable.required_signals), (6, 3, 2))
        self.assertEqual((mobile.samples, mobile.active_days, mobile.required_signals), (9, 3, 3))
        self.assertNotIn("synthetic-newcomer", self.profiles)
        self.assertIn(8, stable.typical_hours_utc)
        self.assertNotIn(21, stable.typical_hours_utc)

    def test_alerts_are_multi_signal_and_adaptive(self):
        report = detect_behavior(self.events, self.profiles, cutoff=CUTOFF)
        self.assertEqual(len(report.findings), 3)
        self.assertTrue(all(f.rule == ANOMALY_RULE for f in report.findings))
        decisions = {decision.event_id: decision for decision in report.decisions}
        self.assertEqual(decisions["BEHAV-001"].decision, "below_threshold")
        self.assertEqual(decisions["BEHAV-002"].decision, "alert")
        self.assertEqual(decisions["BEHAV-002"].signals,
                         ("new_source_ip", "unusual_utc_hour"))
        self.assertEqual(decisions["BEHAV-002"].score, 80)
        self.assertEqual(decisions["BEHAV-005"].decision, "below_threshold")
        self.assertEqual(decisions["BEHAV-005"].required_signals, 3)
        self.assertEqual(decisions["BEHAV-006"].decision, "alert")
        self.assertEqual(decisions["BEHAV-006"].score, 100)
        self.assertEqual(decisions["BEHAV-007"].decision, "insufficient_history")

    def test_approved_policy_suppresses_exact_match_only(self):
        result = detect_behavior(self.events, self.profiles, cutoff=CUTOFF,
                                 approvals=self.approvals)
        self.assertEqual(len(result.findings), 2)
        decisions = {decision.event_id: decision for decision in result.decisions}
        self.assertEqual(decisions["BEHAV-004"].decision, "suppressed_by_policy")
        self.assertEqual(decisions["BEHAV-004"].policy_id, "APPROVED-SYNTH-01")
        self.assertEqual(decisions["BEHAV-002"].decision, "alert")
        self.assertEqual(decisions["BEHAV-006"].decision, "alert")
        self.assertEqual(result.unknown_accounts, ("synthetic-newcomer",))

    def test_ticket_in_event_alone_never_authorizes(self):
        result = detect_behavior(self.events, self.profiles, cutoff=CUTOFF)
        decision = next(x for x in result.decisions if x.event_id == "BEHAV-004")
        self.assertEqual(decision.decision, "alert")
        self.assertIsNone(decision.policy_id)

    def test_cooldown_reduces_duplicate_alerts(self):
        result = detect_behavior(self.events, self.profiles, cutoff=CUTOFF)
        decisions = {d.event_id: d for d in result.decisions}
        self.assertEqual(decisions["BEHAV-003"].decision, "cooldown")
        self.assertEqual(len([d for d in result.decisions if d.decision == "cooldown"]), 1)

    def test_evidence_only_references_triggering_event(self):
        result = detect_behavior(self.events, self.profiles, cutoff=CUTOFF,
                                 approvals=self.approvals)
        original_ids = {event.event_id for event in self.events}
        self.assertTrue(all(set(f.evidence_ids) <= original_ids for f in result.findings))
        self.assertTrue(all(len(f.evidence_ids) == 1 for f in result.findings))
        self.assertTrue(all(f.technique_ids == ("T1078",) for f in result.findings))

    def test_out_of_order_results_identical(self):
        a = detect_behavior(self.events, self.profiles, cutoff=CUTOFF, approvals=self.approvals)
        b = detect_behavior(list(reversed(self.events)), self.profiles,
                            cutoff=CUTOFF, approvals=self.approvals)
        self.assertEqual(a, b)

    def test_training_future_event_rejected_not_leaked(self):
        late = replace(self.training[0], event_id="FUTURE", timestamp=CUTOFF + timedelta(minutes=1))
        with self.assertRaisesRegex(ValueError, "leak"):
            build_profiles([*self.training, late], cutoff=CUTOFF)

    def test_training_too_old_or_too_sparse_skips_accounts(self):
        limited = build_profiles(self.training, cutoff=CUTOFF, lookback_days=1)
        self.assertEqual(limited, {})
        strict = build_profiles(self.training, cutoff=CUTOFF, min_successes=10)
        self.assertEqual(strict, {})

    def test_evaluation_before_cutoff_not_alerted(self):
        early = replace(self.events[1], event_id="EARLY", timestamp=CUTOFF - timedelta(minutes=1))
        result = detect_behavior([early], self.profiles, cutoff=CUTOFF)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.decisions, ())

    def test_old_normal_hour_or_source_change_alone_below_threshold(self):
        familiar = self.events[0]
        new_ip_only = replace(familiar, event_id="NEW-SOURCE", source_ip="198.51.100.99")
        odd_time_only = replace(familiar, event_id="ODD-TIME",
                                timestamp=datetime.fromisoformat("2026-10-30T23:40:00+02:00"))
        for candidate in (new_ip_only, odd_time_only):
            with self.subTest(id=candidate.event_id):
                result = detect_behavior([candidate], self.profiles, cutoff=CUTOFF)
                self.assertEqual(result.findings, ())
                self.assertEqual(result.decisions[0].decision, "below_threshold")

    def test_unrecognized_account_produces_no_confident_alert(self):
        result = detect_behavior([self.events[-1]], self.profiles, cutoff=CUTOFF)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.unknown_accounts, ("synthetic-newcomer",))

    def test_policy_has_exact_account_ip_host_and_time(self):
        accepted = self.events[3]
        assert self.approvals[0].matches(accepted)
        variations = [
            replace(accepted, account="other"),
            replace(accepted, source_ip="198.51.100.44"),
            replace(accepted, host="other-host"),
            replace(accepted, timestamp=accepted.timestamp + timedelta(days=1)),
        ]
        self.assertTrue(all(not self.approvals[0].matches(candidate) for candidate in variations))

    def test_policy_manifest_rejects_overbroad_or_malformed_entries(self):
        raw = json.loads((ROOT / "approved_windows.json").read_text())
        cases = [
            ({"account": "*"}, "policy"),
            ({"source_ip": "0.0.0.0/0"}, "source"),
            ({"until": "2026-11-04T23:59:00+02:00"}, "24 hours"),
            ({"from": "2026-10-30T23:59:00+02:00"}, "24 hours"),
            ({"approved_by": ""}, "nonempty"),
            ({"ticket": None}, "nonempty"),
        ]
        for changes, error in cases:
            with self.subTest(changes=changes):
                custom = json.loads(json.dumps(raw))
                custom["windows"][0].update(changes)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "policy.json"
                    path.write_text(json.dumps(custom))
                    with self.assertRaisesRegex(ValueError, error):
                        load_approved_windows(path)

    def test_invalid_baseline_parameters_rejected(self):
        for args in [{"min_successes": True}, {"min_successes": 1},
                     {"min_days": 0}, {"hour_tolerance": 4},
                     {"lookback_days": 0}]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    build_profiles(self.training, cutoff=CUTOFF, **args)

    def test_invalid_behavior_parameters_rejected(self):
        for value in (-1, 1441, True):
            with self.subTest(cooldown=value):
                with self.assertRaisesRegex(ValueError, "cooldown"):
                    detect_behavior(self.events, self.profiles, cutoff=CUTOFF,
                                    cooldown_minutes=value)
        with self.assertRaisesRegex(ValueError, "same cutoff"):
            detect_behavior(self.events, self.profiles,
                            cutoff=CUTOFF + timedelta(days=1))

    def test_invalid_cutoff_rejected(self):
        for value in ("2026-10-30T12:00:00", "bad date", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "cutoff"):
                    parse_cutoff(value)

    def test_duplicate_id_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            detect_behavior([self.events[0], self.events[0]], self.profiles, cutoff=CUTOFF)


if __name__ == "__main__":
    unittest.main()
