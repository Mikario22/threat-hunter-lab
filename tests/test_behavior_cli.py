"""CLI integration coverage for opt-in behavioral detection and policies."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_hunter_lab.cli import main

ROOT = Path(__file__).resolve().parents[1] / "samples"
CUTOFF = "2026-10-30T00:00:00+02:00"


def args_for(*extra):
    return [
        "threat_hunter_lab", "hunt", str(ROOT / "behavior_evaluation.jsonl"),
        "--baseline-events", str(ROOT / "behavior_training.jsonl"),
        "--baseline-cutoff", CUTOFF, *extra,
    ]


class BehaviorCliTests(unittest.TestCase):
    def invoke(self, args):
        output = io.StringIO()
        with patch("sys.argv", args), contextlib.redirect_stdout(output):
            main()
        return json.loads(output.getvalue())

    def test_behavioral_cli_without_policy_yields_three_anomalies(self):
        report = self.invoke(args_for())
        self.assertEqual(report["records_analyzed"], 7)
        self.assertEqual(report["findings_count"], 3)
        self.assertEqual(report["severity_breakdown"], {"high": 3})
        self.assertEqual(report["behavior"]["training_records"], 17)
        self.assertEqual(report["behavior"]["approved_policy_windows"], 0)
        self.assertEqual(len(report["behavior"]["trained_profiles"]), 2)

    def test_approved_windows_remove_only_one_behaviour_alert(self):
        report = self.invoke(args_for(
            "--approved-windows", str(ROOT / "approved_windows.json")
        ))
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual(report["behavior"]["approved_policy_windows"], 1)
        decisions = {item["event_id"]: item for item in report["behavior"]["decisions"]}
        self.assertEqual(decisions["BEHAV-004"]["decision"], "suppressed_by_policy")
        self.assertEqual(decisions["BEHAV-002"]["decision"], "alert")

    def test_v1_hunt_still_produces_four_finding_sample(self):
        report = self.invoke([
            "threat_hunter_lab", "hunt", str(ROOT / "synthetic_events.jsonl")
        ])
        self.assertEqual(report["findings_count"], 4)
        self.assertNotIn("behavior", report)

    def test_cli_output_contains_json_and_no_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "report.json"
            arguments = args_for("--approved-windows", str(ROOT / "approved_windows.json"),
                                 "--output", str(destination))
            with patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                main()
            report = json.loads(destination.read_text())
            self.assertEqual(len(report["findings"]), 2)
            self.assertIn("Human review", report["disclaimer"])

    def test_baseline_and_cutoff_must_be_supplied_together(self):
        for additions in [
            ("--baseline-events", str(ROOT / "behavior_training.jsonl")),
            ("--baseline-cutoff", CUTOFF),
            ("--approved-windows", str(ROOT / "approved_windows.json")),
        ]:
            with self.subTest(additions=additions):
                args = ["threat_hunter_lab", "hunt",
                        str(ROOT / "behavior_evaluation.jsonl"), *additions]
                with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main()
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
