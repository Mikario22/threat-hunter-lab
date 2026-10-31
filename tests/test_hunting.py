import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threat_hunter_lab.detection import hunt
from threat_hunter_lab.ingest import parse_events
from threat_hunter_lab.models import Event

SAMPLE = Path(__file__).resolve().parents[1] / 'samples' / 'synthetic_events.jsonl'


def item(index, minute, *, acc='user', ip='192.0.2.1', typ='login', outcome='failed', privileged=False, reference=''):
    return Event(f'test-{index}', datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minute), typ, acc, ip, 'host', outcome, privileged, reference)


class HuntingTests(unittest.TestCase):
    def test_sample_has_four_findings(self):
        events = parse_events(SAMPLE)
        self.assertEqual(len(events), 11)
        result = hunt(events)
        self.assertEqual(len(result), 4)
        self.assertEqual({f.rule for f in result}, {
            'POTENTIAL_PASSWORD_SPRAY', 'FAILURE_TO_SUCCESS',
            'PRIVILEGE_CHANGE_NO_REFERENCE', 'CREDENTIAL_TO_PRIVILEGE_CHAIN'
        })

    def test_mitre_mappings_are_explicit(self):
        findings = {f.rule: f for f in hunt(parse_events(SAMPLE))}
        self.assertEqual(findings['POTENTIAL_PASSWORD_SPRAY'].technique_ids, ('T1110.003',))
        self.assertEqual(findings['FAILURE_TO_SUCCESS'].technique_ids, ('T1110.001',))
        self.assertEqual(findings['PRIVILEGE_CHANGE_NO_REFERENCE'].technique_ids, ('T1098',))
        self.assertEqual(findings['CREDENTIAL_TO_PRIVILEGE_CHAIN'].technique_ids, ('T1110.001', 'T1098'))

    def test_spray_requires_distinct_accounts(self):
        events = [item(i, i, acc='same') for i in range(5)]
        self.assertFalse(any(f.rule == 'POTENTIAL_PASSWORD_SPRAY' for f in hunt(events)))

    def test_spray_correlates_source_not_disparate_sources(self):
        events = [item(i, i, acc=f'u{i}', ip=f'192.0.2.{i+1}') for i in range(4)]
        self.assertEqual(hunt(events), [])

    def test_spray_window_expires(self):
        events = [item(i, i * 11, acc=f'u{i}') for i in range(4)]
        self.assertEqual(hunt(events), [])

    def test_spray_emits_only_once_within_active_window(self):
        events = [item(i, i, acc=f'u{i}') for i in range(7)]
        self.assertEqual(len([f for f in hunt(events) if f.rule == 'POTENTIAL_PASSWORD_SPRAY']), 1)

    def test_failure_then_success_requires_matching_source(self):
        events = [item(i, i) for i in range(3)]
        events.append(item(3, 4, ip='192.0.2.2', outcome='success'))
        self.assertFalse(any(f.rule == 'FAILURE_TO_SUCCESS' for f in hunt(events)))

    def test_failure_then_success_detected(self):
        events = [item(i, i) for i in range(3)] + [item(3, 4, outcome='success')]
        match = [f for f in hunt(events) if f.rule == 'FAILURE_TO_SUCCESS']
        self.assertEqual(len(match), 1)
        self.assertEqual(len(match[0].evidence_ids), 4)

    def test_success_after_expired_failures_not_alerted(self):
        events = [item(i, i) for i in range(3)] + [item(3, 21, outcome='success')]
        self.assertEqual(hunt(events), [])

    def test_role_change_without_reference_detected(self):
        findings = hunt([item(1, 1, typ='role_change', outcome='success', privileged=True)])
        self.assertEqual([f.rule for f in findings], ['PRIVILEGE_CHANGE_NO_REFERENCE'])

    def test_role_change_with_reference_not_detected(self):
        findings = hunt([item(1, 1, typ='role_change', outcome='success', privileged=True, reference='CHG-001')])
        self.assertEqual(findings, [])

    def test_failed_role_change_not_alerted(self):
        self.assertEqual(hunt([item(1, 1, typ='role_change', privileged=True)]), [])

    def test_chain_requires_same_source_and_account(self):
        events = [item(i, i) for i in range(3)] + [item(3, 3, outcome='success'),
                 item(4, 4, typ='role_change', outcome='success', privileged=True, ip='192.0.2.2')]
        self.assertFalse(any(f.rule == 'CREDENTIAL_TO_PRIVILEGE_CHAIN' for f in hunt(events)))

    def test_chain_window_limit(self):
        events = [item(i, i) for i in range(3)] + [item(3, 3, outcome='success'),
                 item(4, 35, typ='role_change', outcome='success', privileged=True)]
        self.assertFalse(any(f.rule == 'CREDENTIAL_TO_PRIVILEGE_CHAIN' for f in hunt(events)))

    def test_out_of_order_deterministic_findings(self):
        events = parse_events(SAMPLE)
        self.assertEqual(hunt(events), hunt(list(reversed(events))))

    def test_ids_stable_across_reordered_inputs(self):
        events = parse_events(SAMPLE)
        a = {f.finding_id for f in hunt(events)}
        b = {f.finding_id for f in hunt(list(reversed(events)))}
        self.assertEqual(a, b)

    def test_evidence_ids_all_trace_to_input(self):
        events = parse_events(SAMPLE)
        ids = {e.event_id for e in events}
        self.assertTrue(all(set(f.evidence_ids) <= ids for f in hunt(events)))

    def test_params_enforced(self):
        for key, value in [('spray_accounts', 1), ('spray_accounts', True),
                           ('brute_failures', 0), ('window_minutes', 0),
                           ('chain_window_minutes', 1441)]:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, key):
                    hunt([], **{key: value})

    def test_duplicate_event_ids_rejected(self):
        events = parse_events(SAMPLE)
        with self.assertRaisesRegex(ValueError, 'unique'):
            hunt([events[0], events[0]])

    def test_naive_timestamp_rejected(self):
        events = parse_events(SAMPLE)
        with self.assertRaisesRegex(ValueError, 'timezone-aware'):
            hunt([replace(events[0], timestamp=datetime(2026, 10, 30, 10))])


class ParserTests(unittest.TestCase):
    def write(self, records):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / 'events.jsonl'
        path.write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')
        return path

    def test_sample_parses_and_sorts(self):
        events = parse_events(SAMPLE)
        self.assertTrue(all(events[i].timestamp <= events[i+1].timestamp for i in range(len(events)-1)))

    def test_invalid_schema_rejected(self):
        row = json.loads(SAMPLE.read_text().splitlines()[0])
        row['run_command'] = 'echo malicious'
        with self.assertRaisesRegex(ValueError, 'invalid field set'):
            parse_events(self.write([row]))

    def test_duplicate_ids_rejected(self):
        row = json.loads(SAMPLE.read_text().splitlines()[0])
        with self.assertRaisesRegex(ValueError, 'duplicate event_id'):
            parse_events(self.write([row, row]))

    def test_invalid_timezone_rejected(self):
        row = json.loads(SAMPLE.read_text().splitlines()[0])
        row['timestamp'] = '2026-10-30T10:00:00'
        with self.assertRaisesRegex(ValueError, 'UTC offset'):
            parse_events(self.write([row]))

    def test_bad_source_ip_rejected(self):
        row = json.loads(SAMPLE.read_text().splitlines()[0])
        row['source_ip'] = 'not-an-ip'
        with self.assertRaises(ValueError):
            parse_events(self.write([row]))

    def test_boolean_privileged_enforced(self):
        row = json.loads(SAMPLE.read_text().splitlines()[0])
        row['privileged'] = 'true'
        with self.assertRaisesRegex(ValueError, 'boolean'):
            parse_events(self.write([row]))

    def test_read_limit_enforced(self):
        with self.assertRaisesRegex(ValueError, 'event limit exceeded'):
            parse_events(SAMPLE, max_events=2)


if __name__ == '__main__':
    unittest.main()
