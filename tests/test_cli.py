import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_hunter_lab.cli import main

SAMPLE = Path(__file__).resolve().parents[1] / 'samples' / 'synthetic_events.jsonl'


class CliTests(unittest.TestCase):
    def test_cli_creates_json_report(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'findings.json'
            args = ['threat_hunter_lab', 'hunt', str(SAMPLE), '--output', str(output)]
            with patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO()):
                main()
            data = json.loads(output.read_text())
            self.assertEqual(data['records_analyzed'], 11)
            self.assertEqual(data['findings_count'], 4)
            self.assertEqual(data['severity_breakdown'], {'high': 3, 'critical': 1})
            self.assertIn('Human review', data['disclaimer'])

    def test_cli_stdout_json(self):
        buffer = io.StringIO()
        args = ['threat_hunter_lab', 'hunt', str(SAMPLE)]
        with patch('sys.argv', args), contextlib.redirect_stdout(buffer):
            main()
        self.assertEqual(json.loads(buffer.getvalue())['findings_count'], 4)


if __name__ == '__main__':
    unittest.main()
