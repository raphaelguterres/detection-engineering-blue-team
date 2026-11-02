"""Synthetic-only regression tests for the read-only Manager archive diagnostic."""
import gzip
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "manager_archive_audit", ROOT / "scripts/phase3_manager_archive_audit.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
START = datetime(2026, 11, 1, 20, tzinfo=timezone.utc)
END = datetime(2026, 11, 2, 0, 40, tzinfo=timezone.utc)


def item(rule, timestamp="2026-11-01T23:19:52.407+0000"):
    return {"rule": {"id": rule}, "timestamp": timestamp,
            "id": "PRIVATE-ALERT-ID", "agent": {"id": "PRIVATE-AGENT-ID"},
            "data": {"commandLine": "PRIVATE-COMMAND"}}


class ArchiveAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_uncompressed_matching_and_no_raw_identifiers(self):
        p = self.dir / "ossec-alerts-02.json"
        p.write_text("\n".join(map(json.dumps, [
            item("110100"), item("110120", "2026-11-02T00:22:15Z"),
            item("110140", "2026-11-02T01:00:00Z"),
            item("92057")])) + "\n", encoding="utf-8")
        r = worker.audit_file(p, START, END)
        self.assertEqual(r["custom_rules_in_window"]["110100"], 1)
        self.assertEqual(r["custom_rules_in_window"]["110120"], 1)
        self.assertEqual(r["custom_rules_in_window"]["110140"], 0)
        self.assertEqual(r["custom_rules_without_time_filter"]["110140"], 1)
        output = json.dumps(r)
        for secret in ("PRIVATE-ALERT-ID", "PRIVATE-AGENT-ID", "PRIVATE-COMMAND"):
            self.assertNotIn(secret, output)

    def test_gzip_file_and_timezone_normalization(self):
        p = self.dir / "ossec-alerts-01.json.gz"
        with gzip.open(p, "wt", encoding="utf-8") as f:
            f.write(json.dumps(item("110110", "2026-11-01T15:19:45-08:00")) + "\n")
        r = worker.audit_file(p, START, END)
        self.assertEqual(r["custom_rules_in_window"]["110110"], 1)

    def test_invalid_json_and_invalid_target_time_reported_separately(self):
        p = self.dir / "alerts.json"
        p.write_text('invalid\n' + json.dumps(item("110100", "not-a-date"))
                     + "\n" + json.dumps(item("5502")) + "\n", encoding="utf-8")
        r = worker.audit_file(p, START, END)
        self.assertEqual(r["invalid_json_or_object"], 1)
        self.assertEqual(r["missing_or_invalid_timestamp_for_target_rule"], 1)
        self.assertEqual(r["custom_rules_without_time_filter"]["110100"], 1)
        self.assertEqual(r["custom_rules_in_window"]["110100"], 0)

    def test_refuse_missing_file(self):
        with self.assertRaises(ValueError):
            worker.audit_file(self.dir / "does-not-exist.json", START, END)

    def test_refuse_naive_time(self):
        with self.assertRaises(ValueError):
            worker.parse_utc("2026-11-01T20:00:00")


if __name__ == "__main__":
    unittest.main()
