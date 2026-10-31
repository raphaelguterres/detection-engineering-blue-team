"""Offline tests with synthetic Wazuh-like events; never access a VM."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "offline_alert_comparison", ROOT / "scripts/phase3_compare_alert_exports.py"
)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)

START = "2026-10-30T00:00:00Z"
END = "2026-10-31T00:00:00Z"


def event(alert_id="sample-01", rule="110130", agent="004",
          timestamp="2026-10-30T20:00:00Z"):
    return {"id": alert_id, "timestamp": timestamp,
            "rule": {"id": rule}, "agent": {"id": agent}}


class OfflineAlertCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manager = self.root / "manager.jsonl"
        self.indexer = self.root / "indexer.jsonl"

    def write(self, path, records):
        path.write_text("".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8")

    def test_exact_same_alert_matches(self):
        self.write(self.manager, [event()])
        self.write(self.indexer, [{"_source": event(timestamp="2026-10-30T20:00:00+00:00")}])
        result = worker.compare(self.manager, self.indexer, START, END)
        self.assertEqual(result["per_rule"]["110130"]["same_event_matches"], 1)
        self.assertFalse(result["dashboard_verified"])

    def test_rule_agent_and_timestamp_must_match(self):
        self.write(self.manager, [event()])
        self.write(self.indexer, [
            {"_source": event(rule="110140")},
            {"_source": event(agent="005")},
            {"_source": event(timestamp="2026-10-30T20:00:01Z")},
        ])
        result = worker.compare(self.manager, self.indexer, START, END)
        self.assertEqual(result["per_rule"]["110130"]["same_event_matches"], 0)

    def test_deduplicates_and_excludes_unrelated_rules(self):
        self.write(self.manager, [event(), event(), event(rule="999999")])
        self.write(self.indexer, [event()])
        result = worker.compare(self.manager, self.indexer, START, END)
        self.assertEqual(result["per_rule"]["110130"]["manager_unique_alerts"], 1)
        self.assertEqual(len(result["per_rule"]), 5)
        self.assertNotIn("sample-01", json.dumps(result))

    def test_historical_window_and_timezone(self):
        self.write(self.manager, [event(timestamp="2026-10-30T18:00:00-02:00")])
        self.write(self.indexer, [event(timestamp="2026-10-30T20:00:00Z")])
        result = worker.compare(self.manager, self.indexer, START, END)
        self.assertEqual(result["per_rule"]["110130"]["same_event_matches"], 1)
        outside = worker.compare(self.manager, self.indexer, "2026-10-31T01:00:00Z",
                                 "2026-10-31T02:00:00Z")
        self.assertEqual(outside["per_rule"]["110130"]["same_event_matches"], 0)

    def test_invalid_and_missing_identity_fail_closed(self):
        self.write(self.manager, [event(alert_id="")])
        self.write(self.indexer, [event()])
        with self.assertRaises(ValueError):
            worker.compare(self.manager, self.indexer, START, END)
        self.manager.write_text("invalid JSON\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            worker.compare(self.manager, self.indexer, START, END)

    def test_same_file_cannot_supply_both_stages(self):
        """Prevent false matches from reusing one export in both roles."""
        self.write(self.manager, [event()])
        with self.assertRaisesRegex(ValueError, "distinct files"):
            worker.compare(self.manager, self.manager, START, END)

    def test_hardlinked_export_cannot_supply_both_stages(self):
        """Distinct path strings do not guarantee independent export files."""
        self.write(self.manager, [event()])
        alias = self.root / "alias-manager.jsonl"
        alias.hardlink_to(self.manager)
        with self.assertRaisesRegex(ValueError, "distinct files"):
            worker.compare(self.manager, alias, START, END)

    def test_invalid_time_window_rejected(self):
        self.write(self.manager, [])
        self.write(self.indexer, [])
        with self.assertRaises(ValueError):
            worker.compare(self.manager, self.indexer, END, START)
        with self.assertRaises(ValueError):
            worker.compare(self.manager, self.indexer, "2026-10-30T00:00:00", END)

    def test_symlinked_lab_root_refused(self):
        """Read-only comparator cannot accept private exports via a linked root."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tracked = root / "tracked"
            tracked.mkdir()
            redirect = root / ".lab"
            try:
                redirect.symlink_to(tracked, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            (tracked / "alert.jsonl").write_text("", encoding="utf-8")
            with patch.object(worker, "PRIVATE_DIR", redirect):
                with self.assertRaisesRegex(ValueError, "link"):
                    worker.local_export(redirect / "alert.jsonl")

    def test_cli_guard_requires_private_lab_path(self):
        with patch.object(worker, "PRIVATE_DIR", self.root / ".lab"):
            self.manager.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                worker.local_export(self.manager)
            private_file = self.root / ".lab" / "events.jsonl"
            private_file.parent.mkdir()
            private_file.write_text("", encoding="utf-8")
            self.assertEqual(worker.local_export(private_file), private_file.resolve())


if __name__ == "__main__":
    unittest.main()
