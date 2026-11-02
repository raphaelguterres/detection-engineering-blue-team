"""Offline unit coverage for Discover CSV identity gate; all data are synthetic."""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import phase3_compare_alert_exports as core
import phase3_compare_discover_export as verifier

TIMES = [
    "2026-11-02T00:22:15.606+0000",
    "2026-11-01T23:19:45.738+0000",
    "2026-11-01T23:19:52.407+0000",
    "2026-11-01T21:10:26.157+0000",
    "2026-11-01T21:11:05.931+0000",
    "2026-11-01T21:11:05.997+0000",
]
RULES = ["110100", "110110", "110120", "110130", "110140", "110140"]


class DiscoverGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / ".lab"
        self.private.mkdir()
        self.patcher = mock.patch.object(core, "PRIVATE_DIR", self.private)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.manager = self.private / "manager.jsonl"
        self.indexer = self.private / "indexer.jsonl"
        self.discover = self.private / "discover.csv"
        self.events = [
            {"id": f"synthetic-{i}", "rule": {"id": rule},
             "agent": {"id": "004"}, "timestamp": ts}
            for i, (rule, ts) in enumerate(zip(RULES, TIMES))
        ]
        self.write_jsonl(self.manager, self.events)
        self.write_jsonl(self.indexer, [
            {"_source": event} for event in self.events
        ])
        self.write_discover(self.events)

    def write_jsonl(self, path, events):
        path.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )

    def write_discover(self, events):
        with self.discover.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f, fieldnames=["timestamp", "agent.id", "id", "rule.id"]
            )
            writer.writeheader()
            for event in events:
                writer.writerow({
                    "timestamp": event["timestamp"],
                    "agent.id": event["agent"]["id"],
                    "rule.id": event["rule"]["id"],
                    "id": event["id"],
                })

    def run_gate(self):
        return verifier.compare_three(
            self.manager, self.indexer, self.discover,
            "2026-11-01T20:00:00Z", "2026-11-02T00:40:00Z",
        )

    def test_exact_six_is_candidate_but_not_automatically_verified(self):
        result = self.run_gate()
        self.assertEqual(result["manager_indexer_exact_matches"], 6)
        self.assertEqual(result["discover_exact_matches"], 6)
        self.assertFalse(result["operator_discover_provenance_verified"])
        self.assertEqual(
            result["status"], "SIX_EXACT_MATCHES_REQUIRES_OPERATOR_PROVENANCE_REVIEW"
        )
        self.assertEqual(result["per_rule"]["110140"]["all_three_exact_matches"], 2)

    def test_exact_timestamp_with_different_offset_matches(self):
        events = [dict(x) for x in self.events]
        events[0]["timestamp"] = "2026-11-01T16:22:15.606-0800"
        self.write_discover(events)
        self.assertEqual(self.run_gate()["discover_exact_matches"], 6)

    def test_wrong_original_id_is_rejected(self):
        events = [dict(x) for x in self.events]
        events[0]["id"] = "different"
        self.write_discover(events)
        self.assertEqual(self.run_gate()["discover_exact_matches"], 5)
        self.assertEqual(self.run_gate()["status"], "NOT_ACCEPTED_INCOMPLETE_OR_MISMATCH")

    def test_missing_document_is_rejected(self):
        self.write_discover(self.events[:-1])
        self.assertEqual(self.run_gate()["discover_export_rows"], 5)
        self.assertEqual(self.run_gate()["status"], "NOT_ACCEPTED_INCOMPLETE_OR_MISMATCH")

    def test_duplicates_are_rejected(self):
        self.write_discover(self.events + self.events[-1:])
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_naive_timestamp_is_rejected(self):
        events = [dict(x) for x in self.events]
        events[0]["timestamp"] = "2026-11-02T00:22:15.606"
        self.write_discover(events)
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_required_headers(self):
        self.discover.write_text("id,rule.id,agent.id\none,110100,004\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_reject_exports_outside_private_dir(self):
        outside = Path(self.temp.name) / "outside.csv"
        outside.write_text("id,rule.id,agent.id,timestamp\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            verifier.compare_three(self.manager, self.indexer, outside,
                "2026-11-01T20:00:00Z", "2026-11-02T00:40:00Z")


if __name__ == "__main__":
    unittest.main()
