"""Synthetic offline tests for Phase 3 observation draft creation."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import phase3_prepare_observations as draft  # noqa: E402


def summary():
    return {
        "comparison": "historical_offline_only",
        "dashboard_verified": False,
        "per_rule": {
            rule: {
                "manager_unique_alerts": 0,
                "indexer_unique_alerts": 0,
                "same_event_matches": 0,
            }
            for rule in draft.RULE_IDS
        },
    }


class ObservationDraftTests(unittest.TestCase):
    def test_zero_counts_are_unknown_never_missing(self):
        result = draft.build_observations(summary())
        self.assertEqual(len(result), 5)
        for item in result.values():
            self.assertEqual(item["manager"], "unknown")
            self.assertEqual(item["indexer"], "unknown")
            self.assertEqual(item["dashboard"], "unknown")
            self.assertFalse(item["same_event_verified"])
            self.assertTrue(item["inspection_attempted"])

    def test_matches_do_not_verify_dashboard(self):
        data = summary()
        data["per_rule"]["110130"] = {
            "manager_unique_alerts": 2,
            "indexer_unique_alerts": 2,
            "same_event_matches": 1,
        }
        result = draft.build_observations(data)
        self.assertEqual(result["110130"]["manager"], "found")
        self.assertEqual(result["110130"]["indexer"], "found")
        self.assertEqual(result["110130"]["dashboard"], "unknown")
        self.assertFalse(result["110130"]["same_event_verified"])

    def test_one_sided_export_does_not_imply_indexer_missing(self):
        data = summary()
        data["per_rule"]["110100"]["manager_unique_alerts"] = 1
        result = draft.build_observations(data)["110100"]
        self.assertEqual(result["manager"], "found")
        self.assertEqual(result["indexer"], "unknown")

    def test_reject_invalid_summary_and_missing_rule(self):
        data = summary()
        del data["per_rule"]["110100"]
        with self.assertRaises(ValueError):
            draft.build_observations(data)
        data = summary()
        data["dashboard_verified"] = True
        with self.assertRaises(ValueError):
            draft.build_observations(data)

    def test_reject_boolean_negative_fractional_and_excess_counts(self):
        for value in (True, -1, 1.25, "2", draft.MAX_COUNT + 1):
            with self.subTest(value=value):
                data = summary()
                data["per_rule"]["110100"]["manager_unique_alerts"] = value
                with self.assertRaises(ValueError):
                    draft.build_observations(data)

    def test_reject_impossible_matches(self):
        data = summary()
        data["per_rule"]["110100"]["same_event_matches"] = 1
        with self.assertRaises(ValueError):
            draft.build_observations(data)

    def test_output_matches_evidence_gate_schema(self):
        import phase3_evidence_gate as gate
        result = gate.assess(draft.build_observations(summary()))
        self.assertTrue(all(value == "inconclusive" for value in result.values()))

    def test_output_prevents_unproven_verification_with_counts(self):
        import phase3_evidence_gate as gate
        data = summary()
        data["per_rule"]["110130"].update(
            manager_unique_alerts=2, indexer_unique_alerts=1, same_event_matches=1
        )
        result = gate.assess(draft.build_observations(data))
        self.assertEqual(result["110130"], "partial")

    def test_symlinked_lab_root_is_rejected(self):
        """A symlink named .lab must not authorize access to tracked files."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "tracked"
            target.mkdir()
            redirect = root / ".lab"
            try:
                redirect.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with patch.object(draft, "PRIVATE_DIR", redirect):
                with self.assertRaisesRegex(ValueError, "symlink"):
                    draft.private_path(redirect / "evidence.json")

    def test_private_path_rejects_public_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / ".lab"
            private.mkdir()
            with patch.object(draft, "PRIVATE_DIR", private):
                self.assertEqual(draft.private_path(private / "summary.json"),
                                 (private / "summary.json").resolve())
                with self.assertRaises(ValueError):
                    draft.private_path(root / "public.json")


if __name__ == "__main__":
    unittest.main()
