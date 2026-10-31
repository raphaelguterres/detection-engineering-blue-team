"""Pure offline tests for conservative Phase 3 evidence classification."""
import importlib.util
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts" / "phase3_evidence_gate.py"
spec = importlib.util.spec_from_file_location("phase3_gate", path)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def sample():
    return {r: {"manager": "unknown", "indexer": "unknown", "dashboard": "unknown",
                "same_event_verified": False} for r in gate.RULE_IDS}


class EvidenceGateTests(unittest.TestCase):
    def test_unknown_is_inconclusive_not_failed(self):
        self.assertTrue(all(v == "inconclusive" for v in gate.assess(sample()).values()))

    def test_stage_counts_alone_never_mark_verified(self):
        x = sample()
        x["110130"].update(manager="found", indexer="found", dashboard="found")
        self.assertEqual(gate.assess(x)["110130"], "partial")

    def test_correlated_event_is_verified(self):
        x = sample()
        x["110130"].update(manager="found", indexer="found", dashboard="found",
                           same_event_verified=True)
        self.assertEqual(gate.assess(x)["110130"], "verified")

    def test_missing_downstream_does_not_claim_success(self):
        x = sample()
        x["110140"].update(manager="found", indexer="missing", dashboard="missing")
        self.assertEqual(gate.assess(x)["110140"], "partial")

    def test_reject_partial_schema_and_invalid_status(self):
        x = sample()
        del x["110100"]
        with self.assertRaises(ValueError):
            gate.assess(x)
        x = sample()
        x["110100"]["manager"] = "success"
        with self.assertRaises(ValueError):
            gate.assess(x)

    def test_reject_truthy_string_verification(self):
        x = sample()
        x["110100"]["same_event_verified"] = "true"
        with self.assertRaises(ValueError):
            gate.assess(x)


if __name__ == "__main__":
    unittest.main()
