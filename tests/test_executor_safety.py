"""Offline regression tests for inventory validation and outcome classification.

Run: python -m unittest discover -s tests -p 'test_executor_safety.py' -v
No network, VM, secrets, or third-party packages required.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lab_run", ROOT / "scripts" / "lab" / "run.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


def inventory(timeout=60):
    return {
        "isolated_lab": True,
        "manager": {
            "ssh_target": "lab@manager.example",
            "container": "wazuh-manager",
            "python": "/var/ossec/framework/python/bin/python3",
            "agent_id": "004",
        },
        "windows": {
            "computer_name": "winlab.example",
            "expected_hostname": "WINLAB",
            "authentication": "Negotiate",
            "use_ssl": True,
            "credential_path": "",
        },
        "alert_timeout_seconds": timeout,
    }


class InventorySafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "config.json"

    def load(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return lab.load_config(self.path)

    def test_valid_inventory(self):
        self.assertEqual(self.load(inventory())["manager"]["agent_id"], "004")

    def test_timeout_boundaries(self):
        for value in (5, 60, 300):
            with self.subTest(value=value):
                self.assertEqual(self.load(inventory(value))["alert_timeout_seconds"], value)

    def test_malformed_timeout_rejected_before_transport(self):
        for value in (None, True, False, "60", 60.5, -1, 4, 301, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.load(inventory(value))

    def test_reject_non_isolated_lab(self):
        data = inventory()
        data["isolated_lab"] = False
        with self.assertRaises(ValueError):
            self.load(data)

    def test_reject_placeholder(self):
        data = inventory()
        data["manager"]["ssh_target"] = "REPLACE_HOST"
        with self.assertRaises(ValueError):
            self.load(data)


class OutcomeSafetyTests(unittest.TestCase):
    def test_detected_requires_matching_rule_and_level(self):
        endpoint = {"ok": True, "cleanup": "verified", "local_events": 1}
        evidence = {"ok": True, "counts": {"110130": 1}, "levels": {"110130": 12}}
        self.assertEqual(lab.outcome(endpoint, evidence, 110130, 12), "detected")
        self.assertEqual(lab.outcome(endpoint, evidence, 110130, 10), "severity_mismatch")
        self.assertEqual(lab.outcome(endpoint, evidence, 110140, 12), "alert_missing")

    def test_cleanup_and_telemetry_are_mandatory(self):
        evidence = {"ok": True, "counts": {"110130": 1}, "levels": {"110130": 12}}
        endpoint = {"ok": True, "cleanup": "unknown", "local_events": 1}
        self.assertEqual(lab.outcome(endpoint, evidence, 110130, 12), "cleanup_unverified")
        endpoint["cleanup"] = "verified"
        endpoint["local_events"] = 0
        self.assertEqual(lab.outcome(endpoint, evidence, 110130, 12), "telemetry_missing")


if __name__ == "__main__":
    unittest.main()
