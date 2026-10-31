"""Additional offline transport failure-path coverage, no VM or network access."""
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab_run_transport", ROOT / "scripts/lab/run.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class TransportContractTests(unittest.TestCase):
    def test_successful_json_object(self):
        completed = SimpleNamespace(stdout='{"ok":true,"counts":{"110130":1}}', stderr='', returncode=0)
        with patch.object(runner.subprocess, "run", return_value=completed) as mocked:
            result = runner.run_json(["mock-command"])
        self.assertTrue(result["ok"])
        mocked.assert_called_once()

    def test_nonzero_exit_cannot_claim_success(self):
        completed = SimpleNamespace(stdout='{"ok":true}', stderr='secret', returncode=3)
        with patch.object(runner.subprocess, "run", return_value=completed):
            result = runner.run_json(["mock-command"])
        self.assertEqual(result["error"], "TRANSPORT_NONZERO_EXIT")
        self.assertNotIn("secret", str(result))

    def test_invalid_output_never_exposes_stderr(self):
        for stdout in ("not JSON", '["array"]', ""):
            with self.subTest(stdout=stdout):
                completed = SimpleNamespace(stdout=stdout, stderr="PRIVATE-DETAIL", returncode=1)
                with patch.object(runner.subprocess, "run", return_value=completed):
                    result = runner.run_json(["mock-command"])
                self.assertFalse(result["ok"])
                self.assertNotIn("PRIVATE-DETAIL", json.dumps(result))

    def test_os_error_classified(self):
        with patch.object(runner.subprocess, "run", side_effect=OSError("PRIVATE-PATH")):
            result = runner.run_json(["mock-command"])
        self.assertEqual(result["error"], "TRANSPORT_UNAVAILABLE")
        self.assertNotIn("PRIVATE-PATH", str(result))

    def test_timeout_state_unknown(self):
        with patch.object(runner.subprocess, "run", side_effect=subprocess.TimeoutExpired("mock", 1)):
            result = runner.run_json(["mock-command"])
        self.assertEqual(result["error"], "REMOTE_TIMEOUT_STATE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
