"""Offline tests: no live Wazuh, network, credentials or external processes."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts/lab/archive_live_vs_logtest.py"
spec = importlib.util.spec_from_file_location("archive_live_diff", PATH)
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)


def event(name, marker, *, rule=None, event_id="1"):
    image = {"powershell": "powershell.exe", "rundll32": "rundll32.exe", "schtasks": "schtasks.exe"}[name]
    item = {
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {
            "system": {"eventID": event_id, "providerName": "Microsoft-Windows-Sysmon"},
            "eventdata": {"image": "C:\\Windows\\System32\\" + image},
        }},
        "full_log": '{"win":{}}',
    }
    if rule is not None:
        item["rule"] = {"id": rule}
    return json.dumps(item)[:-1] + ',"marker":"' + auditor.marker_value(name, marker) + '"}'


class ArchiveAuditorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.markers = {
            "powershell": "DE-1111111111111111",
            "rundll32": "DE-2222222222222222",
            "schtasks": "DE-3333333333333333",
        }
        self.path = self.base / "archives.json"
        self.marker_path = self.base / "markers.json"
        self.marker_path.write_text(json.dumps(self.markers), encoding="utf-8")
        os.chmod(self.marker_path, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX mode 0600 cannot be verified via Windows ACLs")
    def test_private_markers_are_accepted(self):
        self.assertEqual(auditor.markers_from_file(self.marker_path), self.markers)

    @unittest.skipIf(os.name == "nt", "POSIX mode 0644 cannot be verified via Windows ACLs")
    def test_reject_world_readable_marker_file(self):
        os.chmod(self.marker_path, 0o644)
        with self.assertRaises(ValueError):
            auditor.markers_from_file(self.marker_path)

    def test_reject_bad_marker_schema(self):
        with self.assertRaises(ValueError):
            auditor.validate_markers({"powershell": "DE-1111111111111111"})

    @unittest.skipUnless(os.name == "nt", "Windows-specific fail-closed test")
    def test_windows_disk_marker_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "privacy cannot be verified"):
            auditor.markers_from_file(self.marker_path)

    def test_archive_filter_only_sysmon_process_event(self):
        self.path.write_text("\n".join([
            event("powershell", self.markers["powershell"], rule="92057"),
            event("rundll32", self.markers["rundll32"]),
            event("schtasks", self.markers["schtasks"], event_id="11"),
            event("schtasks", self.markers["schtasks"]),
        ]) + "\n")
        found = auditor.archived_events(self.path, self.markers)
        self.assertEqual(found["powershell"]["marker_events"], 1)
        self.assertEqual(len(found["powershell"]["event1"]), 1)
        self.assertEqual(found["schtasks"]["marker_events"], 2)
        self.assertEqual(len(found["schtasks"]["event1"]), 1)

    def test_comparison_marks_offline_only_as_unverified(self):
        self.path.write_text("\n".join([
            event("powershell", self.markers["powershell"], rule="92057"),
            event("rundll32", self.markers["rundll32"]),
            event("schtasks", self.markers["schtasks"]),
        ]) + "\n")
        offline = iter([("110100", "json", True), ("110110", "json", True), ("110120", "json", True)])
        with patch.object(auditor, "isolated_logtest", side_effect=lambda *_: next(offline)):
            report = auditor.assess(self.path, self.markers, "mocked")
        for name in self.markers:
            item = report["per_scenario"][name]
            self.assertEqual(item["live_custom_rule_event_count"], 0)
            self.assertEqual(item["offline_expected_rule_count"], 1)
            self.assertEqual(item["live_vs_offline_discrepancy_count"], 1)
            self.assertEqual(item["decoder_difference_count"], 1)
            self.assertEqual(item["status"], "received_but_custom_rule_absent")
        self.assertTrue(report["requires_dashboard_confirmation"])

    def test_empty_archive_is_not_success(self):
        self.path.write_text("")
        with patch.object(auditor, "isolated_logtest") as mock:
            report = auditor.assess(self.path, self.markers, "unused")
            mock.assert_not_called()
        self.assertTrue(all(item["status"] == "no_matching_sysmon_process_event"
                            for item in report["per_scenario"].values()))

    def test_invalid_markers_are_rejected_without_leaking(self):
        self.markers["rundll32"] = "TEST_SECRET"
        with self.assertRaises(ValueError) as err:
            auditor.validate_markers(self.markers)
        self.assertNotIn("TEST_SECRET", str(err.exception))


if __name__ == "__main__":
    unittest.main()
