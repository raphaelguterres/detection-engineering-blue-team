"""Offline detection regression for the three live EventChannel rule-chain fixes.

Pure stdlib unit tests: these validate XML, fixture field predicates and
isolated replay routing. They DO NOT claim operational Wazuh alerts.
"""
import importlib.util
import json
import re
import unittest
import xml.etree.ElementTree as ET
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {
    "110100": ("110100-powershell-encoded-command.xml", "powershell-encoded-command.json"),
    "110110": ("110110-rundll32-user-writable-path.xml", "rundll32-user-writable-path.json"),
    "110120": ("110120-schtasks-create.xml", "schtasks-create.json"),
}


def load_manager_worker():
    path = ROOT / "scripts/lab/manager-worker.py"
    spec = importlib.util.spec_from_file_location("phase3_chain_manager", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def matching_predicates(rule, event):
    for field in rule.findall("field"):
        if field.get("name") not in event:
            return False
        if not re.search((field.text or ""), str(event[field.get("name")])):
            return False
    return True


class RuleChainTests(unittest.TestCase):
    def test_three_rules_anchor_to_live_sysmon_hierarchy(self):
        for rid, (filename, _) in SCENARIOS.items():
            with self.subTest(rule_id=rid):
                root = ET.parse(ROOT / "rules/windows" / filename).getroot()
                rules = root.findall("rule")
                self.assertEqual(len(rules), 1)
                rule = rules[0]
                self.assertEqual(rule.attrib["id"], rid)
                if rid == "110100":
                    self.assertIsNone(rule.find("if_group"))
                    self.assertEqual(rule.findtext("if_sid").replace(" ", ""), "61603,92057")
                else:
                    self.assertEqual(rule.findtext("if_group"), "sysmon_event1")
                    self.assertIsNone(rule.find("if_sid"))
                self.assertIn("win.system.providerName", [f.get("name") for f in rule.findall("field")])
                self.assertIn("win.system.eventID", [f.get("name") for f in rule.findall("field")])
                self.assertTrue(rule.findtext("mitre/id").startswith("T"))
                self.assertGreater(int(rule.attrib["level"]), 0)

    def test_positive_and_benign_fixtures_keep_the_expected_predicates(self):
        for rid, (xml_name, json_name) in SCENARIOS.items():
            rule = ET.parse(ROOT / "rules/windows" / xml_name).getroot().find("rule")
            fixture = json.loads((ROOT / "tests/fixtures" / json_name).read_text(encoding="utf-8"))
            self.assertEqual(str(fixture["rule_id"]), rid)
            self.assertEqual({case["expected_alert"] for case in fixture["cases"]}, {True, False})
            for case in fixture["cases"]:
                with self.subTest(rule_id=rid, case=case["name"]):
                    self.assertEqual(matching_predicates(rule, case["event"]), case["expected_alert"])

    def test_encoded_powershell_positive_covers_both_parent_processes(self):
        fixture = json.loads((ROOT / "tests/fixtures/powershell-encoded-command.json").read_text(encoding="utf-8"))
        parents = {
            case["event"].get("win.eventdata.parentImage", "").lower().split("\\")[-1]
            for case in fixture["cases"]
            if case["expected_alert"]
        }
        self.assertEqual(parents, {"cmd.exe", "powershell.exe"})

    def test_rules_cannot_match_wrong_provider_or_event_id(self):
        for rid, (xml_name, json_name) in SCENARIOS.items():
            rule = ET.parse(ROOT / "rules/windows" / xml_name).getroot().find("rule")
            fixture = json.loads((ROOT / "tests/fixtures" / json_name).read_text(encoding="utf-8"))
            positive = next(case["event"] for case in fixture["cases"] if case["expected_alert"])
            for field, value in (
                ("win.system.providerName", "Microsoft-Windows-Security-Auditing"),
                ("win.system.eventID", "11"),
            ):
                with self.subTest(rule_id=rid, field=field):
                    payload = {**positive, field: value}
                    self.assertFalse(matching_predicates(rule, payload))

    def test_previously_validated_other_two_rules_stay_unchanged(self):
        rules = ROOT / "rules/windows"
        runkey = ET.parse(rules / "110130-run-key-modification.xml").getroot().find("rule")
        account = ET.parse(rules / "110140-net-user-add.xml").getroot().find("rule")
        self.assertEqual(runkey.findtext("if_sid"), "61615, 92300")
        self.assertEqual(account.findtext("if_group"), "sysmon_event1")

    def test_all_three_route_through_disposable_windows_rule_tree(self):
        worker = load_manager_worker()
        request = {"fixtures": [
            {"rule_id": int(rid), "cases": []} for rid in SCENARIOS
        ]}
        with patch.object(worker, "windows_replay_config", return_value=nullcontext(Path("test-only.xml"))) as context, \
             patch.object(worker, "replay_cases", return_value={"ok": True, "cases": []}) as replay:
            result = worker.replay(request)
        self.assertTrue(result["ok"])
        context.assert_called_once_with()
        replay.assert_called_once_with(request, Path("test-only.xml"))

    def test_replay_uses_legacy_tool_with_isolated_config(self):
        worker = load_manager_worker()
        fixture = [{"rule_id": 110110, "cases": [{
            "name": "positive",
            "event": {"win.system.eventID": "1"},
            "expected_alert": True,
        }]}]
        output = "Phase 2: Completed decoding.\nname: json\nid: '110110'\n"
        import types
        result = types.SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch.object(worker.subprocess, "run", return_value=result) as process:
            worker.replay_cases({"fixtures": fixture}, Path("isolated.xml"))
        args = process.call_args.args[0]
        self.assertEqual(args[-2:], ["-c", "isolated.xml"])
        self.assertIn("wazuh-logtest-legacy", args[0])


if __name__ == "__main__":
    unittest.main()
