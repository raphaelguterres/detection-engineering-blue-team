"""Quality gate dependency-free for this detection-as-code repository."""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog" / "detections.yaml"
PURPLE_PLAN = ROOT / "tests" / "purple-validation-plan.json"
REQUIRED = {"id", "title", "status", "rule_id", "technique", "severity", "rule_file", "tests_file", "simulation", "evidence", "false_positives", "tuning", "rollback", "owner"}


def parse_catalog(text: str) -> list[dict[str, object]]:
    """Parse the deliberately small, review-friendly YAML subset used by this catalog."""
    entries, current, section, list_key = [], None, None, None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent, line = len(raw) - len(raw.lstrip()), raw.strip()
        if line == "detections:":
            continue
        if indent == 2 and line.startswith("- "):
            current = {"data_sources": [], "false_positives": [], "tuning": [], "references": []}
            entries.append(current)
            key, value = line[2:].split(":", 1)
            current[key] = value.strip()
            section = list_key = None
        elif current is not None and indent == 4 and line.endswith(":"):
            section, list_key = line[:-1], line[:-1]
            current[section] = {} if section == "evidence" else []
        elif current is not None and indent == 4 and ":" in line:
            key, value = line.split(":", 1)
            current[key] = value.strip()
            section = list_key = None
        elif current is not None and indent >= 6 and line.startswith("- ") and list_key:
            current[list_key].append(line[2:].strip())
        elif current is not None and indent >= 6 and ":" in line and section == "evidence":
            key, value = line.split(":", 1)
            current[section][key] = value.strip()
    return entries


def main() -> int:
    failures: list[str] = []
    entries = parse_catalog(CATALOG.read_text(encoding="utf-8"))
    ids = [str(entry.get("id", "")) for entry in entries]
    rules = [str(entry.get("rule_id", "")) for entry in entries]
    if len(ids) != len(set(ids)) or len(rules) != len(set(rules)):
        failures.append("catalog contains duplicate detection or rule IDs")

    for entry in entries:
        name = str(entry.get("id", "<unknown>"))
        missing = REQUIRED - entry.keys()
        if missing:
            failures.append(f"{name}: missing required fields: {', '.join(sorted(missing))}")
        if not str(entry.get("technique", "")).startswith("T"):
            failures.append(f"{name}: invalid MITRE technique")
        if entry.get("severity") not in {"low", "medium", "high", "critical"}:
            failures.append(f"{name}: invalid severity")
        for field in ("rule_file", "tests_file", "simulation"):
            path = ROOT / str(entry.get(field, ""))
            if not path.is_file():
                failures.append(f"{name}: missing {field}: {path.relative_to(ROOT)}")

        rule_path = ROOT / str(entry.get("rule_file", ""))
        try:
            tree = ET.parse(rule_path)
            rule = tree.find(".//rule")
            mitre_id = tree.findtext(".//mitre/id")
            if rule is None or rule.get("id") != str(entry.get("rule_id")):
                failures.append(f"{name}: rule ID does not match catalog")
            if mitre_id != entry.get("technique"):
                failures.append(f"{name}: MITRE mapping does not match catalog")
        except (ET.ParseError, OSError) as error:
            failures.append(f"{name}: invalid rule XML: {error}")

        try:
            fixture = json.loads((ROOT / str(entry.get("tests_file"))).read_text(encoding="utf-8"))
            cases = fixture.get("cases", [])
            expected = {case.get("expected_alert") for case in cases}
            if fixture.get("rule_id") != int(entry.get("rule_id", 0)):
                failures.append(f"{name}: fixture rule ID does not match catalog")
            if not cases or expected != {True, False}:
                failures.append(f"{name}: needs both positive and false-positive regression cases")
        except (json.JSONDecodeError, OSError, ValueError) as error:
            failures.append(f"{name}: invalid fixture: {error}")

    try:
        purple_plan = json.loads(PURPLE_PLAN.read_text(encoding="utf-8"))
        records = purple_plan.get("validations", [])
        planned_ids = {record.get("detection_id") for record in records}
        catalog_ids = {entry.get("id") for entry in entries}
        if planned_ids != catalog_ids:
            failures.append("Purple Team plan must contain exactly one validation contract per detection")
        required_purple = {"detection_id", "rule_id", "hypothesis", "expected_telemetry", "wazuh_evidence", "cleanup"}
        for record in records:
            missing = required_purple - record.keys()
            if missing:
                failures.append(f"Purple Team record {record.get('detection_id', '<unknown>')}: missing {', '.join(sorted(missing))}")
            if not record.get("expected_telemetry") or not record.get("wazuh_evidence"):
                failures.append(f"Purple Team record {record.get('detection_id', '<unknown>')}: telemetry and Wazuh evidence are required")
            matching = next((entry for entry in entries if entry.get("id") == record.get("detection_id")), None)
            if matching and record.get("rule_id") != int(matching.get("rule_id", 0)):
                failures.append(f"Purple Team record {record.get('detection_id')}: rule ID does not match catalog")
    except (json.JSONDecodeError, OSError) as error:
        failures.append(f"invalid Purple Team validation plan: {error}")

    if failures:
        print("QUALITY GATE FAILED")
        print("\n".join(f"- {failure}" for failure in failures))
        return 1
    print(f"QUALITY GATE PASSED: {len(entries)} detections validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())

