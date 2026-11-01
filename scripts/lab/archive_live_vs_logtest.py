"""Read-only comparison of Wazuh archived events, live decisions and isolated logtest.

The archive stores event payloads and the LIVE decoder/rule decision. Feeding the
same full_log to wazuh-logtest can select a DIFFERENT decoder or ruleset path.
Use this only as diagnostic evidence, never as production acceptance.
"""
from __future__ import annotations

import argparse
import base64
import collections
import json
import re
import stat
import sys
import subprocess
from pathlib import Path

EXPECTED = {
    "powershell": "110100",
    "rundll32": "110110",
    "schtasks": "110120",
}
RULE_RE = re.compile(r"(?m)^\s*id: '(\d+)'")
DECODER_RE = re.compile(r"(?m)^\s*name: '([^']+)'")
MAX_SAMPLES = 8


def validate_markers(data: object) -> dict[str, str]:
    if not isinstance(data, dict) or set(data) != set(EXPECTED):
        raise ValueError("marker file must contain only the three scenario keys")
    for value in data.values():
        if not isinstance(value, str) or not re.fullmatch(r"DE-[a-f0-9]{16}", value):
            raise ValueError("invalid run marker")
    return data


def markers_from_file(path: Path) -> dict[str, str]:
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("marker file must be private (chmod 600)")
    return validate_markers(json.loads(path.read_text(encoding="utf-8")))


def marker_value(scenario: str, run_id: str) -> str:
    if scenario == "powershell":
        return base64.b64encode(("Write-Output '" + run_id + "'").encode("utf-16le")).decode()
    return run_id


def archived_events(path: Path, markers: dict[str, str]) -> dict[str, dict]:
    results = {name: {"marker_events": 0, "event1": []} for name in EXPECTED}
    needles = {name: marker_value(name, value) for name, value in markers.items()}
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if not any(needle in line for needle in needles.values()):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            for scenario, needle in needles.items():
                if needle not in line:
                    continue
                group = results[scenario]
                group["marker_events"] += 1
                win = item.get("data", {}).get("win", {})
                system = win.get("system", {})
                if (str(system.get("eventID")) != "1"
                        or system.get("providerName") != "Microsoft-Windows-Sysmon"):
                    continue
                ed = win.get("eventdata", {})
                image = ed.get("image", "").replace("/", "\\").split("\\")[-1].lower()
                if image != {"powershell": "powershell.exe", "rundll32": "rundll32.exe",
                             "schtasks": "schtasks.exe"}[scenario]:
                    continue
                if len(group["event1"]) >= MAX_SAMPLES:
                    continue
                group["event1"].append({
                    "archive_rule": str(item.get("rule", {}).get("id", "none")),
                    "archive_decoder": str(item.get("decoder", {}).get("name", "unknown")),
                    "full_log": str(item.get("full_log", "")),
                })
    return results


def isolated_logtest(full_log: str, executable: str) -> tuple[str, str, bool]:
    process = subprocess.run(
        [executable], input=full_log + "\n", text=True, capture_output=True, timeout=25,
        check=False,
    )
    if process.returncode:
        return "error", "error", False
    output = process.stdout + process.stderr
    rules = RULE_RE.findall(output)
    decoders = DECODER_RE.findall(output)
    return (
        rules[-1] if rules else "none",
        decoders[-1] if decoders else "unknown",
        "**Alert to be generated." in output,
    )


def assess(archive: Path, markers: dict[str, str], logtest: str) -> dict:
    found = archived_events(archive, markers)
    result = {}
    for scenario, expected in EXPECTED.items():
        group = found[scenario]
        comparisons = []
        for evt in group["event1"]:
            offline_rule, offline_decoder, offline_alert = isolated_logtest(evt["full_log"], logtest)
            comparisons.append({
                "live_rule": evt["archive_rule"],
                "live_decoder": evt["archive_decoder"],
                "isolated_rule": offline_rule,
                "isolated_decoder": offline_decoder,
                "isolated_alert": offline_alert,
                "different_rule": evt["archive_rule"] != offline_rule,
                "different_decoder": evt["archive_decoder"] != offline_decoder,
            })
        live_custom = sum(row["live_rule"] == expected for row in comparisons)
        result[scenario] = {
            "expected_rule": expected,
            "archived_marker_events": group["marker_events"],
            "matching_sysmon_process_events": len(group["event1"]),
            "live_custom_rule_event_count": live_custom,
            "offline_expected_rule_count": sum(
                row["isolated_rule"] == expected for row in comparisons
            ),
            "live_rule_counts": dict(collections.Counter(row["live_rule"] for row in comparisons)),
            "live_decoder_counts": dict(collections.Counter(row["live_decoder"] for row in comparisons)),
            "offline_decoder_counts": dict(collections.Counter(row["isolated_decoder"] for row in comparisons)),
            "live_vs_offline_discrepancy_count": sum(row["different_rule"] for row in comparisons),
            "decoder_difference_count": sum(row["different_decoder"] for row in comparisons),
            "status": (
                "custom_rule_observed_live" if live_custom else
                "received_but_custom_rule_absent" if comparisons else
                "no_matching_sysmon_process_event"
            ),
        }
    return {
        "audit_version": 1,
        "mode": "read_only",
        "requires_dashboard_confirmation": True,
        "live_source": "Wazuh archives decoder/rule fields",
        "isolated_source": "wazuh-logtest with original archived full_log",
        "per_scenario": result,
        "note": "An isolated logtest match does not prove a live alert. Nothing is replayed into the Manager.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    marker_source = parser.add_mutually_exclusive_group(required=True)
    marker_source.add_argument("--markers", type=Path, help="private local 0600 JSON")
    marker_source.add_argument("--markers-stdin", action="store_true", help="read private JSON via stdin")
    parser.add_argument("--logtest", default="/var/ossec/bin/wazuh-logtest")
    args = parser.parse_args()
    try:
        markers = validate_markers(json.load(sys.stdin)) if args.markers_stdin else markers_from_file(args.markers)
        result = assess(args.archive, markers, args.logtest)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(2, f"AUDIT_ERROR={type(exc).__name__}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
