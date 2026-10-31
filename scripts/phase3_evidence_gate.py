"""Offline-only evidence gate for Phase 3. Accepts sanitized observations, never connects to services."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

RULE_IDS = ("110100", "110110", "110120", "110130", "110140")
STAGES = ("manager", "indexer", "dashboard")
VALUES = ("found", "missing", "unknown")


def assess(data):
    if not isinstance(data, dict) or set(data) != set(RULE_IDS):
        raise ValueError("require exactly the five versioned rule IDs")
    result = {}
    for rid in RULE_IDS:
        item = data[rid]
        if not isinstance(item, dict) or set(item) != set(STAGES + ("same_event_verified",)):
            raise ValueError("invalid observation fields")
        if any(item[s] not in VALUES for s in STAGES):
            raise ValueError("stage must be found/missing/unknown")
        if type(item["same_event_verified"]) is not bool:
            raise ValueError("same_event_verified must be boolean")
        m, i, d = (item[s] for s in STAGES)
        if m == i == d == "found" and item["same_event_verified"]:
            status = "verified"
        elif "found" in (m, i, d):
            status = "partial"
        else:
            status = "inconclusive"
        result[rid] = status
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path, help="local sanitized JSON only")
    args = parser.parse_args()
    try:
        result = assess(json.loads(args.observations.read_text(encoding="utf-8")))
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, "INVALID_OFFLINE_EVIDENCE\n")
    print(json.dumps({"phase3_per_rule": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
