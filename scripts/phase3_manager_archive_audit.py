"""Read-only aggregate audit of existing Wazuh Manager JSON/JSON.GZ alerts.

For operator execution locally in an authorized lab, never via a blocked remote path.
Emits no raw events, alert/agent IDs, command lines, or source host identifiers.
"""
from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RULES = ("110100", "110110", "110120", "110130", "110140")
MAX_SOURCE_BYTES = 128 * 1024 * 1024


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp missing")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("timestamp missing offset")
    return stamp.astimezone(timezone.utc)


def audit_file(path: Path, start: datetime, end: datetime) -> dict:
    """Aggregate by custom rule without disclosing original event contents."""
    if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("missing or oversized input")
    result = {
        "file": path.name,
        "lines": 0,
        "valid_json_objects": 0,
        "invalid_json_or_object": 0,
        "missing_or_invalid_timestamp_for_target_rule": 0,
    }
    all_ids = Counter()
    no_window = Counter()
    in_window = Counter()
    first = {}
    last = {}
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            result["lines"] += 1
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("not a JSON object")
            except (ValueError, TypeError):
                result["invalid_json_or_object"] += 1
                continue
            result["valid_json_objects"] += 1
            rule = event.get("rule")
            rid = str(rule.get("id", "")) if isinstance(rule, dict) else ""
            if rid:
                all_ids[rid] += 1
            if rid not in RULES:
                continue
            no_window[rid] += 1
            try:
                stamp = parse_utc(event.get("timestamp"))
            except (ValueError, TypeError, OverflowError):
                result["missing_or_invalid_timestamp_for_target_rule"] += 1
                continue
            first[rid] = min(first.get(rid, stamp), stamp)
            last[rid] = max(last.get(rid, stamp), stamp)
            if start <= stamp <= end:
                in_window[rid] += 1
    result["most_frequent_rule_ids"] = dict(all_ids.most_common(8))
    result["custom_rules_without_time_filter"] = {rid: no_window[rid] for rid in RULES}
    result["custom_rules_in_window"] = {rid: in_window[rid] for rid in RULES}
    result["time_bounds_utc"] = {
        rid: {"first": first[rid].isoformat(), "last": last[rid].isoformat()}
        for rid in RULES if rid in first
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", required=True,
                        help="one original Manager .json or .json.gz file per flag")
    parser.add_argument("--start-utc", required=True)
    parser.add_argument("--end-utc", required=True)
    args = parser.parse_args()
    try:
        start, end = parse_utc(args.start_utc), parse_utc(args.end_utc)
        if end < start:
            raise ValueError("reverse time range")
        paths = [Path(x) for x in args.file]
        if len({str(p.resolve()) for p in paths}) != len(paths):
            raise ValueError("duplicate source path")
        results = [audit_file(p, start, end) for p in paths]
    except (ValueError, OSError, UnicodeError, EOFError) as exc:
        parser.exit(2, "MANAGER_AUDIT_UNAVAILABLE\n")
    print(json.dumps({"mode": "read_only_aggregate",
                      "window_utc": [start.isoformat(), end.isoformat()],
                      "sources": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
