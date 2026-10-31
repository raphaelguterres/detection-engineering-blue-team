"""Compare existing Manager and Indexer Wazuh alert JSONL exports, offline only.

No connections, credentials, service changes, simulations, or raw event output.
Exports must stay in the repository's ignored .lab/ directory.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_DIR = ROOT / ".lab"
RULE_IDS = ("110100", "110110", "110120", "110130", "110140")
MAX_BYTES = 32 * 1024 * 1024
MAX_LINES = 250_000


def utc_datetime(value):
    if not isinstance(value, str):
        raise ValueError("UTC timestamp required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return parsed.astimezone(timezone.utc)


def local_export(path):
    """CLI guard: never read outside the ignored local private directory."""
    if PRIVATE_DIR.is_symlink() or PRIVATE_DIR.is_junction():
        raise ValueError("private .lab/ root must not be a link")
    private_root = PRIVATE_DIR.resolve()
    candidate = Path(path).resolve()
    if not candidate.is_relative_to(private_root) or not candidate.is_file():
        raise ValueError("export must be an existing file inside .lab/")
    if candidate.stat().st_size > MAX_BYTES:
        raise ValueError("export exceeds local processing limit")
    return candidate


def extract_identity(record):
    """Return normalized matching key; never serialize or print key fields."""
    if not isinstance(record, dict):
        raise ValueError("JSONL record must be an object")
    event = record.get("_source", record)
    if not isinstance(event, dict):
        raise ValueError("indexer _source must be an object")
    rule = event.get("rule")
    if not isinstance(rule, dict):
        return None
    rid = str(rule.get("id", ""))
    if rid not in RULE_IDS:
        return None
    agent = event.get("agent")
    if not isinstance(agent, dict):
        raise ValueError("tracked alert missing agent")
    alert_id = event.get("id")
    agent_id = agent.get("id")
    if not isinstance(alert_id, str) or not alert_id:
        raise ValueError("tracked alert missing ID")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("tracked alert missing agent ID")
    ts = utc_datetime(event.get("timestamp"))
    return rid, alert_id, agent_id, ts


def load_records(path, start, end):
    """Fail closed for invalid JSON or incomplete tracked alerts."""
    grouped = defaultdict(set)
    if Path(path).stat().st_size > MAX_BYTES:
        raise ValueError("export exceeds local processing limit")
    with Path(path).open(encoding="utf-8-sig") as stream:
        for number, line in enumerate(stream, 1):
            if number > MAX_LINES:
                raise ValueError("export exceeds line limit")
            if not line.strip():
                continue
            try:
                identity = extract_identity(json.loads(line))
            except (ValueError, TypeError) as exc:
                # Do not include raw line, event values, file path, or exception detail.
                raise ValueError("invalid or incomplete JSONL alert") from None
            if identity is not None and start <= identity[3] <= end:
                grouped[identity[0]].add(identity)
    return grouped


def compare(manager_file, indexer_file, start_utc, end_utc):
    """Compare independent exports; reject paths to the same underlying file."""
    if Path(manager_file).samefile(indexer_file):
        raise ValueError("Manager and Indexer exports must be distinct files")
    start, end = utc_datetime(start_utc), utc_datetime(end_utc)
    if start > end:
        raise ValueError("start must precede end")
    manager = load_records(manager_file, start, end)
    indexer = load_records(indexer_file, start, end)
    per_rule = {}
    for rid in RULE_IDS:
        m, i = manager[rid], indexer[rid]
        per_rule[rid] = {
            "manager_unique_alerts": len(m),
            "indexer_unique_alerts": len(i),
            "same_event_matches": len(m & i),
        }
    return {"comparison": "historical_offline_only", "dashboard_verified": False,
            "per_rule": per_rule}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager", required=True, help="private .lab/ JSONL path")
    parser.add_argument("--indexer", required=True, help="private .lab/ JSONL path")
    parser.add_argument("--start-utc", required=True, help="ISO 8601 UTC with timezone")
    parser.add_argument("--end-utc", required=True, help="ISO 8601 UTC with timezone")
    args = parser.parse_args()
    try:
        manager_file = local_export(args.manager)
        indexer_file = local_export(args.indexer)
        result = compare(manager_file, indexer_file, args.start_utc, args.end_utc)
    except (OSError, ValueError, UnicodeError):
        parser.exit(2, "OFFLINE_COMPARISON_UNAVAILABLE\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
