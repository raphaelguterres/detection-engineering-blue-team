"""Compare an independently exported Wazuh Dashboard Discover CSV against original alerts.

Offline, read-only, no credentials, network, simulations or raw event identifiers
in standard output. CSV must originate from the authorized Discover UI, *not*
from the Indexer Dev Tools response or a copy of the Manager export.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from phase3_compare_alert_exports import (
    RULE_IDS,
    extract_identity,
    load_records,
    local_export,
    utc_datetime,
)

EXPECTED = {"110100": 1, "110110": 1, "110120": 1, "110130": 1, "110140": 2}
REQUIRED_COLUMNS = ("id", "rule.id", "agent.id", "timestamp")
MAX_CSV_ROWS = 100


def load_discover_csv(path: Path, start, end):
    """Read only selected identity columns, rejecting ambiguous/unsafe exports."""
    counts = Counter()
    identities = set()
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        header = reader.fieldnames
        if not header or len(header) != len(set(header)):
            raise ValueError("Discover CSV missing or duplicate headers")
        if any(column not in header for column in REQUIRED_COLUMNS):
            raise ValueError("Discover CSV requires id, rule.id, agent.id and timestamp")
        for number, row in enumerate(reader, 1):
            if number > MAX_CSV_ROWS:
                raise ValueError("Discover CSV has too many rows")
            if None in row or any(row[column] is None for column in REQUIRED_COLUMNS):
                raise ValueError("Discover CSV row has malformed values")
            rule_id = row["rule.id"]
            if rule_id not in RULE_IDS:
                raise ValueError("Discover export includes unexpected rule ID")
            identity = extract_identity({
                "id": row["id"],
                "rule": {"id": rule_id},
                "agent": {"id": row["agent.id"]},
                "timestamp": row["timestamp"],
            })
            if identity is None or not (start <= identity[3] <= end):
                raise ValueError("Discover CSV timestamp out of the requested UTC window")
            if identity in identities:
                raise ValueError("Discover export includes duplicate identities")
            identities.add(identity)
            counts[rule_id] += 1
    return identities, counts


def compare_three(manager_path, indexer_path, discover_path, start_utc, end_utc):
    """Require three different local files; don't assert independent provenance."""
    paths = [local_export(path) for path in (manager_path, indexer_path, discover_path)]
    if len({path.resolve() for path in paths}) != 3:
        raise ValueError("Three distinct private evidence files are required")
    for first in range(3):
        for second in range(first + 1, 3):
            if paths[first].samefile(paths[second]):
                raise ValueError("Evidence files must be different")
    start, end = utc_datetime(start_utc), utc_datetime(end_utc)
    if start > end:
        raise ValueError("Invalid UTC window")

    manager = load_records(paths[0], start, end)
    indexer = load_records(paths[1], start, end)
    discover, discover_counts = load_discover_csv(paths[2], start, end)

    manager_set = set().union(*(manager[rule] for rule in RULE_IDS))
    indexer_set = set().union(*(indexer[rule] for rule in RULE_IDS))
    indexer_matches = manager_set & indexer_set
    all_matches = indexer_matches & discover

    per_rule = {}
    for rid in RULE_IDS:
        m, i = manager[rid], indexer[rid]
        matches = len(all_matches & m)
        per_rule[rid] = {
            "expected": EXPECTED[rid],
            "manager": len(m),
            "indexer": len(i),
            "discover": discover_counts[rid],
            "all_three_exact_matches": matches,
        }

    acceptable = (
        len(manager_set) == len(indexer_set) == len(discover) == 6
        and manager_set == indexer_set == discover
        and all(
            item["manager"] == item["indexer"] == item["discover"]
            == item["all_three_exact_matches"] == item["expected"]
            for item in per_rule.values()
        )
    )
    return {
        "scope": "six_original_custom_detection_alerts_2026_11_01_02",
        "manager_indexer_exact_matches": len(indexer_matches),
        "discover_exact_matches": len(all_matches),
        "discover_export_rows": len(discover),
        "per_rule": per_rule,
        "status": (
            "SIX_EXACT_MATCHES_REQUIRES_OPERATOR_PROVENANCE_REVIEW"
            if acceptable else "NOT_ACCEPTED_INCOMPLETE_OR_MISMATCH"
        ),
        "operator_discover_provenance_verified": False,
        "note": (
            "Only an independently exported Discover UI CSV qualifies. "
            "The operator must review provenance before closing Issue #4."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager", default=".lab/phase3-manager.jsonl")
    parser.add_argument("--indexer", default=".lab/phase3-indexer.jsonl")
    parser.add_argument("--discover", default=".lab/phase3-discover.csv")
    parser.add_argument("--start-utc", default="2026-11-01T20:00:00Z")
    parser.add_argument("--end-utc", default="2026-11-02T00:40:00Z")
    args = parser.parse_args()
    try:
        result = compare_three(
            args.manager, args.indexer, args.discover, args.start_utc, args.end_utc
        )
    except (OSError, ValueError, UnicodeError, csv.Error):
        parser.exit(2, "DISCOVER_COMPARISON_UNAVAILABLE_OR_INVALID_EXPORT\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["discover_exact_matches"] == 6 and result["status"].startswith("SIX_") else 3


if __name__ == "__main__":
    raise SystemExit(main())
