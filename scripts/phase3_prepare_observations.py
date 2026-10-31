"""Create a conservative Phase 3 observation draft from an offline comparison.

No Wazuh access. Never promotes Manager/Indexer counts to Dashboard evidence.
Only reads and writes sanitized JSON inside ignored .lab/.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from phase3_compare_alert_exports import PRIVATE_DIR, RULE_IDS

MAX_SUMMARY_BYTES = 1024 * 1024
MAX_COUNT = 250_000
COUNTS = ("manager_unique_alerts", "indexer_unique_alerts", "same_event_matches")


def build_observations(summary):
    """Validate aggregate input and leave all unproven conclusions unset."""
    if not isinstance(summary, dict) or set(summary) != {
        "comparison", "dashboard_verified", "per_rule"
    }:
        raise ValueError("invalid comparison summary")
    if summary["comparison"] != "historical_offline_only":
        raise ValueError("comparison type is not supported")
    if summary["dashboard_verified"] is not False:
        raise ValueError("summary cannot prove Dashboard visibility")
    rules = summary["per_rule"]
    if not isinstance(rules, dict) or set(rules) != set(RULE_IDS):
        raise ValueError("comparison must cover exactly five rules")

    draft = {}
    for rid in RULE_IDS:
        item = rules[rid]
        if not isinstance(item, dict) or set(item) != set(COUNTS):
            raise ValueError("invalid aggregate fields")
        if any(type(item[k]) is not int or not 0 <= item[k] <= MAX_COUNT for k in COUNTS):
            raise ValueError("invalid aggregate count")
        manager, indexer, matched = (item[k] for k in COUNTS)
        if matched > min(manager, indexer):
            raise ValueError("match count exceeds source counts")
        draft[rid] = {
            "manager": "found" if manager else "unknown",
            "indexer": "found" if indexer else "unknown",
            "dashboard": "unknown",
            "same_event_verified": False,
            "inspection_attempted": True,
        }
    return draft


def private_path(path):
    """Resolve paths and reject anything outside the private .lab/ tree."""
    if PRIVATE_DIR.is_symlink() or PRIVATE_DIR.is_junction():
        raise ValueError(".lab/ must be a real directory, not a symlink or junction")
    root = PRIVATE_DIR.resolve()
    candidate = Path(path).resolve()
    if not root.is_dir() or not candidate.is_relative_to(root):
        raise ValueError("path must be inside .lab/")
    return candidate


def main():
    """Create a new, local-only observations draft without overwriting evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", required=True, help="existing .lab/ comparison JSON")
    parser.add_argument("--output", required=True, help="new .lab/ observations JSON")
    args = parser.parse_args()
    try:
        source, target = private_path(args.comparison), private_path(args.output)
        if not source.is_file() or source.stat().st_size > MAX_SUMMARY_BYTES:
            raise ValueError("comparison input missing or too large")
        if source == target:
            raise ValueError("output must differ from input")
        summary = json.loads(source.read_text(encoding="utf-8-sig"))
        observations = build_observations(summary)
        # EXCL prevents replacing a previous operator observation record.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(observations, stream, indent=2)
            stream.write("\n")
    except (OSError, ValueError, UnicodeError):
        parser.exit(2, "OFFLINE_OBSERVATION_DRAFT_UNAVAILABLE\n")
    print("OFFLINE_OBSERVATION_DRAFT_CREATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
