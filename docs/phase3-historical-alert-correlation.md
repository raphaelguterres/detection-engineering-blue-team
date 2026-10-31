# Phase 3B — Historical alert correlation (offline, read-only)

**Status: implemented and under CI review; not run against real Wazuh exports.**

This phase checks whether **the same historical alert** appears in locally exported Manager and Indexer records. It does **not** log into Wazuh, connect to a VM, replay a detection, validate the Dashboard, or alter services. See [Phase 3 architecture](wazuh-indexer-dashboard-validation.md) and [evidence criteria](phase3-evidence-template.md).

## Prerequisites

An authorized operator must independently obtain two restricted **historical** JSONL files using existing read-only access:

- `.lab/phase3-manager.jsonl`: one JSON alert from the existing Manager `alerts.json` per line.
- `.lab/phase3-indexer.jsonl`: one matching historical Indexer hit per line; each line may be a direct alert JSON or a JSON hit with a `_source` object.
- Both files must use the **same UTC observation window**, and be stored under `.lab/`, which is excluded from Git. Do not upload these files to an issue, PR, chat, or artifact.
- **Manager and Indexer exports must come from independent sources.** The comparator rejects using the same underlying file twice (including symlink or hardlink aliases). Two separately copied files could still contain the same records: the operator must independently confirm the provenance of each export before interpreting matches.
- Do not collect credentials, endpoint identifiers, or raw screenshots as part of the repository changes. If the records are no longer retained, mark the inspection *inconclusive* rather than generating new alerts.

This script expects these existing fields in relevant alerts: `id`, `rule.id`, `agent.id`, and `timestamp` (ISO 8601 with timezone). It supports only five explicit detection IDs: `110100`, `110110`, `110120`, `110130`, `110140`. Each indexer entry must represent a single alert rather than a complete search-results envelope.

## Local execution

```powershell
python scripts/phase3_compare_alert_exports.py `
  --manager .lab/phase3-manager.jsonl `
  --indexer .lab/phase3-indexer.jsonl `
  --start-utc 2026-10-30T00:00:00Z `
  --end-utc 2026-10-31T00:00:00Z
```

The dates are **examples only**. Replace them locally with the actual historical window, without publishing sensitive event details.

The tool enforces input paths inside the private `.lab/` directory, limits file sizes and line counts, and fails closed on malformed relevant records. It emits only aggregate counts by rule:

```json
{
  "comparison": "historical_offline_only",
  "dashboard_verified": false,
  "per_rule": {
    "110130": {
      "manager_unique_alerts": 1,
      "indexer_unique_alerts": 1,
      "same_event_matches": 1
    }
  }
}
```

The example is illustrative; actual output contains all five rule IDs. No raw alert IDs, user names, IP addresses, timestamps, document contents, or credentials are printed.

## Interpreting results

- `same_event_matches > 0` is evidence that at least one historical Manager event and Indexer event have the same alert ID, rule ID, agent ID, and normalized UTC timestamp **in these two exports**.
- `same_event_matches = 0` does **not** prove ingestion failed: retention, wrong windows, exports, permissions, or timestamp transformations may explain it.
- Nonmatching IDs or missing fields are **not** silently reclassified as success.
- Dashboard evidence remains **independent**. Inspect the *same historical event* in Discover with an authorized account and note the result privately. Do not set `same_event_verified=true` in the Phase 3 evidence gate unless Manager, Indexer and Dashboard have all been individually checked and correlated.
- If a result is ambiguous, mark **partial** or **inconclusive**; do not rerun simulations to manufacture evidence.

## Verification and documentation

```powershell
python -m compileall -q scripts
python -m unittest discover -s tests -p 'test_phase3_alert_correlation.py' -v
python -m unittest discover -s tests -p 'test_phase3_evidence_gate.py' -v
```

Record sanitized per-rule counts and conclusions in a local `.lab/phase3-evidence.md`, using the [template](phase3-evidence-template.md). Publish only aggregate counts and scope-limited conclusions when the environment owner authorizes it. The developer may use the **synthetic test fixtures** to validate the comparison tool without ever seeing private exports.

## Acceptance

1. Offline Python tests and quality gate pass.
2. At least one corresponding historical alert exists in both exports, with exact identity match.
3. Dashboard separately shows that same event, with matching rule, agent, timestamp and event identity.
4. Review and sanitize the final evidence before documenting any operational PASS.

**Completion of step 1 is not completion of steps 2–4.**
