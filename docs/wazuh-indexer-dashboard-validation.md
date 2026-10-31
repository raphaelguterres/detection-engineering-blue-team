# Phase 3 — Wazuh Manager → Indexer → Dashboard verification

**Status: procedure prepared, not executed.** This is a read-only investigation of existing alerts. It creates no test events, restarts no services, changes no credentials, and does not alter Wazuh configuration. Carry out only on the authorized isolated lab. Do not paste access tokens, credentials, internal URLs, usernames, raw documents or screenshots containing identifiers into GitHub.

## Data path and proof levels

1. **Manager:** a previously captured alert from one of the five explicit rules (`110100`, `110110`, `110120`, `110130`, `110140`) exists in `/var/ossec/logs/alerts/alerts.json`. This establishes local alert creation only.
2. **Indexer:** the corresponding document is searchable in the relevant `wazuh-alerts-*` index. This establishes ingestion and indexing only.
3. **Dashboard:** the same historical document can be located in Discover, with matching rule ID, agent ID, and event time. This establishes UI visibility; it does not itself establish correct detection logic.

**Do not infer a downstream PASS from an upstream PASS.** If retention has removed older indexed documents, mark `INCONCLUSIVE — historical retention`, not `FAIL`, unless a currently expected document is demonstrably missing.

## Step A: offline preparation (safe on developer machine)

```powershell
python scripts/lab/run.py plan
python scripts/quality_gate.py
python -m unittest discover -s tests -p 'test_*.py' -v
```

Confirm the five rule IDs and their previously documented outcomes in [operational-validation.md](operational-validation.md). Choose a previously captured historical run window (timestamps available **locally only**). Do not generate another simulation to create fresh data.

## Step B: Manager — read-only inspection (inside authorized Wazuh Manager)

The operator chooses and authenticates to the existing Manager by their usual approved route. Read only existing logs and use minimal, sanitized aggregate output. Example, after entering the Manager container with existing authorized access:

```bash
python3 - <<'PY'
import json
from collections import Counter
from pathlib import Path

p = Path('/var/ossec/logs/alerts/alerts.json')
wanted = {'110100','110110','110120','110130','110140'}
counts = Counter()
if p.is_file():
    with p.open(encoding='utf-8', errors='replace') as stream:
        for line in stream:
            try:
                event = json.loads(line)
                rule = str(event.get('rule', {}).get('id',''))
                if rule in wanted:
                    counts[rule] += 1
            except ValueError:
                continue
print(json.dumps({'manager_alert_counts': {rid: counts[rid] for rid in sorted(wanted)},
                  'file_present': p.is_file()}))
PY
```

This reads **only the current alerts.json** and may omit rotated alerts; a zero does not prove no historical alert. Do not print log records or unique identifiers. Compare locally with the sanitized operational history.

## Step C: Indexer — read-only query

Using the authorized Indexer administration interface with existing **read-only** permissions, verify the cluster status and available `wazuh-alerts-*` indices. Run a bounded **search-only** query for the selected historical window; use only the exact index and field mappings discovered in your deployment. Illustrative OpenSearch query body:

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"terms": {"rule.id": ["110100", "110110", "110120", "110130", "110140"]}},
        {"range": {"timestamp": {"gte": "<HISTORICAL_START_UTC>", "lte": "<HISTORICAL_END_UTC>"}}}
      ]
    }
  },
  "aggs": {"by_rule": {"terms": {"field": "rule.id", "size": 5}}}
}
```

Replace the timestamp placeholders **locally**. The aggregation on `rule.id` may require `rule.id.keyword` depending on the index mapping. An aggregation failure is a mapping issue, **not** evidence of missing alerts. Never use write APIs, index deletion, template changes, broad unbounded dumps, or insecure certificate bypasses.

## Optional offline Manager ↔ Indexer correlation

Use the [Phase 3B historical alert comparator](phase3-historical-alert-correlation.md) on previously exported private JSONL to match the **same alert ID, rule ID, agent ID and UTC timestamp**. A match verifies only these two exports; independent Dashboard inspection is still mandatory.

## Step D: Dashboard — visual verification

In the existing Wazuh Dashboard, open Discover or the alerts view and select the matching `wazuh-alerts-*` data view. Set exactly the historical UTC window used above (check timezone display), filter `rule.id` to each of the five IDs, and compare selected document timestamps and agent ID against **local** Manager evidence. Avoid publishing screenshots with sensitive fields. The Indexer and Dashboard may use distinct time filters or permissions; check those before assuming indexing failure.

## Decision matrix

| Manager | Indexer | Dashboard | Conclusion |
|---|---|---|---|
| Found | Found | Visible | PASS **only** when `same_event_verified=true` after comparing rule ID, agent ID, timestamp and unique event identity across all three stages; otherwise PARTIAL |
| Found | Found | Missing | Dashboard data view/timezone/filter/permissions require investigation |
| Found | Missing | Missing | Investigate Filebeat/shipping, Indexer health, mappings, retention |
| Missing | Found | Visible | Current Manager log may have rotated; historical document still indexed |
| Missing | Missing | Missing | INCONCLUSIVE without retention and historical-window evidence |
| Found | Missing | Visible | PARTIAL; cross-check index permissions, time filters and data view, never infer Indexer failure from one query |
| Missing | Found | Missing | PARTIAL; compare historical retention and Dashboard filters |
| Missing | Missing | Visible | PARTIAL; independently reconcile document identity, index pattern and permissions |
| Any other combination | Any | Any | INCONCLUSIVE pending explicit investigation; no implicit PASS |

## Reporting

Save private diagnostics under ignored `.lab/`; publish only sanitized per-rule `manager_seen`, `indexer_seen`, `dashboard_seen`, time-window scope, index-pattern used, and any inconclusive reason. Distinguish **historical evidence** from any later new end-to-end execution. Stop at read-only diagnosis; do not change any service configuration or generate fresh telemetry without explicit operator approval.
