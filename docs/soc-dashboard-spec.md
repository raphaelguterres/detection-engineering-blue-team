# SOC dashboard specification — historical Wazuh alerts

**Design only.** Dashboard not created or tested against live services. Use only previously generated authorized lab alerts and read-only data access. Consult [Manager → Indexer → Dashboard validation](wazuh-indexer-dashboard-validation.md) first.

## Purpose

Show detection coverage and investigate whether existing alerts from five versioned rules are searchable and visible. This is a portfolio-grade *specification*, not a production availability claim.

## Recommended dashboard panels

| Panel | Visualization | Data | Interpretation |
| --- | --- | --- | --- |
| Alerts by rule | Horizontal bars | Count by `rule.id`, filter to IDs 110100–110140 | Counts within selected historical time window; zero may be retention |
| Alert timeline | Date histogram | `timestamp` | When alert records were indexed |
| Severity | Bars or table | `rule.level` | Compare actual severity with rule XML |
| Agent distribution | Table | `agent.id` aggregated, no identifiers in public exports | Detect cross-agent routing mistakes |
| MITRE technique coverage | Static mapping table | Version-controlled catalog and rule ID | **Design coverage only**, not validated MITRE effectiveness |
| Data pipeline verification | Status table | Manager seen / Indexer seen / Dashboard seen | Do not label a stage passed unless evidence is recorded |
| Detailed investigation | Saved query/table | timestamp, rule ID, level, technique; sensitive fields hidden | Investigate one historical alert at a time |

## Versioned detection mapping

| Rule ID | Detection | MITRE ATT&CK |
| --- | --- | --- |
| 110100 | PowerShell encoded command | T1059.001 |
| 110110 | Rundll32 writable-path execution | T1218.011 |
| 110120 | Scheduled task creation | T1053.005 |
| 110130 | Registry Run Key modification | T1547.001 |
| 110140 | Local account creation attempt | T1136.001 |

## Safe default filters

- Index pattern: the authorized deployment's `wazuh-alerts-*` data view (verify first).
- Time range: **exact historical validation window**, with timezone checked.
- Rule IDs: 110100, 110110, 110120, 110130, 110140 only.
- Agent: the authorized endpoint under investigation, selected privately.
- Do not display full command lines, usernames, IPs, credentials, or raw event documents in public screenshots.
- Use read-only credentials with least privilege; never export authentication details.

## Validation checklist

1. Confirm historical alerts exist in the Manager or have an explicitly documented rotation/retention outcome.
2. Check Indexer index availability and field mappings; run bounded aggregate queries before building any charts.
3. Cross-check counts, time ranges, IDs and levels between Manager and Indexer with the same scope.
4. Check the Dashboard data view, timezone, permissions and refresh interval before marking a record missing.
5. Only after verifying existing data, build panels manually in the authorized Dashboard UI; no unreviewed saved-object imports.
6. Export only sanitized screenshots and a summary that clearly distinguishes historical detection evidence from fresh integrated validation.

## Outcome classification

- **Verified:** same historical alert identified at Manager, Indexer and Dashboard (with matching scoped identifiers).
- **Partial:** alert verified at upstream stage but unconfirmed downstream; describe exact stage.
- **Inconclusive:** old alerts unavailable due to rotation, retention or lack of access.
- **Not tested:** no authorized inspection performed yet.

The final report should say which of these is supported rather than claiming a functional SOC dashboard merely because this document exists.
