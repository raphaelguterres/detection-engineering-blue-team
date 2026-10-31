# Phase 3 — Sanitized evidence record template

Copy this Markdown document to a local ignored `.lab/phase3-evidence.md` for narrative notes. Save the JSON block below separately as `.lab/phase3-observations.json` before running the classifier. **Do not store credentials, internal hostnames, IPs, usernames, raw alerts, event markers or unsanitized screenshots in Git.**

## Scope

- Date (UTC):
- Git commit:
- Lab authorization recorded locally:
- Historical observation window (UTC, coarse public summary only):
- Source: historical detection events, no new simulation

## Per-rule observations

| Rule ID | Manager | Indexer | Dashboard | Same historical event correlated? | Result |
| --- | --- | --- | --- | --- | --- |
| 110100 | unknown | unknown | unknown | no | not_tested |
| 110110 | unknown | unknown | unknown | no | not_tested |
| 110120 | unknown | unknown | unknown | no | not_tested |
| 110130 | unknown | unknown | unknown | no | not_tested |
| 110140 | unknown | unknown | unknown | no | not_tested |

Use only `found`, `missing`, `unknown` for the three stages. Set `inspection_attempted` to `true` only after an authorized historical inspection has occurred; otherwise leave it `false`. `same_event_verified` must be true only when the operator privately cross-checks the matching rule, agent, timestamp and unique event identity in all three stages. Generic aggregate counts **do not** prove the same event was observed.

### Optional sanitized JSON for offline classification

```json
{
  "110100": {"manager":"unknown","indexer":"unknown","dashboard":"unknown","same_event_verified":false,"inspection_attempted":false},
  "110110": {"manager":"unknown","indexer":"unknown","dashboard":"unknown","same_event_verified":false,"inspection_attempted":false},
  "110120": {"manager":"unknown","indexer":"unknown","dashboard":"unknown","same_event_verified":false,"inspection_attempted":false},
  "110130": {"manager":"unknown","indexer":"unknown","dashboard":"unknown","same_event_verified":false,"inspection_attempted":false},
  "110140": {"manager":"unknown","indexer":"unknown","dashboard":"unknown","same_event_verified":false,"inspection_attempted":false}
}
```

Keep the populated file inside `.lab/`. Run `python scripts/phase3_evidence_gate.py .lab/phase3-observations.json` to classify the observations offline. Do not mark "verified" merely by changing the boolean: the operator must retain independent local evidence supporting that assessment.

## Investigation and conclusion

- Index pattern and mapping confirmed locally:
- Timezone and retention checked:
- Missing/partial records explained:
- No unauthorized operations performed:
- Next action:
- Reviewer and date:
