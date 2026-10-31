# Phase 3C — Safe observation handoff (offline)

**Scope:** prepare an operator-reviewable evidence draft from the historical Manager ↔ Indexer comparison. This procedure is not connected to Wazuh and cannot confirm the Dashboard.

## Why this exists

The existing historical comparator reports aggregate Manager and Indexer counts. The separate Phase 3 evidence gate expects five structured per-rule observations. Manually copying these counts can cause misleading statements, especially when an empty historical export is incorrectly interpreted as evidence of missing alerts.

The draft generator makes this handoff conservative:

- A positive Manager count → stage `found`; zero → `unknown`, **not** `missing`.
- A positive Indexer count → stage `found`; zero → `unknown`.
- Dashboard → always `unknown`.
- `same_event_verified` → always `false` even when the two exports have matching events.
- `inspection_attempted` → `true` because the comparison was attempted; this does **not** mean the historical sources were complete.
- No direct `verified` outcome can be generated without separate operator inspection in Dashboard.

## Safe local workflow

Use only an authorized lab and existing historical exports. Keep source event files and any local derived files in the Git-ignored `.lab/` directory. Never upload records, access tokens, internal hostnames, or unredacted screenshots into GitHub.

First, create the historical aggregate comparison with the [Phase 3B comparator](phase3-historical-alert-correlation.md). Example in PowerShell, with the *actual* historical dates in UTC rather than the illustrative values:

Every execution gets a **new unique comparison and observation filename**. If comparison generation or saving fails, the workflow stops before creating a draft. Run the following block as one unit in PowerShell:

```powershell
$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath ".lab" -PathType Container)) {
  throw "Create the private .lab directory locally before running."
}
$runId = [guid]::NewGuid().ToString("N")
$comparison = ".lab/phase3-comparison-$runId.json"
$observations = ".lab/phase3-observations-$runId.json"

$jsonLines = & python scripts/phase3_compare_alert_exports.py `
  --manager .lab/phase3-manager.jsonl `
  --indexer .lab/phase3-indexer.jsonl `
  --start-utc 2026-10-30T00:00:00Z `
  --end-utc 2026-10-31T00:00:00Z
if ($LASTEXITCODE -ne 0 -or -not $jsonLines) {
  throw "Comparison failed; no observation draft will be made."
}
$jsonLines | Out-File -LiteralPath $comparison -Encoding utf8 -NoClobber -ErrorAction Stop

& python scripts/phase3_prepare_observations.py `
  --comparison $comparison `
  --output $observations
if ($LASTEXITCODE -ne 0) { throw "Draft creation failed." }

& python scripts/phase3_evidence_gate.py $observations
if ($LASTEXITCODE -ne 0) { throw "Evidence gate failed." }
```

Use the **actual** historical UTC time window; the dates above are illustrative. The two new file paths remain paired by the same run ID and are never replaced. Do not run the later commands separately against files from previous runs.

This will only produce `partial` or `inconclusive` outcomes (never `verified`) because Dashboard visibility is not yet checked.

## Required manual review for end-to-end proof

In the authorized Dashboard, inspect the **same historical alert** by event identity, rule, agent, and timestamp with matching timezone and data view. Record evidence privately using the [evidence template](phase3-evidence-template.md). Only after checking all three stages may the operator manually update the local observation to `dashboard=found` and `same_event_verified=true`, **for a rule with a positively correlated event**. A nonzero aggregate overlap alone does not prove Dashboard identity or export provenance.

The system cannot establish independent data provenance from aggregate counts. Keep independent Manager/Indexer origin records locally and do not infer absence from zero counts: data retention or incomplete exports may explain them.

## Security and rollback

- Inputs and outputs must reside in ignored `.lab/`. Inputs are capped at 1 MiB and validated against the exact expected schema.
- Output is created only if absent, with owner-only permissions where supported.
- The scripts do not call any Wazuh APIs or touch any virtual machines, credentials, live detections, or remote services.
- No rollback of running services is necessary. To discard an invalid local **derived draft**, remove only that specific file after checking its path and ownership, then rerun. Never delete raw evidence in bulk.
- The CI tests use synthetic summaries and do **not** claim operational SIEM validation.

## Acceptance

The offline handoff passes when the GitHub Actions tests succeed, the draft is accepted by the existing evidence gate, and nothing is marked end-to-end verified without the separate Dashboard check. The operational gate remains tracked in [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4).
