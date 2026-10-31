# Phase 3D — Run historical SIEM evidence checks in one offline command

**Status: procedure implemented, operational verification still pending.** This runner reads existing local Manager/Indexer exports only. It never opens a VM connection, calls a Wazuh API, creates alerts, runs simulations, or changes any Wazuh service. Running this script does **not** prove Dashboard visibility.

## Prerequisites

1. Obtain lab-owner approval for a **separate** read-only historical inspection. Select a specific UTC window in which the historical detections were observed.
2. Use existing authorized methods to privately collect two distinct historical exports as JSONL, with one alert or `_source` hit per line. Keep them under the repository's ignored `.lab/` directory:
   - `.lab/phase3-manager.jsonl` — Manager alerts.
   - `.lab/phase3-indexer.jsonl` — Indexer hits.
3. Confirm independent provenance of the exports. A copied Manager file is **not** proof of Indexer ingestion, even if the contents match. Do not share credentials, raw event IDs, host addresses, usernames or original exports through GitHub.
4. On the Windows workstation, ensure `python` resolves to Python 3.12+ and PowerShell is available. Verify `.lab` is a real private directory, not a symlink/junction. Both offline Python programs refuse junction roots before opening files, including when run directly outside the PowerShell wrapper.

## Run once (offline)

From the cloned repository root, after placing the **existing** exports privately:

```powershell
.\scripts\phase3-run-offline.ps1 -StartUtc "2026-10-30T00:00:00Z" -EndUtc "2026-10-31T00:00:00Z"
```

**Replace these example dates** with the correct historical time window; no date is inferred or searched by the script. Optional `-Manager` and `-Indexer` arguments accept different files inside `.lab/`.

The runner does three checks in sequence:

1. `phase3_compare_alert_exports.py` compares the original alert ID, rule ID, agent ID and UTC timestamp across the two independent local JSONL files. It emits only aggregate per-rule counts.
2. `phase3_prepare_observations.py` creates a conservative observation draft: positive counts become `found`; zeros remain `unknown`; Dashboard remains `unknown` and `same_event_verified=false`.
3. `phase3_evidence_gate.py` classifies the observations without claiming end-to-end verification.

Each invocation uses a **new GUID** and creates unique private comparison/observation files under `.lab/`. If parsing, saving, drafting, or classification fails, the runner stops. It does not replace existing evidence and does not print raw event IDs or host details.

## Independent Dashboard verification

An operator must still use the authorized Wazuh Dashboard to search for the **same** historical alert, verifying the ID, rule, agent, timestamp/timezone and data view. Only then can the operator manually mark the local evidence as verified, with independent supporting private records and the [Phase 3 evidence template](phase3-evidence-template.md). Missing historical data may mean retention or incomplete exports; record `inconclusive`, not automatic `failed`.

## Test and release criteria

GitHub Actions runs a Windows PowerShell **syntax check and synthetic end-to-end smoke test**, plus Windows-specific Python tests that construct a real junction redirecting `.lab/` to an external tracked directory and require refusal, alongside the standard Python tests. The smoke test parses the emitted evidence-gate JSON and requires `partial` for the synthetic rule and zero `verified` classifications. The smoke test uses two distinct, locally constructed files with identical synthetic content to prove **software wiring**, not independent SIEM provenance. It runs the command twice and checks that each run creates a new observation file while Dashboard remains unverified.

The operational readiness issue remains [#4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4). Do not merge this feature until its final CI and code review have been assessed.
