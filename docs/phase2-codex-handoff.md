# Phase 2 — controlled handoff for Codex

**Scope:** authorized isolated Kali/Docker Wazuh Manager and Windows endpoint only. **Nothing here has been executed remotely by this document.** No secrets, private keys, raw telemetry or DPAPI exports in ChatGPT, CI, issues or Git.

## Step A — offline work, no VM contact

```powershell
git fetch origin
git checkout hardening/offline-executor-safety
python scripts/lab/run.py plan
python scripts/quality_gate.py
python -m unittest discover -s tests -p 'test_*.py' -v
git status --short
```

Review `docs/detection-acceptance-criteria.md`, `docs/operational-validation.md`, and `docs/lab-automation.md`. The commands above do not connect to VMs. Stop if the local tests fail.

## Step B — owner approval and preflight

Before any remote action, require explicit owner approval, isolated network confirmation, a reviewed local `.lab/config.json`, verified SSH host key and authenticated WinRM configured independently. Do not read, print, copy, replace or transmit credentials; do not weaken SSH host verification, use `TrustedHosts *` or auto-enable remote access.

```powershell
python scripts/lab/run.py preflight --config .lab/config.json
```

A preflight may connect to both authorized VMs but should only probe state; it is not a live detection approval. If blocked, inspect the sanitized report in `.lab/runs/<run-id>/report.json` locally and stop.

## Step C — replay without deploy

Only after approval and successful preflight:

```powershell
python scripts/lab/run.py replay --config .lab/config.json
```

Confirm all fixtures passed and no duplicates exist. Replay validates rule logic on the Manager and cannot prove live Sysmon or Dashboard indexing. **Do not run `pipeline` yet**: it redeploys rules and triggers benign simulations.

## Step D — individually authorized benign validation

After explicit authorization for each run, no unresolved artifacts/journals, verified endpoint identity and snapshot/rollback readiness:

```powershell
python scripts/lab/run.py run --scenario powershell --config .lab/config.json
python scripts/lab/run.py run --scenario rundll32 --config .lab/config.json
python scripts/lab/run.py run --scenario schtasks --config .lab/config.json
python scripts/lab/run.py run --scenario runkey --config .lab/config.json
```

Review each report for `detected`, correct rule ID and level, unique marker and agent ID, local Sysmon event and verified cleanup before the next scenario. The local-account case is **separate and opt-in**, only on a disposable non-domain-controller endpoint with approval:

```powershell
python scripts/lab/run.py run --scenario localaccount --include-account --config .lab/config.json
```

If cleanup is unknown or fails, stop, inspect the journal and independently verify artifact ownership before using the documented targeted `cleanup --recovery-id ... --scenario ...` command. Never execute blanket cleanup or repeat unknown-state runs.

## Step E — promotion and evidence

Do not run `deploy`, `pipeline` or `rollback` without reviewing the existing Wazuh rule set, backup ID and potential conflicts; obtain approval for each change. Validate Dashboard indexing separately from Manager alerts. Publish **only a sanitized** report recording commit SHA, rule IDs, positive/negative fixture status, real endpoint telemetry/alerts and cleanup, failures, and dashboard status. Keep `.lab/` excluded from Git.

## Acceptance decision

- OFFLINE PASS: quality gate and all offline tests pass.
- MANAGER REPLAY PASS: positive/negative fixtures pass, without claiming end-to-end verification.
- LIVE PASS (per scenario): all gates in `docs/detection-acceptance-criteria.md` met.
- PHASE 2 COMPLETE: all five scenarios have **new** end-to-end evidence in one controlled campaign, cleanup independently verified, and any dashboard claim separately substantiated. The five historical detections are context, not proof of this new campaign.

Codex instruction: **Audit first; change nothing remotely by default. Never bypass authentication or request secrets in chat. Stop and ask for explicit operator authorization before any live scenario or service modification.**
