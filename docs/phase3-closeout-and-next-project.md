# Phase 3 closure and portfolio handoff — 2026-10-31

> **Engineering accepted; operational acceptance pending.** Do not claim live end-to-end SIEM validation until independently correlated historical evidence exists in Manager, Indexer, and Dashboard.

## Verified GitHub engineering history

| Stage | Merge into main | Scope |
| --- | --- | --- |
| Phase 2: safe offline executor | [PR #1](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/1), `4db9f19` | Input validation, regression tests, CI |
| Phase 3A: indexer/dashboard criteria | [PR #2](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/2), `e4cdbc7` | Read-only procedure, evidence gate, dashboard specification |
| Phase 3B: historical correlation | [PR #3](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/3), `a9e41b2` | Offline matching of Manager ↔ Indexer by exact event identity |
| Phase 3C: sanitized evidence drafts | [PR #5](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/5), `1b30477` | Conservative evidence handoff; no automatic Dashboard PASS |
| Phase 3D: one-command workflow | [PR #6](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/6), `77bbe01` | Windows PowerShell runner; synthetic CI #63 passed |

The current repository records historical lab results for **five Wazuh rules**: `110100`, `110110`, `110120`, `110130`, `110140`. This is distinct from proof that these alerts were indexed and visible in the Dashboard. The CI smoke test uses synthetic local fixtures, not a live Manager/Indexer.

## Remaining acceptance gates (operator-owned)

1. **Authorize read-only inspection** of the isolated Wazuh lab and record this approval privately. Never infer approval from a GitHub merge.
2. **Choose an actual historical UTC time window** that contains known detections and verify retention limits.
3. **Independently export the historical events** from the Manager and the Indexer, using existing authorized access and bounded queries. Store only in Git-ignored `.lab/`, with evidence of provenance kept locally.
4. **Run the approved local workflow** `scripts/phase3-run-offline.ps1` with `-StartUtc` and `-EndUtc`; confirm the comparison, generated draft, and evidence gate. This does not contact the VMs.
5. **Check the same event in the Dashboard**: alert ID, rule ID, agent ID and UTC timestamp must match the original event. Verify field mapping, data view, permissions and retention. Do not generate events merely to make this step pass.
6. **Publish sanitized conclusions only** (per-rule verified/partial/inconclusive/not_tested), separate true negatives from retention-limited observations, and record reviewer, data window, test method and rollback considerations in the engineering journal.

Track the operational evidence in [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4). Never publish raw alerts, source hostnames, identifiers, IP addresses or credentials.

## Definition of done for the existing project

- All five rules remain versioned and have passing offline regression tests.
- Any proposed deployment or live procedure has explicit authorization, documented preflight and rollback.
- At least one historical alert is independently shown to match across Manager, Indexer and Dashboard before the phrase “end-to-end validated” appears in a portfolio summary.
- For claims of *5/5 end-to-end*, **each** of the five rule IDs must meet the cross-stage proof criterion. Do not substitute a one-event check for a five-rule claim.
- Publish a short sanitized case study: hypothesis, telemetry source, ATT&CK mapping, detection logic, known false positives, evidence boundaries, outcome and lessons learned.
- Include CI badge, architecture diagram, limitations, test commands and exact evidence status in README.
- Mark the issue complete **only after** operational acceptance; otherwise keep it open with explicit blockers.

## Next portfolio project: incident-response-soar-lab

Do not duplicate the existing [Threat Hunting](https://github.com/raphaelguterres/threat-hunting-detection-lab) or [Detection Engineering](https://github.com/raphaelguterres/detection-engineering-blue-team) repositories. The next project demonstrates the third SOC competency: **triage, incident response and constrained automation**.

### Scope

A standalone Python 3.12 offline SOC incident-response engine that ingests **synthetic, sanitized** alert JSON, generates a case record, applies deterministic severity/triage rules, enriches the case with local ATT&CK mappings, and produces an **analyst-reviewed response recommendation**. Initially it must make **no network calls**, perform **no host isolation**, terminate **no process** and use **no credentials**.

### Architecture

`Synthetic Alert → Contract Validation → Triage Policy → Case/Timeline → Analyst Approval Gate → Audit Log → Sanitized Report`

### Suggested milestones

| Milestone | Goal | Quality proof |
| --- | --- | --- |
| M1 — Foundation | Repo, schema, fixtures, README, threat model, CI | Test isolation; no secrets |
| M2 — Alert triage | Deterministic severity and confidence, suppression notes | Unit tests for benign and suspicious inputs |
| M3 — Case management | Case ID, ownership, timeline, immutable audit events | Reproducible fixture-based integration tests |
| M4 — IR playbooks | Phishing, credential misuse, suspicious PowerShell, persistence | Human approval required for any containment recommendation |
| M5 — SOAR simulation | Dry-run orchestration and reversible action planning only | Zero remote side effects, error handling, idempotency |
| M6 — Portfolio | Architecture diagram, sanitized incident report, metrics | CI pass, reviewer checklist, walkthrough video |

**Guardrail:** code and CI can validate *planning*, *schemas* and *synthetic case outcomes*; these do not demonstrate successful containment of real incidents. Future remote actions require a separate security design and explicit operator authorization.

### Recommended recruiter-ready evidence

- Three synthetic incident narratives (PowerShell execution, persistence via Run Key, suspicious account creation) mapped to existing Wazuh rule IDs.
- Before/after incident timeline, false-positive reasoning, TTD/TTR calculations with **synthetic durations clearly labeled**, audit trail and manual approval decisions.
- A report PDF or HTML created from synthetic case data and a concise README showing how to reproduce tests.

### First new repository name

`incident-response-soar-lab` (public after reviewing for secrets and publication quality). This is a proposed **new** repository, not a folder or replacement of the existing detection project.
