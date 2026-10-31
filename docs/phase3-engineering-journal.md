# Phase 3 — Engineering Journal

## 2026-10-31 — Documentation and offline evidence validation

**Scope:** Wazuh Manager → Indexer → Dashboard; no live environment access.

### Completed
- Documented a read-only inspection procedure for historical alerts.
- Specified SOC dashboard panels and MITRE ATT&CK mappings for rules 110100, 110110, 110120, 110130 and 110140.
- Added `scripts/phase3_evidence_gate.py` and `tests/test_phase3_evidence_gate.py` for conservative offline classification.
- Extended GitHub Actions to run the offline evidence tests.
- Verified CI run **#37** was completed with conclusion **success** for commit `e36769e7748a4180e06e4c721b67f79704d204a0`.

### Evidence boundaries
- Historical five-of-five live rule detections are recorded in `docs/operational-validation.md`.
- No new Manager, Indexer or Dashboard inspection was conducted in this work.
- CI validates code contracts, not SIEM delivery, indexing, UI visibility or live service health.
- CodeRabbit displayed the draft-review notice; a full review of this PR is not yet confirmed.
- No credentials, raw logs or production identifiers were accessed or published.

### Open items
1. Verify the latest commit's GitHub Actions conclusion after new documentation is added.
2. Review PR #2 and request a code review before merging.
3. In the authorized lab, collect aggregate historical evidence for Manager and Indexer with read-only permissions.
4. Confirm Dashboard visibility using matching time window, rule ID, agent ID and event identity.
5. Record each stage as found, missing or unknown; classify each rule as verified, partial, inconclusive or not_tested. Never substitute fixture tests for end-to-end evidence.

### Decision record
- **ADR-003:** Use pre-existing historical alert records, rather than generating additional events for UI verification.
- **ADR-004:** Require same-event correlation across three stages before labeling a detection end-to-end verified.
- **ADR-005:** Keep environment-specific output in ignored `.lab/` and publish sanitized summaries only.

### Change discipline
Each future PR should include its objective, risk, tests, observed outcomes, rollback considerations and an explicit statement of what was not tested.

### CodeRabbit review remediation — 2026-10-31
- Correct stage-versus-result terminology, explicit JSON filename and exact detection ID filters.
- Require same-event correlation in the PASS decision matrix and document unlisted stage combinations.
- Distinguish not-tested cases from attempted-but-inconclusive evidence, with offline regression tests.
- Validation: CI results must be verified for the remediation commit before merge; no VM interaction occurred.

## 2026-10-31 — Phase 3B: historical identity correlation

- PR #2 merged into `main` at `e4cdbc7f473fa99fae5e60061f577a25caf87a75` following CI #44 success and resolution of all six CodeRabbit threads.
- Created separate branch `feature/phase3-historical-alert-correlation` for offline comparison of Manager and Indexer historical JSONL exports.
- Added matching by alert ID + rule ID + agent ID + normalized UTC timestamp, restricted to the five exact detection IDs.
- Added synthetic unit tests, CI Python compilation check, read-only usage guide, input size limits and privacy protections.
- No lab connection, credential access, new alert generation or production/dashboard verification is claimed.
- CodeRabbit review on PR #3 found a **major false-positive risk** if the two inputs refer to the same underlying file. The comparator now rejects self-comparison via `Path.samefile`, and two offline tests cover identical paths and hardlink aliases.
- Recheck new CI before merging; path identity checks do not substitute for operator verification of independent export provenance (copied files may still contain duplicated records).
- **Pending:** verify the remediation CI, resolve review findings, then collect authorized historical exports privately and correlate the same event in Dashboard before marking any end-to-end detection verified.

## 2026-10-31 — Phase 3C: sanitized operator handoff

- PR #3 was merged with squash commit `a9e41b28e3bcd44399c929c05bb9d43d471054d6` after CI #49 passed and CodeRabbit's Major self-comparison finding was corrected and resolved.
- Created `scripts/phase3_prepare_observations.py` to convert private aggregate comparison data into conservative structured evidence drafts: Manager/Indexer found only for positive counts, zero means unknown, Dashboard always unknown, and same_event_verified stays false.
- Added synthetic tests, CI coverage and `docs/phase3-evidence-handoff.md` with an operator-owned path for independent Dashboard validation.
- This update involved **no live laboratory inspection**, no credentials and no new simulated events. End-to-end Manager → Indexer → Dashboard verification remains pending in Issue #4.

### PR #5 — CodeRabbit remediation (2026-10-31)

- CodeRabbit found two issues: symlinked `.lab/` roots could redirect derived files outside the ignored tree; a fixed comparison filename could permit stale results to be reused after a failed `Out-File -NoClobber` step.
- The observation tool now rejects a symlinked private root before path resolution, with a synthetic regression test.
- The PowerShell handoff uses unique GUID-based filenames for each comparison/draft pair, verifies the comparator's exit code and save operation, and stops before draft creation on failure.
- CI success for the remediation head must be verified before resolving review threads and merging. Operational SIEM validation remains outstanding under Issue #4.

## 2026-10-31 — Phase 3D: one-command offline workflow

- New branch `feature/phase3-one-command-offline-validation` from the merged Phase 3C `main`.
- Added `scripts/phase3-run-offline.ps1` to execute comparison → private observation draft → evidence gate in one fail-closed workflow with unique GUID-named outputs.
- Added `tests/test_phase3_offline_runner.ps1` for Windows Actions smoke validation using synthetic events only; included parser validation and explicit Python 3.12 setup in the Windows CI job.
- Hardened the existing historical comparator to reject a symlinked `.lab/` root and added a corresponding regression test.
- Added operator documentation for required existing read-only exports, output privacy boundaries and independent Dashboard validation.
- No credentials, Wazuh API calls, simulations, service changes or VM access. CI cannot prove any actual event reached the Indexer or Dashboard.
- **Next gate:** CI + code review before merge; then authorized, local-only review of real historical exports under Issue #4.
