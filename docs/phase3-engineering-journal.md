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
5. Classify each stage as verified, partial or inconclusive; never substitute fixture tests for end-to-end evidence.

### Decision record
- **ADR-003:** Use pre-existing historical alert records, rather than generating additional events for UI verification.
- **ADR-004:** Require same-event correlation across three stages before labeling a detection end-to-end verified.
- **ADR-005:** Keep environment-specific output in ignored `.lab/` and publish sanitized summaries only.

### Change discipline
Each future PR should include its objective, risk, tests, observed outcomes, rollback considerations and an explicit statement of what was not tested.
