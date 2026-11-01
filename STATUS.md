# Project status — 2026-11-01

**Stage:** Phase 3 offline engineering integrated into `main`; **live operational evidence partially collected**. The historical five-rule Wazuh Manager detections are documented, but **same-event Manager → Indexer → Dashboard acceptance for all five rules is not established**.

**New verified operational observations:** [Remote lab inspection, historical preservation and current pipeline correlation — 01/11/2026](docs/phase3-real-observations-20261101.md). **Comprehensive technical case study:** [Wazuh Detection Engineering](docs/case-study-wazuh-detection-engineering.md).

| Workstream | Status | Evidence |
| --- | --- | --- |
| Five Wazuh detection rules | Historical Manager detections documented; `110100` not found in inspected 27–30/10 archives | [Operational journal](docs/operational-validation.md) |
| Offline Phase 3 quality gate | Completed/merged; prior synthetic CI passing, not live SIEM verification | [Engineering journal](docs/phase3-engineering-journal.md) |
| Wazuh Dashboard administrative access | Recovered and observed by operator on 01/11; Indexer admin authentication HTTP 200 | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Historical Manager alerts 27–30/10 | **9 real alerts**, 4 rule IDs, read from preserved archives; evidence manifest private | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Historical Indexer correlation, those 9 alerts | **Not found**: missing indexes for 27–30/10 and 0 hits for five rule IDs in `wazuh-alerts-*` | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Current Manager → Indexer same-event correlation | **40/40 exact matches** on pre-existing 01/11 events, comparing event ID, rule, agent and timestamp | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Same-event Dashboard confirmation, generic real alert | **Confirmed for one rule `5502` event** on 01/11/2026; exact ID, rule, agent and timestamp verified with original Manager event and Dashboard Discover; **not one of the five custom rules** | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Five-rule end-to-end acceptance | **Not established** | [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) |

**Next action:** see the [read-only investigation of the 27–30/10 indexing gap](docs/phase3-indexing-gap-investigation.md). Docker network/DNS incidents were observed but do **not** establish root cause; current Indexer health is green, currently configured ISM policy count is zero, five custom rule XML files are present and `wazuh-analysisd -t` passes. Preserve originals and agree on a controlled acceptance plan, rather than inventing a historical PASS. One real recent alert of rule `5502` has been matched between Manager and Dashboard Discover, confirming generic end-to-end visibility, **not** the five custom rule validations. Any historical replay requires a separate approved decision and clear labeling as post-hoc reindexing, **not contemporaneous ingestion**.

**After this:** build a separate `incident-response-soar-lab` repository for deterministic case triage, audit trails, human-approved response playbooks and dry-run SOAR. See [closeout and next-project plan](docs/phase3-closeout-and-next-project.md).

**Important:** code quality CI and simulated test cases are not operational SIEM evidence. The current 40/40 observation proves only the Manager → Indexer leg for that recent sample. A separate real `5502` event is visually correlated in Discover, but five-rule end-to-end acceptance remains unestablished.
