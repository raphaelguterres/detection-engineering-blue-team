# Project status — 2026-11-01

**Stage:** Phase 3 offline engineering integrated into `main`; **live operational evidence partially collected**. The historical five-rule Wazuh Manager detections are documented, but **same-event Manager → Indexer → Dashboard acceptance for all five rules is not established**.

**New five-rule controlled retest:** [Actual Windows Server Sysmon tests and Manager/Indexer outcomes — 01/11/2026](docs/phase3-live-retest-20261101.md). **Earlier operational observations:** [Remote lab inspection, historical preservation and current pipeline correlation — 01/11/2026](docs/phase3-real-observations-20261101.md). **Comprehensive technical case study:** [Wazuh Detection Engineering](docs/case-study-wazuh-detection-engineering.md).

| Workstream | Status | Evidence |
| --- | --- | --- |
| Five Wazuh detection rules | Historical Manager detections documented; `110100` not found in inspected 27–30/10 archives | [Operational journal](docs/operational-validation.md) |
| Offline Phase 3 quality gate | Completed/merged; prior synthetic CI passing, not live SIEM verification | [Engineering journal](docs/phase3-engineering-journal.md) |
| Wazuh Dashboard administrative access | Recovered and observed by operator on 01/11; Indexer admin authentication HTTP 200 | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Historical Manager alerts 27–30/10 | **9 real alerts**, 4 rule IDs, read from preserved archives; evidence manifest private | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Historical Indexer correlation, those 9 alerts | **Not found**: missing indexes for 27–30/10 and 0 hits for five rule IDs in `wazuh-alerts-*` | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Current Manager → Indexer same-event correlation | **40/40 exact matches** on pre-existing 01/11 events, comparing event ID, rule, agent and timestamp | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Same-event Dashboard confirmation, generic real alert | **Confirmed for one rule `5502` event** on 01/11/2026; exact ID, rule, agent and timestamp verified with original Manager event and Dashboard Discover; **not one of the five custom rules** | [Operational observations](docs/phase3-real-observations-20261101.md) |
| Five benign scenarios on Windows Server | **5/5 local Sysmon evidence; cleanup independently verified (zero test artifacts remaining)** | [New retest report](docs/phase3-live-retest-20261101.md) |
| Five custom rules, current Manager → Indexer | **2/5 custom rule IDs correlated**: `110130` (1) and `110140` (2). `110100` produced native `92057`, `110110` and `110120` had no matching custom alert | [New retest report](docs/phase3-live-retest-20261101.md) |
| Three-rule fix in current Wazuh 4.14.9 Manager | **Deployed on 01/11/2026** with private verified backup; isolated regression **11/11 PASS**; three benign Windows Server scenarios **LOCAL_OK=True**. Live Manager→Indexer→Dashboard same-event correlation **not yet checked after deployment** because remote audit access was blocked | [Deployment notes, Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) |
| Five-rule end-to-end acceptance | **Not established; 0/5 custom rules visually confirmed in Dashboard in this retest** | [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) |

**Next action:** the three Sysmon rule-chain changes are already **deployed** to the lab Manager with private rollback backup. Do **not** repeat the Windows simulations merely because the remote alert inspection was blocked. When an authorized SIEM evidence path is available, correlate the **new, post-deploy** custom rule alerts in Manager → Indexer → Dashboard by identical event ID/rule/agent/timestamp, and check negative controls. If a real regression is observed, apply the preserved rollback. This is **not** 5/5 operational acceptance. The [27–30/10 historical indexing gap](docs/phase3-indexing-gap-investigation.md) remains a **separate, unresolved forensic issue**, with no proven root cause. No historical replay or new Wazuh configuration change occurred during this retest.

**After this:** build a separate `incident-response-soar-lab` repository for deterministic case triage, audit trails, human-approved response playbooks and dry-run SOAR. See [closeout and next-project plan](docs/phase3-closeout-and-next-project.md).

**Important:** code quality CI and simulated test cases are not operational SIEM evidence. The current 40/40 observation proves only the Manager → Indexer leg for that recent sample. A separate real `5502` event is visually correlated in Discover, but five-rule end-to-end acceptance remains unestablished.
