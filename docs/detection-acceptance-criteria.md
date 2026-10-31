# Detection acceptance criteria — offline and operational

This is a **review checklist**, not a claim of new live validation. Existing historical 5/5 operational evidence is recorded in [operational-validation.md](operational-validation.md). Passing offline tests alone **never** proves end-to-end detection, Wazuh Dashboard indexing, or production readiness.

## General acceptance gates

1. Catalog entry and rule XML agree on ID, severity, ATT&CK technique, source, owner, test fixtures and rollback.
2. `python scripts/quality_gate.py` and the complete offline unittest suite pass without network access.
3. Positive fixture matches exactly the expected rule; benign fixture does not match it. The Manager replay validates rule logic, **not** live EventChannel behavior.
4. An explicitly authorized benign scenario produces a **local Sysmon event** after the recorded start time.
5. Wazuh `alerts.json` contains the expected rule ID and level, the expected agent ID, and a unique marker from that run.
6. The endpoint reports verified cleanup (or legitimately `not_needed`), with no residual artifacts. Unknown states block approval and require manual inspection.
7. Evidence is sanitized for publication; raw logs, internal addresses, usernames, access tokens and credentials stay in ignored `.lab/`.
8. Dashboard indexing is a **separate gate**: do not claim it based solely on `alerts.json`.

| Scenario | Wazuh rule | ATT&CK | Required endpoint telemetry | Benign test and cleanup | Typical false-positive/tuning review |
| --- | --- | --- | --- | --- | --- |
| PowerShell EncodedCommand | `110100` | `T1059.001` | Sysmon Event ID 1, matching encoded command marker | Prints fixed test marker; no lasting artifact | Approved deployment scripts, endpoint management tooling |
| Rundll32 writable path | `110110` | `T1218.011` | Sysmon Event ID 1, command line with unique nonexistent DLL path | No DLL created or loaded; terminate test child if needed | Authorized application installers using writable directories |
| Scheduled task creation | `110120` | `T1053.005` | Sysmon Event ID 1, `schtasks` invocation marker | One disposable task, never executed; remove and confirm absence | Legitimate scheduled maintenance, software updates |
| Run Key modification | `110130` | `T1547.001` | Sysmon Event ID 13, registry target and unique marker | HKCU Run value removed and independently checked | Authorized autostart configuration; validate live `windows_eventchannel` chain, including `92300` |
| Local account create attempt | `110140` | `T1136.001` | Sysmon Event ID 1, `net user` command line with unique account marker | Disabled temporary account; duplicate-create attempt; remove and independently confirm | IT provisioning scripts; command-line attempt **does not** prove account creation succeeded |

## Interpretation

- `detected`: endpoint succeeded, required cleanup and telemetry present, Manager evidence matches rule, agent, marker and configured severity.
- `telemetry_missing`, `alert_missing`, `severity_mismatch`, `cleanup_unverified`, `execution_failed` or `evidence_unavailable`: do not promote to operationally validated.
- A truncated `alerts.json` scan or a dashboard search mismatch requires separate investigation; do not infer the event never occurred.
- Record the timestamp and Git commit of every **new** live validation separately from the historic five successful detections.
