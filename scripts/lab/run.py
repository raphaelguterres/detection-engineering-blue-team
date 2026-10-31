"""Lab automation: plan, preflight, deploy, replay, run and explicit recovery.

Uses OpenSSH for Kali/Docker and Windows PowerShell WinRM for the endpoint.
No external Python packages; no prompts or credentials in process arguments.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCENARIOS = {'powershell': 110100, 'rundll32': 110110, 'schtasks': 110120, 'runkey': 110130, 'localaccount': 110140}


def load_config(path, require_windows=True):
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if data.get('isolated_lab') is not True:
        raise ValueError('isolated_lab must be true')
    if 'REPLACE_' in json.dumps(data):
        raise ValueError('configure the local inventory before connecting')
    manager, windows = data['manager'], data.get('windows')
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]*', manager['ssh_target']):
        raise ValueError('invalid SSH target')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', manager['container']):
        raise ValueError('invalid container name')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', manager['python']):
        raise ValueError('invalid container Python path')
    if not re.fullmatch(r'\d{3,}', manager['agent_id']):
        raise ValueError('invalid Wazuh agent ID')
    for field in ('identity_file', 'known_hosts_file'):
        if field in manager:
            candidate = (ROOT / manager[field]).resolve()
            if not candidate.is_relative_to(ROOT / '.lab') or not candidate.is_file():
                raise ValueError(f'{field} must reference an existing file under .lab')
            manager[field] = str(candidate)
    if require_windows:
        if not isinstance(windows, dict):
            raise ValueError('Windows inventory is required for this action')
        for field in ('computer_name', 'expected_hostname'):
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', windows[field]):
                raise ValueError('invalid Windows identity')
        if windows.get('authentication') not in ('Negotiate', 'Kerberos'):
            raise ValueError('only Negotiate/Kerberos authentication is supported')
        if not isinstance(windows.get('use_ssl'), bool):
            raise ValueError('use_ssl must be a boolean')
    alert_timeout = data.get('alert_timeout_seconds', 60)
    if type(alert_timeout) is not int or not 5 <= alert_timeout <= 300:
        raise ValueError('alert timeout must be an integer between 5 and 300 seconds')
    return data


def run_json(args, *, payload=None, timeout=120):
    try:
        proc = subprocess.run(args, input=payload, text=True, encoding='utf-8', errors='replace',
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'REMOTE_TIMEOUT_STATE_UNKNOWN'}
    except OSError:
        return {'ok': False, 'error': 'TRANSPORT_UNAVAILABLE'}
    try:
        result = json.loads(proc.stdout.strip().lstrip('\ufeff'))
        if not isinstance(result, dict):
            raise ValueError('expected object')
        if proc.returncode and result.get('ok'):
            return {'ok': False, 'error': 'TRANSPORT_NONZERO_EXIT'}
        return result
    except ValueError:
        # Deliberately omit raw stderr: it may contain environment identifiers.
        return {'ok': False, 'error': 'TRANSPORT_OR_AUTH_FAILED', 'exit_code': proc.returncode}


def manager_call(config, action, run_id, **fields):
    m = config['manager']
    script = (HERE / 'manager-worker.py').read_text(encoding='utf-8')
    remote = shlex.join(['docker', 'exec', '-i', m['container'], m['python'], '-c', script])
    args = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
            '-o', 'IdentitiesOnly=yes']
    if m.get('identity_file'):
        args.extend(['-i', m['identity_file']])
    if m.get('known_hosts_file'):
        args.extend(['-o', f"UserKnownHostsFile={m['known_hosts_file']}"])
    args.extend([m['ssh_target'], remote])
    return run_json(args, payload=json.dumps({'action': action, 'run_id': run_id, **fields}), timeout=240)


def windows_call(config_path, action, run_id, scenario='powershell'):
    executable = shutil.which('powershell.exe')
    if not executable:
        return {'ok': False, 'error': 'WINDOWS_POWERSHELL_REQUIRED'}
    return run_json([executable, '-NoProfile', '-NonInteractive', '-File', str(HERE / 'windows-bridge.ps1'),
                     '-ConfigPath', str(config_path), '-Action', action, '-RunId', run_id, '-Scenario', scenario])


def outcome(endpoint, evidence, rule_id, expected_level=None):
    if not endpoint.get('ok'):
        return 'execution_failed'
    if endpoint.get('cleanup') not in ('verified', 'not_needed'):
        return 'cleanup_unverified'
    if not endpoint.get('local_events', 0):
        return 'telemetry_missing'
    if not evidence.get('ok'):
        return 'evidence_unavailable'
    if evidence.get('counts', {}).get(str(rule_id), 0) < 1:
        return 'alert_missing'
    if expected_level is not None and evidence.get('levels', {}).get(str(rule_id)) != expected_level:
        return 'severity_mismatch'
    return 'detected'


def journal_report(report):
    directory = ROOT / '.lab/journal' / report['run_id']
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / 'report.tmp'
    temporary.write_text(json.dumps(report, indent=2), encoding='utf-8')
    temporary.replace(directory / 'report.json')


def save_report(report):
    directory = ROOT / '.lab/runs' / report['run_id']
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    rows = ['# Lab run', '', f"Action: `{report['action']}`", f"Result: `{report['status']}`", '',
            '| Scenario | Result | Cleanup |', '| --- | --- | --- |']
    for test in report.get('scenarios', []):
        rows.append(f"| {test['scenario']} | {test['status']} | {test['endpoint'].get('cleanup', 'unknown')} |")
    (directory / 'report.md').write_text('\n'.join(rows) + '\n', encoding='utf-8')
    return directory


def execute(args, config, run_id):
    report = {'run_id': run_id, 'action': args.action, 'status': 'failed', 'scenarios': []}
    journal_report(report)
    if args.action == 'cleanup':
        if not args.recovery_id or not args.scenario:
            raise ValueError('cleanup requires --recovery-id and --scenario')
        # Only recover a recorded invocation, preventing deletion by an arbitrary name.
        record = ROOT / '.lab/runs' / args.recovery_id / 'report.json'
        if not record.exists():
            record = ROOT / '.lab/journal' / args.recovery_id / 'report.json'
        previous = json.loads(record.read_text())
        test = next((x for x in previous['scenarios'] if x['scenario'] == args.scenario), None)
        if (not test or test.get('endpoint', {}).get('error') == 'ARTIFACT_COLLISION'
                or not re.fullmatch(r'DE-[a-f0-9]{16}', test.get('run_id', ''))):
            raise ValueError('no recoverable scenario recorded')
        result = windows_call(args.config, 'cleanup', test['run_id'], args.scenario)
        report['recovery'] = result
        report['status'] = 'passed' if result.get('ok') else 'failed'
        return report
    if args.action == 'rollback':
        if not args.backup_id:
            raise ValueError('rollback requires --backup-id')
        result = manager_call(config, 'rollback', run_id, backup_id=args.backup_id)
        report['manager'] = result
        report['status'] = 'passed' if result.get('ok') else 'failed'
        return report
    report['manager'] = manager_call(config, 'probe', run_id)
    if args.action in ('preflight', 'run', 'pipeline'):
        report['windows'] = windows_call(args.config, 'probe', run_id)
    if not report['manager'].get('ok') or ('windows' in report and not report['windows'].get('ok')):
        report['status'] = 'blocked'
        return report
    if args.action == 'preflight':
        report['status'] = 'passed'
        return report
    if args.action in ('deploy', 'pipeline'):
        gate = subprocess.run([sys.executable, str(ROOT / 'scripts/quality_gate.py')], capture_output=True)
        if gate.returncode:
            report['error'] = 'QUALITY_GATE_FAILED'
            return report
        rules = [{'id': int(path.name.split('-')[0]), 'xml': path.read_text(encoding='utf-8')}
                 for path in sorted((ROOT / 'rules/windows').glob('*.xml'))]
        report['deployment'] = manager_call(config, 'deploy', run_id, rules=rules)
        report['status'] = 'passed' if report['deployment'].get('ok') else 'failed'
        journal_report(report)
        if args.action == 'deploy' or report['status'] != 'passed':
            return report
        report['manager'] = manager_call(config, 'probe', run_id)
        if not report['manager'].get('ok'):
            report['status'] = 'failed'
            return report
    if any(report['manager']['rules_present'].get(str(i)) != 1 for i in SCENARIOS.values()):
        report['error'] = 'MISSING_OR_DUPLICATE_RULES'
        report['status'] = 'blocked'
        return report
    if args.action in ('replay', 'pipeline'):
        fixtures = [json.loads(p.read_text()) for p in sorted((ROOT / 'tests/fixtures').glob('*.json'))]
        report['regression'] = manager_call(config, 'replay', run_id, fixtures=fixtures)
        report['status'] = 'passed' if report['regression'].get('ok') else 'failed'
        if args.action == 'pipeline' and report['status'] == 'failed':
            report['rollback'] = manager_call(config, 'rollback', run_id, backup_id=run_id)
        journal_report(report)
        if args.action == 'replay' or report['status'] != 'passed':
            return report
    selected = [args.scenario] if args.scenario else list(SCENARIOS)
    if 'localaccount' in selected and not args.include_account:
        selected.remove('localaccount')
        report['skipped'] = {'localaccount': 'requires --include-account'}
    report['status'] = 'running'
    for scenario in selected:
        test_id = 'DE-' + uuid.uuid4().hex[:16]
        test = {'scenario': scenario, 'rule_id': SCENARIOS[scenario], 'run_id': test_id,
                'status': 'running', 'endpoint': {'cleanup': 'unknown'}}
        report['scenarios'].append(test)
        # Persist intent before remote mutation, so an interrupted invocation can be recovered.
        journal_report(report)
        endpoint = windows_call(args.config, 'run', test_id, scenario)
        test['endpoint'] = {k: v for k, v in endpoint.items() if k != 'marker'}
        evidence = {'ok': False}
        if endpoint.get('ok') and endpoint.get('marker'):
            deadline = time.monotonic() + config.get('alert_timeout_seconds', 60)
            while True:
                evidence = manager_call(config, 'evidence', test_id, marker=endpoint['marker'], agent_id=config['manager']['agent_id'])
                if not evidence.get('ok') or evidence.get('counts', {}).get(str(test['rule_id']), 0) or time.monotonic() >= deadline:
                    break
                time.sleep(3)
        test['evidence'] = evidence
        rule_file = next((ROOT / 'rules/windows').glob(f"{test['rule_id']}-*.xml"))
        expected_level = int(ET.parse(rule_file).find('.//rule').get('level'))
        test['status'] = outcome(endpoint, evidence, test['rule_id'], expected_level)
        journal_report(report)
        print(f"{scenario}: {test['status']}", flush=True)
        if not endpoint.get('ok') or endpoint.get('cleanup') not in ('verified', 'not_needed'):
            break
    report['status'] = 'passed' if report['scenarios'] and all(t['status'] == 'detected' for t in report['scenarios']) else 'failed'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=('plan', 'preflight', 'deploy', 'replay', 'run', 'pipeline', 'rollback', 'cleanup'))
    parser.add_argument('--config', type=Path, default=ROOT / '.lab/config.json')
    parser.add_argument('--scenario', choices=SCENARIOS)
    parser.add_argument('--include-account', action='store_true', help='include temporary disabled local account creation')
    parser.add_argument('--backup-id')
    parser.add_argument('--recovery-id')
    args = parser.parse_args()
    if args.action == 'plan':
        print(json.dumps({'mode': 'plan', 'remote_execution': False, 'steps': ['preflight', 'deploy', 'replay', 'run'],
                          'scenarios': SCENARIOS, 'account_default': 'skipped', 'report_directory': '.lab/runs'}, indent=2))
        return 0
    for value in (args.backup_id, args.recovery_id):
        if value and not re.fullmatch(r'DE-[a-f0-9]{16}', value):
            parser.error('invalid recovery/backup ID')
    run_id = 'DE-' + uuid.uuid4().hex[:16]
    try:
        args.config = args.config.resolve()
        config = load_config(args.config, require_windows=args.action in ('preflight', 'run', 'pipeline', 'cleanup'))
        report = execute(args, config, run_id)
    except (OSError, ValueError, KeyError) as exc:
        print(f'BLOCKED: configuration or local state invalid ({type(exc).__name__}); see docs/lab-automation.md')
        return 2
    directory = save_report(report)
    print(f"{report['status'].upper()}: {directory / 'report.json'}")
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    sys.exit(main())
