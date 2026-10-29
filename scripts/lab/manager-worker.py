"""Executed inside the Wazuh container over authenticated SSH; JSON in/out only."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path('/var/ossec')
RULES = ROOT / 'etc/rules'
BACKUPS = ROOT / 'backup/detection-engineering'
IDS = {110100, 110110, 110120, 110130, 110140}


def command(*args, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    text = result.stdout + result.stderr
    if result.returncode or re.search(r'(?i)error|invalid|will be ignored|duplicat', text):
        raise RuntimeError('MANAGER_COMMAND_FAILED')
    return text


def validate_rules():
    command(str(ROOT / 'bin/wazuh-analysisd'), '-t')


def restart():
    command(str(ROOT / 'bin/wazuh-control'), 'restart', timeout=90)
    status = command(str(ROOT / 'bin/wazuh-control'), 'status')
    if 'wazuh-analysisd is running' not in status:
        raise RuntimeError('ANALYSISD_NOT_RUNNING')


def rule_ids(text):
    return {int(x) for x in re.findall(r'<rule\s+[^>]*\bid=["\'](\d+)["\']', text)}


def digest(content):
    return hashlib.sha256(content).hexdigest()


def inventory():
    found = {str(i): [] for i in IDS}
    for path in RULES.rglob('*.xml'):
        for rule in rule_ids(path.read_text(errors='replace')) & IDS:
            found[str(rule)].append(path.relative_to(RULES).as_posix())
    return found


def safe_target(name):
    original = RULES / name
    path = original.resolve()
    if not path.is_relative_to(RULES.resolve()) or path.suffix != '.xml' or original.is_symlink():
        raise RuntimeError('INVALID_RULE_PATH')
    return path


def atomic_write(path, content, mode=0o640):
    temp = path.with_name(path.name + '.de-tmp')
    # Exclusive creation prevents overwriting another operation's temporary file.
    with temp.open('xb') as stream:
        os.chmod(temp, mode)
        stream.write(content)
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def restore(entries, check_drift=True):
    # Check all paths before the first mutation.
    for entry in entries:
        target = safe_target(entry['name'])
        if check_drift and (not target.exists() or digest(target.read_bytes()) != entry['new_sha256']):
            raise RuntimeError('ROLLBACK_CONFLICT_EXTERNAL_CHANGE')
    for entry in entries:
        target = safe_target(entry['name'])
        if entry['old_b64'] is None:
            target.unlink(missing_ok=True)
        else:
            atomic_write(target, base64.b64decode(entry['old_b64']), entry['mode'])
            os.chown(target, entry['uid'], entry['gid'])
    validate_rules()
    restart()


def deploy(request):
    validate_rules()
    files = request['rules']
    if {int(f['id']) for f in files} != IDS or len(files) != len(IDS):
        raise RuntimeError('RULE_SET_INCOMPLETE')
    existing = inventory()
    entries = []
    for item in files:
        rid = int(item['id'])
        if rule_ids(item['xml']) != {rid}:
            raise RuntimeError('INVALID_RULE_CONTENT')
        matches = existing[str(rid)]
        if len(matches) > 1:
            raise RuntimeError('DUPLICATE_RULE_ID')
        name = matches[0] if matches else f'detection-engineering-{rid}.xml'
        target = safe_target(name)
        old = target.read_bytes() if target.exists() else None
        if old is not None and rule_ids(old.decode()) != {rid}:
            raise RuntimeError('SHARED_RULE_FILE_REQUIRES_REVIEW')
        stat = target.stat() if target.exists() else RULES.stat()
        new = item['xml'].encode()
        entries.append(dict(name=name, old_b64=base64.b64encode(old).decode() if old is not None else None,
                            new_sha256=digest(new), mode=(stat.st_mode & 0o777) if old is not None else 0o640,
                            uid=stat.st_uid, gid=stat.st_gid, new_b64=base64.b64encode(new).decode()))
    backup = BACKUPS / request['run_id']
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = backup / 'manifest.json'
    manifest.write_text(json.dumps(entries))
    os.chmod(manifest, 0o600)
    written = []
    try:
        for entry in entries:
            target = safe_target(entry['name'])
            atomic_write(target, base64.b64decode(entry['new_b64']), entry['mode'])
            written.append(entry)
            os.chown(target, entry['uid'], entry['gid'])
        validate_rules()
        restart()
    except Exception:
        try:
            restore(written)
            (backup / 'restored').touch(mode=0o600)
        except Exception:
            return {'ok': False, 'error': 'DEPLOY_FAILED_ROLLBACK_UNVERIFIED', 'backup_id': request['run_id']}
        return {'ok': False, 'error': 'DEPLOY_FAILED_ROLLED_BACK', 'backup_id': request['run_id']}
    return {'ok': True, 'backup_id': request['run_id'], 'rules_deployed': len(entries)}


def evidence(request):
    path = ROOT / 'logs/alerts/alerts.json'
    counts = {str(i): 0 for i in IDS}
    levels = {}
    truncated = False
    if path.exists():
        with path.open('rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            offset = max(0, size - 8 * 1024 * 1024)
            stream.seek(offset)
            if offset:
                stream.readline()
                truncated = True
            for line in stream:
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                rid = str(event.get('rule', {}).get('id', ''))
                data = event.get('data', {}).get('win', {}).get('eventdata', {})
                fields = (data.get('commandLine', ''), data.get('targetObject', ''), data.get('details', ''))
                if (rid in counts and str(event.get('agent', {}).get('id')) == request['agent_id']
                        and any(request['marker'] in str(value) for value in fields)):
                    counts[rid] += 1
                    levels[rid] = event['rule'].get('level')
    return {'ok': True, 'counts': counts, 'levels': levels, 'scan_truncated': truncated}


def replay(request):
    results = []
    for fixture in request['fixtures']:
        for case in fixture['cases']:
            event = {}
            for key, value in case['event'].items():
                branch = event
                parts = key.split('.')
                for part in parts[:-1]:
                    branch = branch.setdefault(part, {})
                branch[parts[-1]] = value
            proc = subprocess.run([str(ROOT / 'bin/wazuh-logtest')], input=json.dumps(event) + '\n',
                                  text=True, capture_output=True, timeout=15)
            output = proc.stdout + proc.stderr
            ids = re.findall(r"\bid:\s*'(\d+)'", output)
            matched = int(ids[-1]) if ids else None
            decoded = '**Phase 2:' in output and 'No decoder matched' not in output
            healthy = proc.returncode == 0 and decoded and not re.search(r'(?i)error|invalid|will be ignored', output)
            passed = healthy and ((matched == fixture['rule_id']) == case['expected_alert'])
            results.append({'rule_id': fixture['rule_id'], 'case': case['name'], 'passed': bool(passed), 'matched_rule': matched})
    return {'ok': all(x['passed'] for x in results), 'cases': results}


def handle(request):
    if not re.fullmatch(r'DE-[a-f0-9]{16}', request.get('run_id', '')):
        raise RuntimeError('INVALID_RUN_ID')
    action = request['action']
    if action == 'probe':
        validate_rules()
        status = command(str(ROOT / 'bin/wazuh-control'), 'status')
        return {'ok': 'wazuh-analysisd is running' in status, 'rules_present': {k: len(v) for k, v in inventory().items()},
                'logall_json': re.findall(r'<logall_json>(.*?)</logall_json>', (ROOT / 'etc/ossec.conf').read_text())}
    if action == 'evidence':
        return evidence(request)
    if action == 'replay':
        return replay(request)
    if action not in {'deploy', 'rollback'}:
        raise RuntimeError('UNKNOWN_ACTION')
    lock = ROOT / 'var/run/detection-engineering.lock'
    # No automatic stale-lock deletion; a crashed deploy must be inspected first.
    with lock.open('x') as stream:
        stream.write(request['run_id'])
    try:
        if action == 'deploy':
            return deploy(request)
        backup_id = request['backup_id']
        if not re.fullmatch(r'DE-[a-f0-9]{16}', backup_id):
            raise RuntimeError('INVALID_BACKUP_ID')
        backup = BACKUPS / backup_id
        if (backup / 'restored').exists():
            raise RuntimeError('BACKUP_ALREADY_RESTORED')
        restore(json.loads((backup / 'manifest.json').read_text()))
        (backup / 'restored').touch(mode=0o600)
        return {'ok': True, 'backup_id': backup_id, 'rollback': 'verified'}
    finally:
        lock.unlink()


if __name__ == '__main__':
    try:
        print(json.dumps(handle(json.load(sys.stdin))))
    except Exception as exc:
        message = str(exc)
        code = message if re.fullmatch(r'[A-Z_]+', message) else type(exc).__name__
        print(json.dumps({'ok': False, 'error': code}))
        sys.exit(1)
