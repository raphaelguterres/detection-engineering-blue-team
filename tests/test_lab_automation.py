"""Offline failure-path tests. These never connect to or modify the lab."""
import importlib.util
import json
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/lab' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


runner = module('lab_runner', 'run.py')
manager = module('lab_manager', 'manager-worker.py')


class RunnerTests(unittest.TestCase):
    def test_no_success_without_endpoint_telemetry(self):
        endpoint = {'ok': True, 'cleanup': 'verified', 'local_events': 0}
        evidence = {'ok': True, 'counts': {'110130': 1}}
        self.assertEqual(runner.outcome(endpoint, evidence, 110130), 'telemetry_missing')

    def test_no_success_when_cleanup_unverified(self):
        self.assertEqual(runner.outcome({'ok': True, 'cleanup': 'failed', 'local_events': 1},
                                       {'ok': True, 'counts': {'110130': 1}}, 110130), 'cleanup_unverified')

    def test_other_rule_does_not_count(self):
        self.assertEqual(runner.outcome({'ok': True, 'cleanup': 'verified', 'local_events': 1},
                                       {'ok': True, 'counts': {'110100': 1}}, 110130), 'alert_missing')

    def test_verified_chain_passes(self):
        self.assertEqual(runner.outcome({'ok': True, 'cleanup': 'verified', 'local_events': 1},
                                       {'ok': True, 'counts': {'110130': 1}}, 110130), 'detected')

    def test_severity_must_match_versioned_rule(self):
        self.assertEqual(runner.outcome({'ok': True, 'cleanup': 'verified', 'local_events': 1},
                                       {'ok': True, 'counts': {'110130': 1}, 'levels': {'110130': 3}},
                                       110130, 12), 'severity_mismatch')

    def test_pipeline_stops_before_simulation_when_auth_fails(self):
        args = SimpleNamespace(action='pipeline', config=Path('unused'))
        with patch.object(runner, 'journal_report'), \
                patch.object(runner, 'manager_call', return_value={'ok': False}) as manager_call, \
                patch.object(runner, 'windows_call', return_value={'ok': False}) as windows_call:
            report = runner.execute(args, {}, 'DE-0123456789abcdef')
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(manager_call.call_count, 1)
        self.assertEqual(windows_call.call_args.args[1], 'probe')

    def test_pipeline_rolls_back_failed_regression_without_running_windows_test(self):
        args = SimpleNamespace(action='pipeline', config=Path('unused'))
        ready = {'ok': True, 'rules_present': {str(i): 1 for i in runner.SCENARIOS.values()}}
        with patch.object(runner, 'journal_report'), \
                patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                patch.object(runner, 'manager_call', side_effect=[ready, {'ok': True}, ready, {'ok': False}, {'ok': True}]) as manager_call, \
                patch.object(runner, 'windows_call', return_value={'ok': True}) as windows_call:
            report = runner.execute(args, {}, 'DE-0123456789abcdef')
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(manager_call.call_args.args[1], 'rollback')
        self.assertEqual(windows_call.call_count, 1)

    def test_template_cannot_connect(self):
        with self.assertRaises(ValueError):
            runner.load_config(ROOT / 'scripts/lab/config.example.json')

    def test_shell_metacharacters_rejected(self):
        data = json.loads((ROOT / 'scripts/lab/config.example.json').read_text())
        data['manager'] = {'ssh_target': 'lab;whoami', 'container': 'manager', 'python': '/python', 'agent_id': '005'}
        data['windows'].update(computer_name='endpoint', expected_hostname='endpoint')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                runner.load_config(path)

    def test_ssh_is_noninteractive_and_strict(self):
        config = {'manager': {'ssh_target': 'lab', 'container': 'manager', 'python': '/python'}}
        with patch.object(runner, 'run_json', return_value={'ok': True}) as call:
            runner.manager_call(config, 'probe', 'DE-0123456789abcdef')
        args = call.call_args.args[0]
        self.assertIn('BatchMode=yes', args)
        self.assertIn('StrictHostKeyChecking=yes', args)

    def test_transport_timeout_does_not_claim_rollback(self):
        with patch.object(runner.subprocess, 'run', side_effect=runner.subprocess.TimeoutExpired('ssh', 1)):
            result = runner.run_json(['ssh'])
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'REMOTE_TIMEOUT_STATE_UNKNOWN')


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.rules = self.root / 'etc/rules'
        self.rules.mkdir(parents=True)
        self.root_patch = patch.object(manager, 'ROOT', self.root)
        self.rules_patch = patch.object(manager, 'RULES', self.rules)
        self.backup_patch = patch.object(manager, 'BACKUPS', self.root / 'backup')
        self.root_patch.start(); self.rules_patch.start(); self.backup_patch.start()

    def tearDown(self):
        self.root_patch.stop(); self.rules_patch.stop(); self.backup_patch.stop()
        self.temp.cleanup()

    def test_path_traversal_blocked(self):
        with self.assertRaises(RuntimeError):
            manager.safe_target('../../outside.xml')

    def test_rollback_preserves_external_change(self):
        target = self.rules / 'rule.xml'
        target.write_text('external edit')
        with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_CONFLICT'):
            manager.restore([{'name': target.name, 'new_sha256': manager.digest(b'original')}])
        self.assertEqual(target.read_text(), 'external edit')

    def test_duplicate_rule_deploy_rejected_before_write(self):
        for name in ('first.xml', 'second.xml'):
            (self.rules / name).write_text('<group><rule id="110100" /></group>')
        request = {'run_id': 'DE-0123456789abcdef', 'rules': [
            {'id': rid, 'xml': f'<group><rule id="{rid}" /></group>'} for rid in sorted(manager.IDS)]}
        with patch.object(manager, 'validate_rules'), self.assertRaisesRegex(RuntimeError, 'DUPLICATE'):
            manager.deploy(request)
        self.assertEqual(len(list(self.rules.glob('*.xml'))), 2)

    def test_failed_deploy_restores_original_rules(self):
        path = self.rules / 'old.xml'
        original = '<group><rule id="110100" level="1" /></group>'
        path.write_text(original)
        request = {'run_id': 'DE-0123456789abcdef', 'rules': [
            {'id': rid, 'xml': f'<group><rule id="{rid}" level="12" /></group>'} for rid in sorted(manager.IDS)]}
        with patch.object(manager, 'validate_rules', side_effect=[None, RuntimeError('BAD_RULE'), None]), \
                patch.object(manager, 'restart'), patch.object(manager.os, 'chown', create=True):
            result = manager.deploy(request)
        self.assertEqual(result['error'], 'DEPLOY_FAILED_ROLLED_BACK')
        self.assertEqual(path.read_text(), original)
        self.assertEqual(list(self.rules.glob('*.xml')), [path])

    def test_evidence_requires_agent_and_current_marker(self):
        logs = self.root / 'logs/alerts'
        logs.mkdir(parents=True)
        def event(agent, marker):
            return {'agent': {'id': agent}, 'rule': {'id': '110130', 'level': 12},
                    'data': {'win': {'eventdata': {'targetObject': marker}}}}
        events = [event('005', 'OLD'), event('999', 'DE-CURRENT'), event('005', 'DE-CURRENT')]
        (logs / 'alerts.json').write_text('\n'.join(json.dumps(e) for e in events) + '\n')
        result = manager.evidence({'agent_id': '005', 'marker': 'DE-CURRENT'})
        self.assertEqual(result['counts']['110130'], 1)

    def test_parent_command_line_does_not_count(self):
        logs = self.root / 'logs/alerts'
        logs.mkdir(parents=True)
        event = {'agent': {'id': '005'}, 'rule': {'id': '110100'},
                 'data': {'win': {'eventdata': {'parentCommandLine': 'MARKER', 'commandLine': 'other'}}}}
        (logs / 'alerts.json').write_text(json.dumps(event))
        self.assertEqual(manager.evidence({'agent_id': '005', 'marker': 'MARKER'})['counts']['110100'], 0)

    def test_decoder_failure_cannot_pass_negative_regression(self):
        request = {'fixtures': [{'rule_id': 110100, 'cases': [
            {'name': 'negative', 'event': {}, 'expected_alert': False}]}]}
        process = SimpleNamespace(returncode=0, stdout='**Phase 2: Completed decoding.\nNo decoder matched.', stderr='')
        with patch.object(manager.subprocess, 'run', return_value=process):
            self.assertFalse(manager.replay(request)['ok'])


if __name__ == '__main__':
    unittest.main()
