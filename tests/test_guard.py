"""Check persistent operation and its stop/target lifecycle without using LD14."""

import importlib.util
import ctypes as c
import json
import os
from pathlib import Path
import tempfile
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

if os.name != 'nt':
    raise unittest.SkipTest('Windows process APIs are required')

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ld14_guard_test', ROOT / 'experimental' / 'ld14-guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
experiment = guard.load_experiment()


class FakeControl:
    def __init__(self, stop_after_waits=None):
        self.stopped = False
        self.waits = 0
        self.stop_after_waits = stop_after_waits

    def is_set(self):
        return self.stopped

    def wait(self, seconds):
        self.waits += 1
        if self.stop_after_waits is not None and self.waits >= self.stop_after_waits:
            self.stopped = True
        return self.stopped


class GuardTests(unittest.TestCase):
    def test_stale_heartbeat_is_unknown_even_when_guard_process_exists(self):
        snapshot = {'state': 'active', 'nvidia_cleanup': True,
                    'time': '2026-09-06T14:02:42+08:00'}
        now = guard.datetime.fromisoformat('2026-09-06T18:00:00+08:00')
        result = guard.status_view(snapshot, True, now)
        self.assertTrue(result['running'])
        self.assertEqual(result['state'], 'unresponsive')
        self.assertIsNone(result['nvidia_cleanup'])
        self.assertEqual(result['last_recorded'], snapshot)

    def test_fresh_heartbeat_preserves_live_status(self):
        snapshot = {'state': 'active', 'nvidia_cleanup': True,
                    'time': '2026-09-06T14:02:42+08:00'}
        now = guard.datetime.fromisoformat('2026-09-06T14:02:50+08:00')
        result = guard.status_view(snapshot, True, now)
        self.assertEqual(result['state'], 'active')
        self.assertTrue(result['nvidia_cleanup'])
        self.assertEqual(result['heartbeat_age_seconds'], 8)

    def test_hidden_controller_records_exception_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            with mock.patch.object(guard, 'DIRECTORY', Path(directory)), \
                 mock.patch.object(guard, 'main', side_effect=RuntimeError('fixture controller failure')), \
                 mock.patch.object(sys, 'argv', ['ld14-guard.py', '--run']), \
                 mock.patch.object(sys, 'stderr', None):
                self.assertEqual(guard.run_cli(), 1)
            log = (Path(directory) / 'controller.log').read_text(encoding='utf-8')
            self.assertIn('LD14-GUARD-CONTROLLER-3', log)
            self.assertIn('RuntimeError: fixture controller failure', log)
            self.assertIn('"exit_code": 1', log)

    def test_status_does_not_report_dead_guard_as_active(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            status_file = Path(directory) / 'status.json'
            snapshot = {'state': 'active', 'nvidia_cleanup': True, 'guard_pid': 123,
                        'time': '2026-09-06T14:02:42+08:00',
                        'sample': {'private_gib': 4.49}}
            status_file.write_text(json.dumps(snapshot), encoding='utf-8')
            with mock.patch.object(guard, 'STATUS', status_file), \
                 mock.patch.object(guard, 'is_running', return_value=False), \
                 mock.patch.object(guard, 'load_experiment') as loader, \
                 mock.patch.object(sys, 'stdout', None):
                loader.return_value.load_existing_helper.return_value.read_config.return_value = {}
                result = guard.main(['--status', '--console', 'C:\\test\\ldconsole.exe', '--index', '1'])
            self.assertFalse(result['running'])
            self.assertEqual(result['state'], 'not_running')
            self.assertFalse(result['nvidia_cleanup'])
            self.assertEqual(result['last_recorded'], snapshot)
            self.assertNotIn('sample', result)

    def run_session_fixture(self, minutes, version='616.64'):
        driver_sha256, profile = next((digest, item) for digest, item in experiment.DRIVERS.items()
                                      if item['version'] == version)
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            directory = Path(directory)
            driver = directory / 'driver.fixture'
            driver.write_bytes(b'fixture')
            fix = mock.Mock()
            fix.backend_pid.return_value = 707
            fix.verify_target.return_value = {'base': 0x100000}
            fix.modules.return_value = {'nvoglv64.dll': {'path': str(driver), 'base': 0}}
            fix.K.OpenProcess.return_value = 1
            fix.inspect_or_apply.return_value = {'after': 'patched', 'metrics': {'private_bytes': 42}}
            fix.save_report.return_value = 'fixture-report.json'

            def read(handle, address, buffer, length, used):
                expected = dict(profile['guards'])[address]
                c.memmove(buffer, expected, len(expected))
                c.cast(used, c.POINTER(c.c_size_t)).contents.value = len(expected)
                return True

            fix.K.ReadProcessMemory.side_effect = read
            callbacks = {}
            script = mock.Mock()
            script.on.side_effect = lambda name, callback: callbacks.update({name: callback})
            script.load.side_effect = lambda: callbacks['message']({'payload': {
                'ready': True, 'marker': experiment.MARKER, 'driver_sha256': driver_sha256,
                'driver_version': version}}, None)
            counters = {'thread_detaches': 1, 'cleaned_heaps': 1, 'owner_mismatch': 0, 'cleanup_still_owned': 0}
            script.exports_sync.status.return_value = counters
            script.exports_sync.stop.return_value = counters
            session = mock.Mock()
            session.create_script.return_value = script
            frida = SimpleNamespace(__version__='17.17.0', attach=mock.Mock(return_value=session))
            stop = threading.Event()
            samples = []

            def sample(report, row):
                samples.append(row)
                if len(samples) == 2:
                    stop.set()

            clock = iter([0, 18000, 18000])
            with mock.patch.object(experiment, 'load_existing_helper', return_value=fix), \
                 mock.patch.object(experiment, 'prepare_frida') as prepare, \
                 mock.patch.object(experiment.hashlib, 'sha256') as digest, \
                 mock.patch.dict(sys.modules, {'frida': frida}), \
                 mock.patch.object(experiment.time, 'monotonic', side_effect=lambda: next(clock)), \
                 mock.patch.object(experiment, 'wait_for_end', side_effect=lambda *unused: stop.is_set()):
                digest.return_value.hexdigest.return_value = driver_sha256
                prepare.return_value.snapshot.return_value = {'active': True, 'skipped_null_paths': 0}
                frida.attach.side_effect = lambda pid: session if prepare.called else self.fail('Dependency guard must precede attach')
                result = experiment.main(['--apply', '--with-semaphore', '--minutes', str(minutes), '--quiet'],
                                         stop_event=stop, on_sample=sample, output=directory / 'report.json', expected_pid=707)
            session.detach.assert_called_once()
            script.unload.assert_called_once()
            self.assertTrue(result['driver_code_restored'])
            self.assertEqual(result['driver_version'], version)
            self.assertEqual(result['driver_sha256'], driver_sha256)
            self.assertTrue(samples[0]['frida_usb_guard']['active'])
            self.assertTrue(any(call.args[2] is True for call in fix.inspect_or_apply.call_args_list))
            return result

    def test_zero_duration_keeps_running_until_explicit_stop_and_restores_hook(self):
        for version in ('616.64', '616.92'):
            with self.subTest(version=version):
                result = self.run_session_fixture(0, version)
                self.assertEqual(result['sample_count'], 2)
                self.assertEqual(result['stop_reason'], 'guard_stop')

    def test_finite_duration_still_expires_and_restores_hook(self):
        result = self.run_session_fixture(1)
        self.assertEqual(result['sample_count'], 1)
        self.assertEqual(result['stop_reason'], 'duration_elapsed')

    def test_only_one_guard_and_external_graceful_stop(self):
        name = 'Local\\LD14GuardTest-' + uuid.uuid4().hex
        self.assertFalse(guard.is_running(name))
        control = guard.Control(name)
        try:
            self.assertTrue(guard.is_running(name))
            with self.assertRaisesRegex(RuntimeError, 'already running'):
                guard.Control(name)
            self.assertFalse(control.is_set())
            self.assertTrue(guard.request_stop(name))
            self.assertTrue(control.wait(0.1))
        finally:
            control.close()
        self.assertFalse(guard.is_running(name))
        self.assertFalse(guard.request_stop(name))

    def test_restart_revalidates_and_reapplies_both_without_reapplying_live_pid(self):
        fix = mock.Mock()
        fix.backend_pid.side_effect = [0, 101, 101, 0, 202]
        fix.verify_target.return_value = {'base': 1}
        fix.modules.return_value = {'nvoglv64.dll': {'base': 2}}
        control = FakeControl()
        runner = mock.Mock()
        status = mock.Mock()
        args = SimpleNamespace(console='C:\\test\\ldconsole.exe', index=1)

        def session(argv, **options):
            options['on_sample']({'start': 'test', 'sample_count': 1,
                                  'driver_version': '616.92', 'driver_sha256': 'fixture'},
                                 {'semaphore_patch': 'patched', 'frida_usb_guard': {'active': True}})
            if options['expected_pid'] == 202:
                control.stopped = True
                return {'stop_reason': 'guard_stop', 'driver_code_restored': True}
            return {'stop_reason': 'target_detached'}

        runner.main.side_effect = session
        result = guard.watch(fix, runner, args, control, status)
        self.assertTrue(result['driver_code_restored'])
        self.assertEqual([call.kwargs['expected_pid'] for call in runner.main.call_args_list], [101, 202])
        self.assertEqual(fix.verify_target.call_args_list, [mock.call(101), mock.call(202)])
        for call in runner.main.call_args_list:
            argv = call.args[0]
            self.assertIn('--with-semaphore', argv)
            self.assertEqual(argv[argv.index('--minutes') + 1], '0')
        self.assertEqual(sum(call.args[0] == 'active' for call in status.update.call_args_list), 2)
        self.assertTrue(all(call.kwargs['driver_version'] == '616.92'
                            for call in status.update.call_args_list if call.args[0] == 'active'))

    def test_incompatible_process_is_blocked_without_repeated_patch_attempts(self):
        fix = mock.Mock()
        fix.backend_pid.return_value = 303
        fix.verify_target.side_effect = RuntimeError('Unsupported renderer version')
        runner = mock.Mock()
        status = mock.Mock()
        guard.watch(fix, runner, SimpleNamespace(console='unused', index=1), FakeControl(3), status)
        fix.verify_target.assert_called_once_with(303)
        runner.main.assert_not_called()
        self.assertTrue(any(call.args[0] == 'blocked' and 'Unsupported' in call.kwargs['error']
                            for call in status.update.call_args_list))

    def test_interrupt_in_session_ends_the_guard(self):
        fix = mock.Mock()
        fix.backend_pid.return_value = 404
        fix.verify_target.return_value = {'base': 1}
        fix.modules.return_value = {'nvoglv64.dll': {}}
        runner = mock.Mock()
        runner.main.return_value = {'stop_reason': 'user_interrupt', 'driver_code_restored': True}
        result = guard.watch(fix, runner, SimpleNamespace(console='unused', index=1), FakeControl(), mock.Mock())
        self.assertEqual(result['stop_reason'], 'user_interrupt')
        runner.main.assert_called_once()

    def test_supported_upgrade_after_blocked_process_is_applied_automatically(self):
        fix = mock.Mock()
        fix.backend_pid.side_effect = [303, 303, 404]
        fix.verify_target.side_effect = [RuntimeError('Unsupported renderer version'), {'base': 1}]
        fix.modules.return_value = {'nvoglv64.dll': {'base': 2}}
        runner = mock.Mock()
        control = FakeControl()
        status = mock.Mock()

        def session(argv, **options):
            control.stopped = True
            return {'stop_reason': 'guard_stop', 'driver_code_restored': True}

        runner.main.side_effect = session
        guard.watch(fix, runner, SimpleNamespace(console='unused', index=1), control, status)
        self.assertEqual(fix.verify_target.call_args_list, [mock.call(303), mock.call(404)])
        runner.main.assert_called_once()
        self.assertEqual(runner.main.call_args.kwargs['expected_pid'], 404)
        self.assertIn('--with-semaphore', runner.main.call_args.args[0])
        self.assertTrue(any(call.args[0] == 'blocked' for call in status.update.call_args_list))

    def test_unlimited_report_is_bounded_but_history_keeps_all_samples(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            output = Path(directory) / 'report.json'
            report = {'options': {'minutes': 0}, 'samples': []}
            history = mock.Mock()
            total = experiment.RECENT_SAMPLES + 17
            for sequence in range(total):
                experiment.record_sample(report, {'sequence': sequence}, output, history)
            restored = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(restored['sample_count'], total)
            self.assertEqual(len(restored['samples']), experiment.RECENT_SAMPLES)
            self.assertEqual(restored['samples'][0]['sequence'], 17)
            self.assertEqual(restored['samples'][-1]['sequence'], total - 1)
            self.assertEqual(history.emit.call_count, total)
            self.assertFalse(output.with_suffix('.json.tmp').exists())

    def test_finite_report_preserves_complete_sample_history(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tests') as directory:
            report = {'options': {'minutes': 240}, 'samples': []}
            for sequence in range(experiment.RECENT_SAMPLES + 1):
                experiment.record_sample(report, {'sequence': sequence}, Path(directory) / 'report.json')
            self.assertEqual(len(report['samples']), experiment.RECENT_SAMPLES + 1)

    def test_unlimited_session_can_be_stopped_without_a_duration_deadline(self):
        detached = threading.Event()
        stopped = threading.Event()
        stopped.set()
        self.assertTrue(experiment.wait_for_end(detached, stopped, 3600))
        self.assertFalse(experiment.wait_for_end(detached, threading.Event(), 0))
        detached.set()
        self.assertTrue(experiment.wait_for_end(detached, threading.Event(), 3600))


if __name__ == '__main__':
    unittest.main()
