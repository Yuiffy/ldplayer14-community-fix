import argparse
import contextlib
import csv
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

if os.name != 'nt':
    raise unittest.SkipTest('Windows process APIs are required')

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ld14_distribution', root.parent / 'ld14-local-fix.py')
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=root)
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_wrong_installation_is_rejected_before_console_execution(self):
        console = self.directory / 'ldconsole.exe'
        console.write_bytes(b'test fixture')
        (self.directory / 'gpu').mkdir()
        (self.directory / 'gpu' / 'fastpipe2.dll').write_bytes(b'unsupported binary')
        with mock.patch.object(fix.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported LD14 installation'):
                fix.verify_installation(console)
            run.assert_not_called()

    def test_ld9_mapping_is_rejected_before_patch_access(self):
        selected = self.directory / 'ldconsole.exe'
        loaded = {'libopenglrender2.dll': {'base': 0x180000000, 'path': 'unused'},
                  'fastpipe2.dll': {'base': 0, 'path': str(self.directory / 'LD9' / 'gpu' / 'fastpipe2.dll')}}
        with mock.patch.object(fix, 'read_config', return_value={}), \
             mock.patch.object(fix, 'verify_installation', return_value=selected), \
             mock.patch.object(fix, 'list_instances', return_value=[{'index': 0, 'pid': 123}]), \
             mock.patch.object(fix, 'modules', return_value=loaded), \
             mock.patch.object(fix, 'inspect_or_apply') as patch:
            with self.assertRaisesRegex(RuntimeError, 'expected LD14 fastpipe'):
                fix.main(['--apply', '--console', str(selected), '--index', '0'])
            patch.assert_not_called()

    def test_unknown_renderer_is_rejected_before_patch_access(self):
        selected = self.directory / 'ldconsole.exe'
        renderer = self.directory / 'libOpenglRender2.dll'
        renderer.write_bytes(b'future renderer')
        loaded = {'libopenglrender2.dll': {'base': 0x180000000, 'path': str(renderer)},
                  'fastpipe2.dll': {'base': 0, 'path': str(self.directory / 'gpu' / 'fastpipe2.dll')}}
        with mock.patch.object(fix, 'read_config', return_value={}), \
             mock.patch.object(fix, 'verify_installation', return_value=selected), \
             mock.patch.object(fix, 'list_instances', return_value=[{'index': 0, 'pid': 123}]), \
             mock.patch.object(fix, 'modules', return_value=loaded), \
             mock.patch.object(fix, 'inspect_or_apply') as patch:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported renderer version'):
                fix.main(['--apply', '--console', str(selected), '--index', '0'])
            patch.assert_not_called()

    def test_nonexistent_instance_does_not_launch(self):
        selected = self.directory / 'ldconsole.exe'
        with mock.patch.object(fix, 'read_config', return_value={}), \
             mock.patch.object(fix, 'verify_installation', return_value=selected), \
             mock.patch.object(fix, 'list_instances', return_value=[{'index': 0, 'pid': 123}]), \
             mock.patch.object(fix, 'console') as console:
            with self.assertRaisesRegex(RuntimeError, 'instance was not found'):
                fix.main(['--start', '--console', str(selected), '--index', '9'])
            console.assert_not_called()

    def test_validated_renderer_selects_its_own_profile(self):
        selected = self.directory / 'ldconsole.exe'
        renderer = self.directory / 'libOpenglRender2.dll'
        pipe = self.directory / 'gpu' / 'fastpipe2.dll'
        pipe.parent.mkdir()
        renderer.write_bytes(b'fixture renderer')
        pipe.write_bytes(b'fixture pipe')
        loaded = {'libopenglrender2.dll': {'base': 0x180000000, 'path': str(renderer)},
                  'fastpipe2.dll': {'base': 0, 'path': str(pipe)}}
        for digest, profile in fix.RENDERER_PROFILES.items():
            with self.subTest(version=profile['version']), \
                 mock.patch.object(fix, 'CONSOLE', selected), \
                 mock.patch.object(fix, 'modules', return_value=loaded), \
                 mock.patch.object(fix.hashlib, 'sha256', side_effect=[
                     mock.Mock(hexdigest=lambda: digest),
                     mock.Mock(hexdigest=lambda: profile['fastpipe_sha256'])]):
                self.assertEqual(fix.verify_target(123)['sha256'], digest)

    def test_supported_files_from_different_builds_are_rejected(self):
        selected = self.directory / 'ldconsole.exe'
        renderer = self.directory / 'libOpenglRender2.dll'
        pipe = self.directory / 'gpu' / 'fastpipe2.dll'
        pipe.parent.mkdir()
        renderer.write_bytes(b'fixture renderer')
        pipe.write_bytes(b'fixture pipe')
        loaded = {'libopenglrender2.dll': {'base': 0x180000000, 'path': str(renderer)},
                  'fastpipe2.dll': {'base': 0, 'path': str(pipe)}}
        digests = list(fix.RENDERER_PROFILES)
        with mock.patch.object(fix, 'CONSOLE', selected), \
             mock.patch.object(fix, 'modules', return_value=loaded), \
             mock.patch.object(fix.hashlib, 'sha256', side_effect=[
                 mock.Mock(hexdigest=lambda: digests[0]),
                 mock.Mock(hexdigest=lambda: fix.RENDERER_PROFILES[digests[1]]['fastpipe_sha256'])]):
            with self.assertRaisesRegex(RuntimeError, 'not a validated pair'):
                fix.verify_target(123)

    def test_setup_keeps_explicit_zero_index_and_space_path(self):
        selected = self.directory / 'LD Player' / 'ldconsole.exe'
        config = self.directory / 'config.json'
        args = argparse.Namespace(console=str(selected), index=0, setup=True, list=False)
        with mock.patch.object(fix, 'CONFIG', config), \
             mock.patch.object(fix, 'verify_installation', return_value=selected), \
             mock.patch.object(fix, 'list_instances', return_value=[{'index': 0, 'pid': 123}]), \
             contextlib.redirect_stdout(io.StringIO()):
            fix.configure(args, {'index': 1})
            self.assertEqual(fix.read_config(), {'console': str(selected), 'index': 0})

    def test_recorder_stops_on_pid_change_without_applying(self):
        report = {'time': 'test', 'after': 'patched', 'metrics': {'private_bytes': 100}}
        with mock.patch.object(fix, 'ROOT', self.directory), \
             mock.patch.object(fix, 'backend_pid', side_effect=[123, 456]), \
             mock.patch.object(fix, 'inspect_or_apply', return_value=report) as inspect, \
             mock.patch.object(fix.time, 'sleep'), contextlib.redirect_stdout(io.StringIO()):
            fix.monitor(123, {'base': 0}, 1, 1)
        inspect.assert_called_once_with(123, {'base': 0}, False)
        with next((self.directory / 'logs').glob('*.csv')).open(encoding='utf-8-sig', newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['pid'], '123')


if __name__ == '__main__':
    unittest.main(verbosity=2)
