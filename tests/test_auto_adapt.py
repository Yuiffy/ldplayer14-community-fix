"""Relocation proofs must reject changed behavior, aliases and ambiguous roots."""
import importlib.util
import argparse
import contextlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
try:
    import capstone as cs
    import pefile
except ImportError:
    cs = pefile = None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = load('auto_engine_tests', ROOT / 'compatibility/engine.py') if cs and pefile else None
client = load('auto_client_tests', ROOT / 'ld14-auto-adapt.py')


def image(root=0x1100, callee=0x2100, data=0x5100, immediate=7, duplicate=False):
    """Owned synthetic image with real x64 instructions and unwind metadata."""
    obj = engine.Image.__new__(engine.Image)
    obj.base = 0x180000000
    obj.data = bytearray(b'\xcc' * 0x4000 + b'\0' * 0x4000)
    obj.raw = bytes(obj.data)
    obj.sha256 = engine.digest(obj.raw)
    obj.relocations = set()
    obj.imports = {}
    obj.headers = SimpleNamespace(Misc_VirtualSize=0x1000, Name=b'HEADERS', Characteristics=0x40000040, VirtualAddress=0)
    obj.sections = []
    for name, start, size, flags in [(b'.text', 0x1000, 0x3000, 0x60000020),
                                    (b'.data', 0x5000, 0x1000, 0xc0000040),
                                    (b'.xdata', 0x7000, 0x1000, 0x40000040)]:
        section = SimpleNamespace(Name=name, VirtualAddress=start, Misc_VirtualSize=size, Characteristics=flags)
        section.get_data = lambda section=section: bytes(obj.data[section.VirtualAddress:section.VirtualAddress + section.Misc_VirtualSize])
        obj.sections.append(section)
    code = bytes.fromhex('4883ec28e8') + struct.pack('<i', callee - root - 9)
    code += bytes.fromhex('488b05') + struct.pack('<i', data - root - 16)
    code += bytes.fromhex('4883c428c3')
    helper = b'\xb8' + struct.pack('<I', immediate) + b'\xc3'
    obj.data[root:root + len(code)] = code
    obj.data[callee:callee + len(helper)] = helper
    obj.data[0x7000:0x7004] = bytes.fromhex('01000000')
    obj.functions = [(root, root + len(code), 0x7000), (callee, callee + len(helper), 0x7000)]
    if duplicate:
        other = 0x3100
        copied = bytearray(code)
        struct.pack_into('<i', copied, 5, callee - other - 9)
        struct.pack_into('<i', copied, 12, data - other - 16)
        obj.data[other:other + len(code)] = copied
        obj.functions.append((other, other + len(code), 0x7000))
    obj.functions.sort()
    obj.starts = [a for a, b, u in obj.functions]
    obj.dis = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    obj.dis.detail = True
    return obj


@unittest.skipUnless(engine is not None, 'Optional pinned Capstone and pefile required')
class GraphProofTests(unittest.TestCase):
    def setUp(self):
        self.original = image()
        self.template = engine.build_graph(self.original, {'entry': (0x1100, None)})

    def test_independently_relocated_functions_and_data_pass(self):
        moved = image(root=0x1200, callee=0x2400, data=0x5200)
        self.assertEqual(engine.match_graph(moved, self.template), {0x1100: 0x1200, 0x2100: 0x2400})

    def test_same_entry_but_changed_downstream_behavior_is_rejected(self):
        with self.assertRaisesRegex(engine.Incompatible, 'dependency'):
            engine.match_graph(image(immediate=8), self.template)

    def test_two_matching_roots_are_rejected(self):
        with self.assertRaisesRegex(engine.Incompatible, '2 compatible candidates'):
            engine.match_graph(image(duplicate=True), self.template)

    def test_changed_object_field_offset_is_not_masked(self):
        changed = image()
        changed.data[0x2100:0x2106] = bytes.fromhex('8b41109090c3')
        with self.assertRaises(engine.Incompatible):
            engine.match_graph(changed, self.template)

    def test_changed_global_initial_value_is_rejected(self):
        changed = image()
        changed.data[0x5100] = 1
        with self.assertRaisesRegex(engine.Incompatible, 'Referenced data'):
            engine.match_graph(changed, self.template)

    def test_changed_imported_api_is_rejected(self):
        a, b = image(), image()
        a.imports[0x5100], b.imports[0x5100] = 'kernel32.dll!CloseHandle', 'kernel32.dll!DeleteFileW'
        template = engine.build_graph(a, {'entry': (0x1100, None)})
        with self.assertRaisesRegex(engine.Incompatible, 'imported API'):
            engine.match_graph(b, template)

    def test_changed_internal_branch_destination_is_rejected(self):
        a, b = image(), image()
        for obj, displacement in [(a, 2), (b, 3)]:
            obj.data[0x2100:0x2106] = bytes([0xeb, displacement, 0x90, 0x90, 0x90, 0xc3])
        template = engine.build_graph(a, {'entry': (0x1100, None)})
        with self.assertRaisesRegex(engine.Incompatible, 'Internal branch'):
            engine.match_graph(b, template)

    def test_changed_unwind_information_is_rejected(self):
        changed = image()
        changed.data[0x7001] = 4
        with self.assertRaises(engine.Incompatible):
            engine.match_graph(changed, self.template)

    def test_live_guards_cover_helpers_and_exclude_only_patch_bytes(self):
        mapping = engine.match_graph(self.original, self.template)
        guards = engine.runtime_guards(self.original, mapping, self.template, [(0x1105, 0x1109)])
        self.assertTrue(any(start == 0x2100 for start, value in guards))
        self.assertTrue(all(not (start <= 0x1105 < start + len(bytes.fromhex(value))) for start, value in guards))


class AdapterClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'owned.dll'
        self.path.write_bytes(b'owned test bytes')
        self.digest = client.sha256(self.path)
        client._verified.clear()
        self.patch = mock.patch.object(client, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def worker(self, command, **options):
        result = {'schema': 1, 'kind': 'driver', 'compatible': True, 'sha256': self.digest,
                  'native_verified': True, 'baseline_sha256': 'fixture', 'elapsed_seconds': 0.01,
                  'profile': {'version': 'fixture', 'rvas': {}, 'guards': [[0x100, '90']]}}
        Path(command[command.index('--result') + 1]).write_text(json.dumps(result))
        return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')

    def test_fresh_proof_is_cached_only_in_memory(self):
        with mock.patch.object(client.subprocess, 'run', side_effect=self.worker) as run:
            a = client.analyze('driver', self.path)
            self.assertEqual(a['guards'], [(0x100, b'\x90')])
            self.assertIs(a, client.analyze('driver', self.path))
            self.assertEqual(run.call_count, 1)

    def test_disk_report_cannot_bypass_new_proof_or_timeout(self):
        with mock.patch.object(client.subprocess, 'run', side_effect=self.worker):
            client.analyze('driver', self.path)
        client._verified.clear()
        with mock.patch.object(client.subprocess, 'run', side_effect=subprocess.TimeoutExpired('worker', 90)):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                client.analyze('driver', self.path)

    def test_file_replacement_during_analysis_is_rejected(self):
        def worker(*args, **kwargs):
            result = self.worker(*args, **kwargs)
            self.path.write_bytes(b'replaced during proof')
            return result
        with mock.patch.object(client.subprocess, 'run', side_effect=worker):
            with self.assertRaisesRegex(RuntimeError, 'files changed'):
                client.analyze('driver', self.path)
        self.assertFalse(client._verified)

    def test_worker_failure_without_report_stops(self):
        with mock.patch.object(client.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'no module')):
            with self.assertRaisesRegex(RuntimeError, 'failed before producing'):
                client.analyze('driver', self.path)

    def test_failed_native_selftest_cannot_be_accepted(self):
        def worker(command, **kwargs):
            completed = self.worker(command, **kwargs)
            path = Path(command[command.index('--result') + 1])
            result = json.loads(path.read_text())
            result['native_verified'] = False
            path.write_text(json.dumps(result))
            return completed
        with mock.patch.object(client.subprocess, 'run', side_effect=worker):
            with self.assertRaisesRegex(RuntimeError, 'self-test did not pass'):
                client.analyze('driver', self.path)
        self.assertFalse(client._verified)

    def test_mismatched_pair_report_is_rejected(self):
        with mock.patch.object(client.subprocess, 'run', side_effect=self.worker):
            with self.assertRaisesRegex(RuntimeError, 'fastpipe pair'):
                client.analyze('renderer', self.path, self.path)
        self.assertFalse(client._verified)

    def test_enable_disable_preserves_local_configuration(self):
        path = self.root / 'ld14-fix.config.json'
        saved = {'console': 'F:/LD14/ldconsole.exe', 'index': 0, 'extra': 'preserved'}
        path.write_text(json.dumps(saved))
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                client.set_enabled(enabled)
                self.assertEqual(json.loads(path.read_text()), {**saved, 'auto_adapt': enabled})


@unittest.skipUnless(engine is not None, 'Optional pinned Capstone and pefile required')
class WorkerIntegrityTests(unittest.TestCase):
    def test_changed_baseline_is_rejected_before_image_analysis(self):
        with mock.patch.dict(sys.modules, {'engine': engine}):
            worker = load('worker_integrity_test', ROOT / 'compatibility/worker.py')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compatibility').mkdir()
            (root / 'compatibility/baseline-v1.json').write_text('{"schema":1}')
            with mock.patch.object(worker, 'ROOT', root), mock.patch.object(worker, 'Image') as inspect:
                with self.assertRaisesRegex(engine.Incompatible, 'integrity'):
                    worker.analyze('driver', root / 'never-opened.dll')
                inspect.assert_not_called()


@unittest.skipUnless(sys.platform == 'win32', 'Windows target-selection code required')
class RuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fix = load('auto_runtime_fixture', ROOT / 'ld14-local-fix.py')
        self.fix.CONSOLE = self.root / 'ldconsole.exe'
        self.fix.AUTO_ADAPT = True
        (self.root / 'gpu').mkdir()
        self.pipe = self.root / 'gpu/fastpipe2.dll'
        self.pipe.write_bytes(b'future bridge')
        self.renderer = self.root / 'libOpenglRender2.dll'
        self.renderer.write_bytes(b'future renderer')
        self.modules = {'libopenglrender2.dll': {'base': 0x180000000, 'path': str(self.renderer)},
                        'fastpipe2.dll': {'base': 0, 'path': str(self.pipe)}}

    def test_unknown_renderer_requires_fresh_pair_analysis(self):
        adapter = mock.Mock()
        profile = {'version': 'owned fixture', 'guards': [], 'patches': []}
        adapter.analyze.return_value = profile
        with mock.patch.object(self.fix, 'modules', return_value=self.modules), \
             mock.patch.object(self.fix, 'load_auto_adapter', return_value=adapter):
            target = self.fix.verify_target(123)
        self.assertIs(target['profile'], profile)
        adapter.analyze.assert_called_once_with('renderer', str(self.renderer), str(self.pipe))

    def test_unknown_driver_only_adapts_when_explicitly_enabled(self):
        cleanup = load('auto_driver_fixture', ROOT / 'experimental/nvidia-thread-cleanup.py')
        path = self.root / 'driver.dll'
        path.write_bytes(b'future driver')
        adapter = mock.Mock()
        adapter.analyze.return_value = {'version': 'owned fixture'}
        helper = mock.Mock()
        helper.load_auto_adapter.return_value = adapter
        with mock.patch.object(cleanup, 'load_existing_helper', return_value=helper):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported NVIDIA'):
                cleanup.select_driver(path)
            adapter.analyze.assert_not_called()
            self.assertEqual(cleanup.select_driver(path, True)[1]['version'], 'owned fixture')
        adapter.analyze.assert_called_once_with('driver', path)

    def test_setup_preserves_enabled_flag(self):
        config = self.root / 'config.json'
        args = argparse.Namespace(console=str(self.fix.CONSOLE), index=0, setup=True, list=False)
        with mock.patch.object(self.fix, 'CONFIG', config), \
             mock.patch.object(self.fix, 'verify_installation', return_value=self.fix.CONSOLE), \
             mock.patch.object(self.fix, 'list_instances', return_value=[{'index': 0}]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.fix.configure(args, {'auto_adapt': True})
        self.assertIs(json.loads(config.read_text())['auto_adapt'], True)


if __name__ == '__main__':
    unittest.main()
