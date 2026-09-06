"""Exercise real Frida comparison calls in isolated processes without a GPU."""

import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_guard():
    spec = importlib.util.spec_from_file_location('usb_guard_fixture', ROOT / 'experimental' / 'frida-usb-guard.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    return guard


def call_fragment(guard, base, site, left, right):
    rva, expected = guard.SITES[site]
    live = c.string_at(base + rva, len(expected))
    target = base + rva + guard.CALL_OFFSET + 5 + struct.unpack_from('<i', live, guard.CALL_OFFSET + 1)[0]
    memory = guard._reserve_near(base)
    try:
        code = bytearray(b'\xcc' * guard.PAGE_SIZE)
        # Preserve the caller's nonvolatile registers and provide x64 shadow space.
        entry = bytes.fromhex('5756554883ec204889ce4889cd4889d7')
        code[:len(entry)] = entry
        code[len(entry):len(entry) + 5] = guard._relative(0xe9, memory + len(entry), memory + 0x40)
        fragment = bytearray(live)
        offset = guard.CALL_OFFSET
        fragment[offset:offset + 5] = guard._relative(0xe8, memory + 0x40 + offset, target)
        code[0x40:0x40 + len(fragment)] = fragment
        match = 0x40 + len(fragment)
        mismatch = match + fragment[-1]
        for position, returned in ((match, 1), (mismatch, 0)):
            code[position:position + 5] = b'\xb8' + struct.pack('<I', returned)
            code[position + 5:position + 10] = guard._relative(0xe9, memory + position + 5, memory + 0x100)
        code[0x100:0x108] = bytes.fromhex('4883c4205d5e5fc3')
        c.memmove(memory, bytes(code), len(code))
        old = w.DWORD()
        if not guard.K.VirtualProtect(memory, guard.PAGE_SIZE, 0x20, c.byref(old)):
            raise c.WinError(c.get_last_error())
        if not guard.K.FlushInstructionCache(guard.K.GetCurrentProcess(), memory, len(code)):
            raise c.WinError(c.get_last_error())
        device = c.create_string_buffer(0x100)
        change = c.create_string_buffer(0x20)
        strings = [c.create_string_buffer(value) if value is not None else None for value in (left, right)]
        c.c_void_p.from_buffer(device, 0x80).value = c.addressof(strings[0]) if strings[0] else None
        c.c_void_p.from_buffer(change, 0x18).value = c.addressof(strings[1]) if strings[1] else None
        function = c.WINFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p)(memory)
        return function(c.addressof(device), c.addressof(change))
    finally:
        guard.K.VirtualFree(memory, 0, 0x8000)


def worker(mode):
    guard = load_guard()
    guard.K.SetErrorMode(0x8003)
    import frida
    base = guard.K.GetModuleHandleW(str(Path(frida._frida.__file__).resolve()))
    if mode.startswith('original-'):
        assert frida.__version__ == '17.17.0'
        assert guard.hashlib.sha256(Path(frida._frida.__file__).read_bytes()).hexdigest() == guard.FRIDA_SHA256
        site = int(mode.rsplit('-', 1)[-1])
        print('calling-original-null-path', flush=True)
        call_fragment(guard, base, site, None, b'usb-fixture')
        raise AssertionError('Original null path unexpectedly survived')
    if mode in ('wrong-hash', 'wrong-code', 'late-init'):
        original_calls = [c.string_at(base + rva, len(value)) for rva, value in guard.SITES]
        if mode == 'wrong-hash':
            guard.FRIDA_SHA256 = '0' * 64
        elif mode == 'wrong-code':
            guard.SITES = tuple((rva, b'\x00' * len(value)) for rva, value in guard.SITES)
        else:
            frida.get_local_device()
            deadline = time.monotonic() + 5
            while not guard._usb_started() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert guard._usb_started(), 'The fixture USB event window did not start'
        try:
            guard.install()
        except RuntimeError as error:
            assert not guard.snapshot()['active']
            assert original_calls == [c.string_at(base + rva, len(value)) for rva, value in guard.SITES]
            print(json.dumps({'rejected': str(error)}), flush=True)
            return
        raise AssertionError('Unsupported dependency was not rejected')
    first = guard.install()
    assert guard.install() == first
    cases = [(None, b'usb-fixture', 0), (b'usb-fixture', None, 0), (None, None, 0),
             (b'USB\\VID_1234', b'usb\\vid_1234', 1), (b'usb-one', b'usb-two', 0),
             (b'', b'', 1), (b'', b'usb-fixture', 0)]
    for site in range(len(guard.SITES)):
        for left, right, expected in cases:
            actual = call_fragment(guard, base, site, left, right)
            assert actual == expected, (site, left, right, actual)
    assert guard.snapshot()['skipped_null_paths'] == 6
    # Verify the guarded dependency still supports normal local attachment.
    child = subprocess.Popen([sys.executable, '-c', 'import sys; print("ready", flush=True); sys.stdin.readline()'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        assert child.stdout.readline().strip() == b'ready'
        session = frida.attach(child.pid)
        try:
            script = session.create_script('rpc.exports = { targetpid() { return Process.id; } };')
            script.load()
            assert script.exports_sync.targetpid() == child.pid
            script.unload()
        finally:
            session.detach()
    finally:
        try:
            child.communicate(b'\n', timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    assert guard.install()['skipped_null_paths'] == 6
    print(json.dumps({'cases': len(cases) * len(guard.SITES), 'attachment': True, **guard.snapshot()}), flush=True)


@unittest.skipUnless(os.name == 'nt' and c.sizeof(c.c_void_p) == 8, 'Windows x64 required')
class FridaUsbGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec('frida') is None:
            raise unittest.SkipTest('Optional Frida dependency required')

    def run_worker(self, mode):
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker', mode],
                              capture_output=True, text=True, timeout=25,
                              creationflags=subprocess.CREATE_NO_WINDOW)

    def test_original_comparisons_reproduce_captured_fast_fail(self):
        for site in (0, 1):
            with self.subTest(site=site):
                result = self.run_worker('original-' + str(site))
                self.assertIn('calling-original-null-path', result.stdout)
                self.assertEqual(result.returncode & 0xffffffff, 0xc0000409, result.stdout + result.stderr)

    def test_null_paths_are_skipped_and_valid_comparisons_and_attachment_survive(self):
        result = self.run_worker('patched')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['skipped_null_paths'], 6)
        self.assertEqual(report['cases'], 14)
        self.assertTrue(report['attachment'])

    def test_unsupported_dependency_or_late_initialization_is_rejected_without_changes(self):
        for mode in ('wrong-hash', 'wrong-code', 'late-init'):
            with self.subTest(mode=mode):
                result = self.run_worker(mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('rejected', json.loads(result.stdout))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        worker(sys.argv[2])
    else:
        unittest.main()
