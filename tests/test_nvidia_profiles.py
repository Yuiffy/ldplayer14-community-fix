"""Reject an unsupported DLL or changed live code before either patch is applied."""
import ctypes as c
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cleanup_profile_tests', ROOT / 'experimental' / 'nvidia-thread-cleanup.py')
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


@unittest.skipUnless(sys.platform == 'win32', 'Windows process APIs required')
class ProfileRejectionTests(unittest.TestCase):
    def fixture(self, path):
        fix = mock.Mock()
        fix.backend_pid.return_value = 707
        fix.verify_target.return_value = {'base': 0x100000}
        fix.modules.return_value = {'nvoglv64.dll': {'path': str(path), 'base': 0}}
        fix.K.OpenProcess.return_value = 1
        return fix

    def test_unknown_hash_cannot_apply_either_patch_or_prepare_frida(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nvoglv64.dll'
            path.write_bytes(b'Unrecognized NVIDIA build')
            fix = self.fixture(path)
            with mock.patch.object(cleanup, 'load_existing_helper', return_value=fix), \
                 mock.patch.object(cleanup, 'prepare_frida') as prepare:
                with self.assertRaisesRegex(RuntimeError, 'Unsupported NVIDIA driver'):
                    cleanup.main(['--apply', '--with-semaphore', '--quiet'])
            fix.K.OpenProcess.assert_not_called()
            fix.inspect_or_apply.assert_not_called()
            prepare.assert_not_called()

    def test_changed_live_tls_reference_is_rejected_for_each_supported_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'nvoglv64.dll'
            path.write_bytes(b'Disk identity is mocked; live instructions are inspected')
            for digest, profile in cleanup.DRIVERS.items():
                with self.subTest(driver=profile['version']):
                    fix = self.fixture(path)

                    def read(handle, address, buffer, length, used):
                        expected = bytearray(dict(profile['guards'])[address])
                        if address == 0xa7f2d9:
                            expected[-1] ^= 1
                        c.memmove(buffer, bytes(expected), len(expected))
                        c.cast(used, c.POINTER(c.c_size_t)).contents.value = len(expected)
                        return True

                    fix.K.ReadProcessMemory.side_effect = read
                    with mock.patch.object(cleanup, 'load_existing_helper', return_value=fix), \
                         mock.patch.object(cleanup, 'select_driver', return_value=(digest, profile)), \
                         mock.patch.object(cleanup, 'prepare_frida') as prepare:
                        with self.assertRaisesRegex(RuntimeError, 'Unexpected driver code'):
                            cleanup.main(['--apply', '--with-semaphore', '--quiet'])
                    fix.inspect_or_apply.assert_not_called()
                    fix.K.CloseHandle.assert_called_once_with(1)
                    prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
