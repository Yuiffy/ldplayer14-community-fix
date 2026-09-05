"""Execute the validated instruction fragment on locally owned Win32 handles."""

import ctypes as c
from ctypes import wintypes as w
import importlib.util
import os
from pathlib import Path
import struct
import unittest

if os.name != 'nt' or c.sizeof(c.c_void_p) != 8:
    raise unittest.SkipTest('Windows 64-bit native test')

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ld14_native', root / 'ld14-local-fix.py')
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)
k = c.WinDLL('kernel32', use_last_error=True)
k.VirtualAlloc.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, w.DWORD]
k.VirtualAlloc.restype = c.c_void_p
k.VirtualProtect.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, c.POINTER(w.DWORD)]
k.VirtualFree.argtypes = [c.c_void_p, c.c_size_t, w.DWORD]
k.CreateSemaphoreW.argtypes = [c.c_void_p, w.LONG, w.LONG, w.LPCWSTR]
k.CreateSemaphoreW.restype = w.HANDLE
k.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
k.CreateEventW.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]
k.GetHandleInformation.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
k.GetCurrentProcess.restype = w.HANDLE
k.FlushInstructionCache.argtypes = [w.HANDLE, c.c_void_p, c.c_size_t]


class NativePatchTests(unittest.TestCase):
    def exercise(self, patched):
        page_rva = 0x60000
        code = bytearray(b'\xcc' * 0x1000)
        # Preserve RDI/RSI and Windows x64 shadow space before the real fragment.
        entry = bytes.fromhex('57564883ec284889cf4889d6') + fix.jump(page_rva + 12, 0x60aef)
        code[:len(entry)] = entry
        code[0xaef:0xaf6] = bytes.fromhex('488b8f60040000')
        code[0xaf6:0xafb] = fix.jump(0x60af6, 0x60afd)
        code[0xafd:0xb08] = bytes.fromhex('ffd6488b8fc0040000ffd6')
        code[0xb08:0xb0f] = bytes.fromhex('4883c4285e5fc3')
        for rva, original, replacement in fix.PATCHES:
            self.assertEqual(len(original), len(replacement))
            value = replacement if patched else original
            code[rva - page_rva:rva - page_rva + len(value)] = value
        memory = k.VirtualAlloc(None, len(code), 0x3000, 4)
        self.assertTrue(memory)
        try:
            c.memmove(memory, bytes(code), len(code))
            old = w.DWORD()
            self.assertTrue(k.VirtualProtect(memory, len(code), 0x20, c.byref(old)))
            self.assertTrue(k.FlushInstructionCache(k.GetCurrentProcess(), memory, len(code)))
            procedure = c.WINFUNCTYPE(None, c.c_void_p, c.c_void_p)(memory)
            for _ in range(128):
                values = [k.CreateEventW(None, True, False, None),
                          k.CreateSemaphoreW(None, 2, 100, None),
                          k.CreateSemaphoreW(None, 0, 100, None)]
                self.assertTrue(all(values))
                state = c.create_string_buffer(0x520)
                for offset, handle in zip((0x460, 0x4b8, 0x4c0), values):
                    struct.pack_into('<Q', state, offset, handle)
                try:
                    procedure(c.addressof(state), c.cast(k.CloseHandle, c.c_void_p))
                    valid = [bool(k.GetHandleInformation(value, c.byref(w.DWORD()))) for value in values]
                    self.assertEqual(valid, [False, not patched, False])
                finally:
                    for value in values:
                        if k.GetHandleInformation(value, c.byref(w.DWORD())):
                            k.CloseHandle(value)
        finally:
            self.assertTrue(k.VirtualFree(memory, 0, 0x8000))

    def test_original_fragment_leaves_first_semaphore_open(self):
        self.exercise(False)

    def test_patched_fragment_closes_all_owned_handles(self):
        self.exercise(True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
