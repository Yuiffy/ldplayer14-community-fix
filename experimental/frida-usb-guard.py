"""Guard two libusb null-path comparisons in the validated Frida controller."""

import ctypes as c
from ctypes import wintypes as w
import hashlib
import os
from pathlib import Path
import struct
import threading

FRIDA_SHA256 = '93638a16bf0a651c6fdc8f41228ce9069e7b79d56834cce7aec9f8b6639c671c'
COMPARE_RVA = 0xec2e40
SITES = (
    (0xdc422f, bytes.fromhex('488b5718488b8e80000000e801ec0f0085c07514')),
    (0xdc42aa, bytes.fromhex('488b5718488b8d80000000e886eb0f0085c0750f')),
)
CALL_OFFSET = 11
PAGE_SIZE = 0x1000
_lock = threading.Lock()
_state = None

K = c.WinDLL('kernel32', use_last_error=True)
K.GetModuleHandleW.argtypes = [w.LPCWSTR]
K.GetModuleHandleW.restype = w.HMODULE
K.GetCurrentProcess.restype = w.HANDLE
K.VirtualAlloc.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, w.DWORD]
K.VirtualAlloc.restype = c.c_void_p
K.VirtualFree.argtypes = [c.c_void_p, c.c_size_t, w.DWORD]
K.VirtualProtect.argtypes = [c.c_void_p, c.c_size_t, w.DWORD, c.POINTER(w.DWORD)]
K.FlushInstructionCache.argtypes = [w.HANDLE, c.c_void_p, c.c_size_t]


class MemoryRegion(c.Structure):
    _fields_ = [('base', c.c_void_p), ('allocation_base', c.c_void_p),
                ('allocation_protect', w.DWORD), ('size', c.c_size_t),
                ('state', w.DWORD), ('protect', w.DWORD), ('kind', w.DWORD)]


K.VirtualQuery.argtypes = [c.c_void_p, c.POINTER(MemoryRegion), c.c_size_t]
K.VirtualQuery.restype = c.c_size_t


def _reserve_near(base):
    lower = max(0x10000, base + COMPARE_RVA - 2**31)
    upper = min(0x7fffffff0000, base + SITES[0][0] + CALL_OFFSET + 5 + 2**31 - 1)
    for start, end in ((base, upper), (lower, base)):
        address = start
        while address + 2 * PAGE_SIZE <= end:
            region = MemoryRegion()
            if not K.VirtualQuery(address, c.byref(region), c.sizeof(region)):
                break
            region_end = region.base + region.size
            candidate = (max(address, region.base) + 0xffff) & ~0xffff
            if region.state == 0x10000 and candidate + 2 * PAGE_SIZE <= min(region_end, end):
                result = K.VirtualAlloc(candidate, 2 * PAGE_SIZE, 0x3000, 4)
                if result:
                    return result
            address = region_end
    raise RuntimeError('No nearby address space for the Frida USB guard')


def _relative(opcode, address, target):
    return bytes([opcode]) + struct.pack('<i', target - address - 5)


def _stub(address, compare):
    # A tail jump preserves the original ABI; null strings mean no device match.
    prefix = bytes.fromhex('4885c9740a4885d27405')
    tail = _relative(0xe9, address + len(prefix), compare)
    count = bytes.fromhex('f048ff05') + struct.pack('<i', PAGE_SIZE - 23)
    return prefix + tail + count + bytes.fromhex('b801000000c3')


def _usb_started():
    user = c.WinDLL('user32', use_last_error=True)
    callback_type = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.EnumWindows.argtypes = [callback_type, w.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [w.HWND, c.POINTER(w.DWORD)]
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, c.c_int]
    found = []

    @callback_type
    def visit(hwnd, unused):
        pid = w.DWORD()
        user.GetWindowThreadProcessId(hwnd, c.byref(pid))
        name = c.create_unicode_buffer(128)
        user.GetClassNameW(hwnd, name, len(name))
        if pid.value == os.getpid() and name.value == 'libusb-1.0-windows-hotplug':
            found.append(hwnd)
        return True

    if not user.EnumWindows(visit, 0):
        raise c.WinError(c.get_last_error())
    return bool(found)


def snapshot():
    if _state is None:
        return {'active': False}
    return {'marker': 'LD14-FRIDA-USB-NULL-GUARD-1', 'active': True,
            'frida_sha256': FRIDA_SHA256, 'controller_pid': os.getpid(),
            'guarded_calls': [hex(rva + CALL_OFFSET) for rva, _ in SITES],
            'skipped_null_paths': c.c_uint64.from_address(_state['memory'] + PAGE_SIZE).value}


def install():
    global _state
    with _lock:
        if _state is not None:
            for address, value in _state['calls']:
                if c.string_at(address, len(value)) != value:
                    raise RuntimeError('Frida USB guard instructions changed')
            return snapshot()
        import frida
        if os.name != 'nt' or c.sizeof(c.c_void_p) != 8 or frida.__version__ != '17.17.0':
            raise RuntimeError('Frida USB guard requires Windows x64 and Frida 17.17.0')
        path = Path(frida._frida.__file__).resolve()
        if hashlib.sha256(path.read_bytes()).hexdigest() != FRIDA_SHA256:
            raise RuntimeError('Unsupported Frida binary; refusing the USB guard')
        base = K.GetModuleHandleW(str(path))
        if not base:
            raise c.WinError(c.get_last_error())
        for rva, expected in SITES:
            if c.string_at(base + rva, len(expected)) != expected:
                raise RuntimeError('Unexpected libusb instructions at ' + hex(rva))
        if _usb_started():
            raise RuntimeError('Initialize the USB guard before using the Frida device manager')

        memory = _reserve_near(base)
        published = False
        try:
            code = _stub(memory, base + COMPARE_RVA)
            c.memmove(memory, code, len(code))
            ignored = w.DWORD()
            if not K.VirtualProtect(memory, PAGE_SIZE, 0x20, c.byref(ignored)):
                raise c.WinError(c.get_last_error())
            if not K.FlushInstructionCache(K.GetCurrentProcess(), memory, len(code)):
                raise c.WinError(c.get_last_error())
            calls = [(base + rva + CALL_OFFSET,
                      _relative(0xe8, base + rva + CALL_OFFSET, memory)) for rva, _ in SITES]
            page = (base + SITES[0][0]) & ~(PAGE_SIZE - 1)
            original_protection = w.DWORD()
            if not K.VirtualProtect(page, PAGE_SIZE, 0x40, c.byref(original_protection)):
                raise c.WinError(c.get_last_error())
            try:
                try:
                    for address, value in calls:
                        c.memmove(address, value, len(value))
                    if not K.FlushInstructionCache(K.GetCurrentProcess(), page, PAGE_SIZE):
                        raise c.WinError(c.get_last_error())
                except BaseException:
                    for rva, expected in SITES:
                        original = expected[CALL_OFFSET:CALL_OFFSET + 5]
                        c.memmove(base + rva + CALL_OFFSET, original, len(original))
                    K.FlushInstructionCache(K.GetCurrentProcess(), page, PAGE_SIZE)
                    raise
                published = True
            finally:
                if not K.VirtualProtect(page, PAGE_SIZE, original_protection.value, c.byref(ignored)):
                    raise c.WinError(c.get_last_error())
            _state = {'memory': memory, 'calls': calls, 'native_module': frida._frida}
            return snapshot()
        finally:
            # Published code stays valid for all later device-manager sessions.
            if not published:
                K.VirtualFree(memory, 0, 0x8000)
