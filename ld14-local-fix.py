"""Version-locked, process-local fix for MyRenderThread's missing CloseHandle."""

import argparse
import csv
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent
VERSION = '0.1.0-alpha.1'
CONFIG = ROOT / 'ld14-fix.config.json'
CONSOLE = None
INSTANCE = None
FASTPIPE_SHA256 = 'dd8eeea7484b5ca49d7bae70622f5c53878a627a4cd31cc97cf3f31dba610125'
RENDERER_SHA256 = 'e6d99bc45ae98baa17b3ad3ed9f17d7c5b576279ad07f16b70ef5fdfd06c660f'
K = c.WinDLL('kernel32', use_last_error=True)
N = c.WinDLL('ntdll')
P = c.WinDLL('psapi')


class ModuleEntry(c.Structure):
    _fields_ = [('dwSize', w.DWORD), ('th32ModuleID', w.DWORD), ('th32ProcessID', w.DWORD),
                ('GlblcntUsage', w.DWORD), ('ProccntUsage', w.DWORD), ('modBaseAddr', c.c_void_p),
                ('modBaseSize', w.DWORD), ('hModule', w.HMODULE), ('szModule', w.WCHAR * 256),
                ('szExePath', w.WCHAR * 260)]


class MemoryCounters(c.Structure):
    _fields_ = [('cb', w.DWORD), ('PageFaultCount', w.DWORD)] + [
        (name, c.c_size_t) for name in ['PeakWorkingSetSize', 'WorkingSetSize',
        'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
        'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage']]


K.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
K.OpenProcess.restype = w.HANDLE
K.CloseHandle.argtypes = [w.HANDLE]
K.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
K.CreateToolhelp32Snapshot.restype = w.HANDLE
K.Module32FirstW.argtypes = [w.HANDLE, c.POINTER(ModuleEntry)]
K.Module32NextW.argtypes = [w.HANDLE, c.POINTER(ModuleEntry)]
K.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
K.WriteProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
K.VirtualProtectEx.argtypes = [w.HANDLE, c.c_void_p, c.c_size_t, w.DWORD, c.POINTER(w.DWORD)]
K.FlushInstructionCache.argtypes = [w.HANDLE, c.c_void_p, c.c_size_t]
K.GetProcessHandleCount.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
P.GetProcessMemoryInfo.argtypes = [w.HANDLE, c.POINTER(MemoryCounters), w.DWORD]
N.NtSuspendProcess.argtypes = [w.HANDLE]
N.NtSuspendProcess.restype = c.c_long
N.NtResumeProcess.argtypes = [w.HANDLE]
N.NtResumeProcess.restype = c.c_long


def jump(source, destination):
    return b'\xe9' + struct.pack('<i', destination - source - 5)


# Both stubs occupy unreachable alignment padding in the original destructor.
# Keeping them in the same function preserves its existing x64 unwind metadata.
PATCHES = [
    (0x609e2, bytes.fromhex('662e0f1f8400000000000f1f4000'),
     bytes.fromhex('488b8fb8040000ffd6') + jump(0x609eb, 0x60a71)),
    (0x60a71, bytes.fromhex('662e0f1f8400000000000f1f440000'),
     bytes.fromhex('488b8fc0040000') + jump(0x60a78, 0x60b06) + b'\x90' * 3),
    (0x60aff, bytes.fromhex('488b8fc0040000'), jump(0x60aff, 0x609e2) + b'\x90' * 2),
]
GUARDS = [
    (0x60990, bytes.fromhex('5541574156415541545657534883ec48')),
    (0x604e0, bytes.fromhex('55415741565657534883ec68488d6c24')),
]

# Each renderer and fastpipe pair was analyzed independently. The 14.0.31.0
# constructor/destructor retain the original control flow and object layout,
# but both functions moved by 0x180. Never infer offsets from a version string.
RENDERER_PROFILES = {
    RENDERER_SHA256: {
        'version': '14.0.26.1', 'fastpipe_sha256': FASTPIPE_SHA256,
        'patches': PATCHES, 'guards': GUARDS,
    },
    '02c318f5c07ad8699ccdd72eb3bf9db18b515a23b618bb8d7c1dc6c0d4f7d288': {
        'version': '14.0.31.0',
        'fastpipe_sha256': 'fa1421cdac5315bc9b5bba36761545cbc92a9f20b2ee18cd0921f08af320701f',
        'patches': [
            (0x60b62, bytes.fromhex('662e0f1f8400000000000f1f4000'),
             bytes.fromhex('488b8fb8040000ffd6') + jump(0x60b6b, 0x60bf1)),
            (0x60bf1, bytes.fromhex('662e0f1f8400000000000f1f440000'),
             bytes.fromhex('488b8fc0040000') + jump(0x60bf8, 0x60c86) + b'\x90' * 3),
            (0x60c7f, bytes.fromhex('488b8fc0040000'), jump(0x60c7f, 0x60b62) + b'\x90' * 2),
        ],
        'guards': [
            (0x60b10, bytes.fromhex('5541574156415541545657534883ec48')),
            (0x60660, bytes.fromhex('55415741565657534883ec68488d6c24')),
            (0x60c6f, bytes.fromhex('488b8f60040000488b35f30c9700ffd6')),
        ],
    },
}


def console(*arguments):
    result = subprocess.run([str(CONSOLE), *arguments], capture_output=True, timeout=15,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError('LD14 console failed: ' + str(result.returncode))
    return result.stdout.decode('gb18030', errors='replace')


def list_instances():
    result = []
    for fields in csv.reader(console('list2').splitlines()):
        if len(fields) >= 7 and fields[0].isdigit():
            result.append({'index': int(fields[0]), 'name': fields[1],
                           'pid': max(0, int(fields[6]))})
    return result


def backend_pid():
    for instance in list_instances():
        if instance['index'] == INSTANCE:
            return instance['pid']
    raise RuntimeError('Configured LD14 instance was not found: ' + str(INSTANCE))


def verify_installation(path):
    candidate = Path(path).expanduser()
    if candidate.is_dir():
        candidate /= 'ldconsole.exe'
    if candidate.name.lower() != 'ldconsole.exe' or not candidate.is_file():
        raise RuntimeError('Select the LD14 installation folder or its ldconsole.exe')
    pipe = candidate.parent / 'gpu' / 'fastpipe2.dll'
    supported_pipes = {profile['fastpipe_sha256'] for profile in RENDERER_PROFILES.values()}
    if not pipe.is_file() or hashlib.sha256(pipe.read_bytes()).hexdigest() not in supported_pipes:
        raise RuntimeError('Unsupported LD14 installation; fastpipe2.dll does not match the validated build')
    return candidate.resolve()


def read_config():
    if not CONFIG.exists():
        return {}
    value = json.loads(CONFIG.read_text(encoding='utf-8-sig'))
    if not isinstance(value, dict):
        raise RuntimeError('Configuration must be a JSON object')
    return value


def configure(args, saved):
    global CONSOLE, INSTANCE
    selected = args.console or saved.get('console')
    if args.setup and not args.console:
        entered = input('LD14 folder or ldconsole.exe path' +
                        (' [' + str(selected) + ']' if selected else '') + ': ').strip().strip('"')
        selected = entered or selected
    if not selected:
        raise RuntimeError('Run Setup-LD14-Fix.cmd first, or supply --console and --index')
    CONSOLE = verify_installation(selected)
    INSTANCE = args.index if args.index is not None else saved.get('index')
    if args.setup:
        available = list_instances()
        print(json.dumps(available, ensure_ascii=False, indent=2))
        if args.index is None:
            entered = input('Instance index' + (' [' + str(INSTANCE) + ']' if INSTANCE is not None else '') + ': ').strip()
            INSTANCE = int(entered) if entered else INSTANCE
        if not isinstance(INSTANCE, int) or isinstance(INSTANCE, bool) or INSTANCE < 0:
            raise RuntimeError('Select a non-negative instance index from the list')
        if INSTANCE not in {item['index'] for item in available}:
            raise RuntimeError('Instance index is not in this LD14 installation')
        CONFIG.write_text(json.dumps({'console': str(CONSOLE), 'index': INSTANCE}, indent=2), encoding='utf-8')
        print('Saved local configuration: ' + str(CONFIG))
        return
    if not args.list and (not isinstance(INSTANCE, int) or isinstance(INSTANCE, bool) or INSTANCE < 0):
        raise RuntimeError('Run setup or supply a non-negative --index')


def modules(pid):
    snap = K.CreateToolhelp32Snapshot(0x18, pid)
    if snap == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    result = {}
    try:
        entry = ModuleEntry()
        entry.dwSize = c.sizeof(entry)
        ok = K.Module32FirstW(snap, c.byref(entry))
        while ok:
            result[entry.szModule.lower()] = {'base': entry.modBaseAddr, 'path': entry.szExePath}
            ok = K.Module32NextW(snap, c.byref(entry))
        return result
    finally:
        K.CloseHandle(snap)


def verify_target(pid):
    loaded = modules(pid)
    renderer = loaded.get('libopenglrender2.dll')
    pipe = loaded.get('fastpipe2.dll')
    if not renderer or not pipe:
        return None
    if Path(pipe['path']).resolve() != (CONSOLE.parent / 'gpu' / 'fastpipe2.dll').resolve():
        raise RuntimeError('The backend is not using the expected LD14 fastpipe2.dll')
    digest = hashlib.sha256(Path(renderer['path']).read_bytes()).hexdigest()
    profile = RENDERER_PROFILES.get(digest)
    if profile is None:
        raise RuntimeError('Unsupported renderer version; no patch was applied. SHA256=' + digest)
    if hashlib.sha256(Path(pipe['path']).read_bytes()).hexdigest() != profile['fastpipe_sha256']:
        raise RuntimeError('Renderer and fastpipe2.dll are not a validated pair; no patch was applied')
    return {**renderer, 'sha256': digest}


def inspect_or_apply(pid, renderer, apply):
    digest = renderer['sha256']
    profile = RENDERER_PROFILES[digest]
    patches = profile['patches']
    guards = profile['guards']
    access = 0xc38 if apply else 0x410
    handle = K.OpenProcess(access, False, pid)
    if not handle:
        raise c.WinError(c.get_last_error())
    base = renderer['base']

    def read(rva, length):
        buffer = c.create_string_buffer(length)
        used = c.c_size_t()
        if not K.ReadProcessMemory(handle, base + rva, buffer, length, c.byref(used)) or used.value != length:
            raise c.WinError(c.get_last_error())
        return buffer.raw

    def write(rva, value):
        buffer = c.create_string_buffer(value, len(value))
        used = c.c_size_t()
        if not K.WriteProcessMemory(handle, base + rva, buffer, len(value), c.byref(used)) or used.value != len(value):
            raise c.WinError(c.get_last_error())

    def status():
        for rva, expected in guards:
            if read(rva, len(expected)) != expected:
                raise RuntimeError('Unexpected function entry or active instrumentation at ' + hex(rva))
        current = [read(rva, len(original)) for rva, original, replacement in patches]
        if all(value == replacement for value, (_, _, replacement) in zip(current, patches)):
            return 'patched'
        if all(value == original for value, (_, original, _) in zip(current, patches)):
            return 'original'
        raise RuntimeError('Unexpected or partially patched code; restart LD14 before proceeding')

    def metrics():
        memory = MemoryCounters()
        memory.cb = c.sizeof(memory)
        count = w.DWORD()
        if not P.GetProcessMemoryInfo(handle, c.byref(memory), memory.cb):
            raise c.WinError(c.get_last_error())
        if not K.GetProcessHandleCount(handle, c.byref(count)):
            raise c.WinError(c.get_last_error())
        return {'private_bytes': memory.PrivateUsage, 'private_gib': round(memory.PrivateUsage / 1024**3, 6),
                'working_set_bytes': memory.WorkingSetSize,
                'working_set_gib': round(memory.WorkingSetSize / 1024**3, 6), 'handles': count.value}

    try:
        before = status()
        report = {'version': VERSION, 'time': datetime.now().astimezone().isoformat(), 'pid': pid, 'before': before,
                  'renderer_sha256': digest, 'renderer_version': profile['version'], 'renderer_path': renderer['path'],
                  'base': hex(base), 'instance': INSTANCE, 'scope': 'Configured LD14 instance, current process only',
                  'metrics': metrics()}
        if not apply or before == 'patched':
            report['after'] = before
            return report
        suspended = False
        writable = False
        old_protection = w.DWORD()
        page = base + 0x60000
        started = time.perf_counter()
        try:
            result = N.NtSuspendProcess(handle)
            if result < 0:
                raise RuntimeError('NtSuspendProcess failed: ' + hex(result & 0xffffffff))
            suspended = True
            if status() != 'original':
                raise RuntimeError('Code changed while preparing the patch')
            if not K.VirtualProtectEx(handle, page, 0x1000, 0x40, c.byref(old_protection)):
                raise c.WinError(c.get_last_error())
            writable = True
            try:
                # Publish the entry jump last, after both stubs are ready.
                for rva, original, replacement in patches:
                    write(rva, replacement)
                if not K.FlushInstructionCache(handle, page, 0x1000):
                    raise c.WinError(c.get_last_error())
                if status() != 'patched':
                    raise RuntimeError('Patch verification failed')
            except BaseException:
                # No target thread has executed the stubs while suspended.
                for rva, original, replacement in reversed(patches):
                    write(rva, original)
                K.FlushInstructionCache(handle, page, 0x1000)
                raise
        finally:
            try:
                if writable:
                    ignored = w.DWORD()
                    if not K.VirtualProtectEx(handle, page, 0x1000, old_protection.value, c.byref(ignored)):
                        raise c.WinError(c.get_last_error())
            finally:
                if suspended:
                    result = N.NtResumeProcess(handle)
                    if result < 0:
                        raise RuntimeError('NtResumeProcess failed: ' + hex(result & 0xffffffff))
        report['pause_ms'] = round((time.perf_counter() - started) * 1000, 3)
        report['after'] = status()
        report['patches'] = [{'rva': hex(rva), 'original': original.hex(), 'replacement': replacement.hex()}
                             for rva, original, replacement in patches]
        return report
    finally:
        K.CloseHandle(handle)


def save_report(report):
    directory = ROOT / 'logs'
    directory.mkdir(exist_ok=True)
    path = directory / ('ld14-fix-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.json')
    path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return str(path)


def monitor(pid, renderer, minutes, interval):
    directory = ROOT / 'logs'
    directory.mkdir(exist_ok=True)
    path = directory / ('ld14-stats-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.csv')
    deadline = time.monotonic() + minutes * 60
    fields = ['time', 'pid', 'patch_status', 'private_bytes', 'private_gib',
              'working_set_bytes', 'working_set_gib', 'handles']
    print('Read-only recording. Stop with Ctrl+C. Output: ' + str(path), flush=True)
    try:
        with path.open('w', newline='', encoding='utf-8-sig') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            while True:
                if backend_pid() != pid:
                    print('Instance stopped or restarted; recording ended without mixing processes.', flush=True)
                    break
                report = inspect_or_apply(pid, renderer, False)
                row = {'time': report['time'], 'pid': pid, 'patch_status': report['after'], **report['metrics']}
                writer.writerow(row)
                stream.flush()
                print(json.dumps(row), flush=True)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(interval, remaining))
    except KeyboardInterrupt:
        print('Recording stopped; existing CSV rows are saved.', flush=True)
    print('CSV: ' + str(path), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--console', help='LD14 installation folder or ldconsole.exe')
    parser.add_argument('--index', type=int, help='Instance index from ldconsole list2')
    parser.add_argument('--save', action='store_true', help='Save a local JSON status report')
    parser.add_argument('--minutes', type=float, default=240, help='Read-only monitor duration, at most 1440 minutes')
    parser.add_argument('--interval', type=float, default=60, help='Monitor sampling interval, at least 1 second')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--setup', action='store_true', help='Configure the local LD14 installation and instance')
    actions.add_argument('--list', action='store_true', help='List instances without modifying processes')
    actions.add_argument('--check', action='store_true', help='Read-only patch status (default)')
    actions.add_argument('--apply', action='store_true', help='Patch the configured running LD14 instance')
    actions.add_argument('--start', action='store_true', help='Launch the configured LD14 instance if needed, then patch it')
    actions.add_argument('--monitor', action='store_true', help='Record memory and handles without modifying the process')
    args = parser.parse_args(argv)
    if c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('64-bit Python is required')
    if args.monitor and (not 0 < args.minutes <= 1440 or not 1 <= args.interval <= 3600):
        parser.error('monitor requires 0 < minutes <= 1440 and 1 <= interval <= 3600')
    configure(args, read_config())
    if args.setup:
        return
    if args.list:
        print(json.dumps(list_instances(), ensure_ascii=False, indent=2))
        return
    pid = backend_pid()
    if not pid and args.start:
        console('launch', '--index', str(INSTANCE))
    elif not pid:
        raise RuntimeError('The configured LD14 instance is not running')
    deadline = time.monotonic() + (120 if args.start else 5)
    renderer = None
    while time.monotonic() < deadline:
        pid = backend_pid()
        if pid:
            renderer = verify_target(pid)
            if renderer:
                break
        time.sleep(1)
    if not renderer:
        raise RuntimeError('Timed out waiting for the LD14 renderer')
    if args.monitor:
        monitor(pid, renderer, args.minutes, args.interval)
        return
    report = inspect_or_apply(pid, renderer, args.apply or args.start)
    if args.apply or args.start or args.save:
        report['report'] = save_report(report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
