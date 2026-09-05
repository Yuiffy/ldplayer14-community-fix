"""Opt-in NVIDIA 616.64 thread cleanup experiment; not a stable release."""

import argparse
import ctypes as c
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
DRIVER_SHA256 = '970bb2528b3c12867997ac1b344eb6b9b356e18bc8a1ad768238e3306b58a4c9'
GUARDS = (
    (0x107d678, bytes.fromhex('48895c24084889742410574883ec20')),
    (0xa7f2d0, bytes.fromhex('40535741564883ec40')),
    (0xa7f440, bytes.fromhex('65488b042530000000c3')),
)


def load_existing_helper():
    spec = importlib.util.spec_from_file_location('ld14_local_fix', ROOT / 'ld14-local-fix.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--console')
    parser.add_argument('--index', type=int)
    parser.add_argument('--apply', action='store_true', help='Enable the temporary native callback')
    parser.add_argument('--minutes', type=float, default=240)
    parser.add_argument('--interval', type=float, default=30)
    parser.set_defaults(setup=False, list=False)
    args = parser.parse_args()
    if sys.platform != 'win32' or c.sizeof(c.c_void_p) != 8:
        parser.error('Windows and 64-bit Python are required')
    if not 0 < args.minutes <= 1440 or not 1 <= args.interval <= 3600:
        parser.error('minutes must be 0..1440 and interval 1..3600')
    fix = load_existing_helper()
    fix.configure(args, fix.read_config())
    pid = fix.backend_pid()
    if not pid:
        raise RuntimeError('Start the configured LD14 instance first')
    renderer = fix.verify_target(pid)
    if renderer is None:
        raise RuntimeError('LD14 renderer is not ready')
    driver = fix.modules(pid).get('nvoglv64.dll')
    if driver is None:
        raise RuntimeError('NVIDIA OpenGL driver is not loaded')
    if hashlib.sha256(Path(driver['path']).read_bytes()).hexdigest() != DRIVER_SHA256:
        raise RuntimeError('Unsupported NVIDIA driver; this experiment requires the exact validated 616.64 DLL')
    handle = fix.K.OpenProcess(0x410, False, pid)
    if not handle:
        raise c.WinError(c.get_last_error())

    def check_code():
        for rva, expected in GUARDS:
            data = c.create_string_buffer(len(expected))
            used = c.c_size_t()
            if not fix.K.ReadProcessMemory(handle, driver['base'] + rva, data, len(expected), c.byref(used)):
                raise c.WinError(c.get_last_error())
            if used.value != len(expected) or data.raw != expected:
                raise RuntimeError('Unexpected driver code or another active hook at ' + hex(rva))

    try:
        check_code()
        baseline = fix.inspect_or_apply(pid, renderer, False)
        if not args.apply:
            print(json.dumps({'validated': True, 'applied': False, 'pid': pid,
                              'driver_sha256': DRIVER_SHA256, 'metrics': baseline['metrics']}, indent=2))
            return
        try:
            import frida
        except ImportError as error:
            raise RuntimeError('Install the dependency first: py -3 -m pip install frida==17.17.0') from error
        if frida.__version__ != '17.17.0':
            raise RuntimeError('The validated Frida version is 17.17.0')
        output_dir = ROOT / 'logs'
        output_dir.mkdir(exist_ok=True)
        output = output_dir / ('nvidia-cleanup-experiment-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.json')
        report = {'marker': 'LD14-NVIDIA-TLS-CLEANUP-EXPERIMENT-1', 'pid': pid,
                  'start': datetime.now().astimezone().isoformat(), 'options': vars(args),
                  'driver_sha256': DRIVER_SHA256, 'baseline': baseline['metrics'], 'samples': [], 'messages': []}
        detached = threading.Event()
        session = frida.attach(pid)
        session.on('detached', lambda *unused: detached.set())
        script = session.create_script(Path(__file__).with_suffix('.js').read_text(encoding='utf-8'))
        script.on('message', lambda message, data: report['messages'].append(message))
        loaded = False
        try:
            script.load()
            loaded = True
            if not any(m.get('payload', {}).get('ready') for m in report['messages']):
                raise RuntimeError('Native callback did not report its startup marker')
            print('EXPERIMENT ACTIVE for PID ' + str(pid) + '. Ctrl+C detaches it.', flush=True)
            deadline = time.monotonic() + args.minutes * 60
            while not detached.is_set():
                counters = script.exports_sync.status()
                row = {'time': datetime.now().astimezone().isoformat(), **counters,
                       **fix.inspect_or_apply(pid, renderer, False)['metrics']}
                report['samples'].append(row)
                output.write_text(json.dumps(report, indent=2), encoding='utf-8')
                print(json.dumps(row), flush=True)
                if counters['cleanup_still_owned'] or counters['owner_mismatch']:
                    raise RuntimeError('Unexpected heap state; stopping the experiment')
                left = deadline - time.monotonic()
                if left <= 0 or detached.wait(min(args.interval, left)):
                    break
        except KeyboardInterrupt:
            report['stop_reason'] = 'user_interrupt'
        except Exception as error:
            if detached.is_set():
                report['stop_reason'] = 'target_detached'
            else:
                report['error'] = str(error)
                raise
        finally:
            try:
                if not detached.is_set():
                    try:
                        if loaded:
                            report['final_counters'] = script.exports_sync.stop()
                            script.unload()
                            check_code()
                            report['driver_code_restored'] = True
                    finally:
                        session.detach()
            finally:
                report['end'] = datetime.now().astimezone().isoformat()
                output.write_text(json.dumps(report, indent=2), encoding='utf-8')
                print('Log: ' + str(output), flush=True)
    finally:
        fix.K.CloseHandle(handle)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
