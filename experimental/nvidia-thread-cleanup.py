"""Opt-in NVIDIA thread cleanup for two exact validated DLLs; not a stable release."""

import argparse
import ctypes as c
from datetime import datetime
import hashlib
import importlib.util
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'LD14-NVIDIA-TLS-CLEANUP-EXPERIMENT-2'
# Profiles are selected only by the complete on-disk DLL hash. No pattern scan
# or command-line offset override is used in a running emulator.
DRIVERS = {
    '970bb2528b3c12867997ac1b344eb6b9b356e18bc8a1ad768238e3306b58a4c9': {
        'version': '616.64',
        'rvas': {'entry': 0x107d678, 'tls_index': 0x2d424e8,
                 'current_teb': 0xa7f440, 'thread_done': 0xa7f2d0,
                 'empty_heap': 0x1af4a00, 'main_heap': 0x2c3af00},
        'guards': ((0x107d678, bytes.fromhex('48895c24084889742410574883ec20')),
                   (0xa7f2d0, bytes.fromhex('40535741564883ec40')),
                   (0xa7f440, bytes.fromhex('65488b042530000000c3')),
                   (0xa7f2d9, bytes.fromhex('8b3d09322c02')),
                   (0xa7f31b, bytes.fromhex('488d2dde560701')),
                   (0xa7f37f, bytes.fromhex('4c8d3d7abb1b02'))),
    },
    '693f471a56bb374ff04cefbf4a67a082974a32627d5145f5b1f2d6418736cf6a': {
        'version': '616.92',
        'rvas': {'entry': 0x107d828, 'tls_index': 0x2d554e8,
                 'current_teb': 0xa7f440, 'thread_done': 0xa7f2d0,
                 'empty_heap': 0x1af4a00, 'main_heap': 0x2c4df00},
        'guards': ((0x107d828, bytes.fromhex('48895c24084889742410574883ec20')),
                   (0xa7f2d0, bytes.fromhex('40535741564883ec40')),
                   (0xa7f440, bytes.fromhex('65488b042530000000c3')),
                   (0xa7f2d9, bytes.fromhex('8b3d09622d02')),
                   (0xa7f31b, bytes.fromhex('488d2dde560701')),
                   (0xa7f37f, bytes.fromhex('4c8d3d7aeb1c02'))),
    },
}
RECENT_SAMPLES = 120


def select_driver(path):
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    profile = DRIVERS.get(digest)
    if profile is None:
        raise RuntimeError('Unsupported NVIDIA driver; exact validated 616.64 or 616.92 DLL required (SHA256 ' + digest + ')')
    return digest, profile


def build_script(digest, profile):
    configuration = {'sha256': digest, 'version': profile['version'], 'rvas': profile['rvas']}
    return ("'use strict';\nconst DRIVER_PROFILE = " + json.dumps(configuration) + ';\n' +
            Path(__file__).with_suffix('.js').read_text(encoding='utf-8'))


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    temporary.replace(path)


def record_sample(report, row, output, history=None):
    report['sample_count'] = report.get('sample_count', 0) + 1
    report['samples'].append(row)
    if report['options']['minutes'] == 0:
        del report['samples'][:-RECENT_SAMPLES]
    if history is not None:
        history.emit(logging.LogRecord('ld14.samples', logging.INFO, '', 0,
                                      json.dumps(row), (), None))
    write_json(output, report)


def wait_for_end(detached, stop_event, seconds):
    deadline = time.monotonic() + seconds
    while not detached.is_set():
        if stop_event is not None and stop_event.is_set():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        detached.wait(min(1, remaining))
    return True


def load_existing_helper():
    spec = importlib.util.spec_from_file_location('ld14_local_fix', ROOT / 'ld14-local-fix.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_frida():
    name = 'ld14_frida_usb_guard'
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name('frida-usb-guard.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[name] = module
    module.install()
    return module


def main(argv=None, *, stop_event=None, on_sample=None, output=None, expected_pid=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--console')
    parser.add_argument('--index', type=int)
    parser.add_argument('--apply', action='store_true', help='Enable the temporary native callback')
    parser.add_argument('--with-semaphore', action='store_true', help='Also apply the validated semaphore fix')
    parser.add_argument('--minutes', type=float, default=240, help='Duration in minutes; 0 runs until stopped or target exits')
    parser.add_argument('--interval', type=float, default=30)
    parser.add_argument('--quiet', action='store_true', help='Write logs without console sampling output')
    parser.set_defaults(setup=False, list=False)
    args = parser.parse_args(argv)
    if sys.platform != 'win32' or c.sizeof(c.c_void_p) != 8:
        parser.error('Windows and 64-bit Python are required')
    if not 0 <= args.minutes <= 1440 or not 1 <= args.interval <= 3600:
        parser.error('minutes must be 0..1440 (0 means no timeout) and interval 1..3600')
    if args.with_semaphore and not args.apply:
        parser.error('--with-semaphore requires --apply')

    def emit(value):
        if not args.quiet and sys.stdout is not None:
            print(value, flush=True)

    fix = load_existing_helper()
    fix.configure(args, fix.read_config())
    pid = fix.backend_pid()
    if not pid:
        raise RuntimeError('Start the configured LD14 instance first')
    if expected_pid is not None and pid != expected_pid:
        raise RuntimeError('Configured LD14 process changed before attachment')
    renderer = fix.verify_target(pid)
    if renderer is None:
        raise RuntimeError('LD14 renderer is not ready')
    driver = fix.modules(pid).get('nvoglv64.dll')
    if driver is None:
        raise RuntimeError('NVIDIA OpenGL driver is not loaded')
    driver_sha256, profile = select_driver(driver['path'])
    handle = fix.K.OpenProcess(0x410, False, pid)
    if not handle:
        raise c.WinError(c.get_last_error())

    def check_code():
        for rva, expected in profile['guards']:
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
            result = {'validated': True, 'applied': False, 'pid': pid,
                      'driver_sha256': driver_sha256, 'driver_version': profile['version'],
                      'metrics': baseline['metrics']}
            emit(json.dumps(result, indent=2))
            return result
        try:
            import frida
        except ImportError as error:
            raise RuntimeError('Install the dependency first: py -3 -m pip install frida==17.17.0') from error
        if frida.__version__ != '17.17.0':
            raise RuntimeError('The validated Frida version is 17.17.0')
        usb_guard = prepare_frida()
        if stop_event is not None and stop_event.is_set():
            return {'stop_reason': 'guard_stop'}
        output_dir = output.parent if output is not None else ROOT / 'logs'
        output_dir.mkdir(exist_ok=True)
        if output is None:
            output = output_dir / ('nvidia-cleanup-experiment-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.json')
        report = {'marker': MARKER, 'pid': pid,
                  'start': datetime.now().astimezone().isoformat(), 'options': vars(args),
                  'driver_sha256': driver_sha256, 'driver_version': profile['version'],
                  'baseline': baseline['metrics'], 'samples': [], 'messages': []}
        if args.with_semaphore:
            report['semaphore_fix'] = fix.inspect_or_apply(pid, renderer, True)
            report['semaphore_report'] = fix.save_report(report['semaphore_fix'])
        history = None
        if args.minutes == 0:
            history = RotatingFileHandler(output.with_suffix('.jsonl'), maxBytes=4 * 1024**2,
                                          backupCount=3, encoding='utf-8')
            report['history'] = str(output.with_suffix('.jsonl'))
            report['recent_sample_limit'] = RECENT_SAMPLES
        detached = threading.Event()
        session = None
        script = None
        loaded = False
        try:
            session = frida.attach(pid)
            session.on('detached', lambda *unused: detached.set())
            script = session.create_script(build_script(driver_sha256, profile))
            script.on('message', lambda message, data: report['messages'].append(message))
            script.load()
            loaded = True
            if not any(m.get('payload', {}).get('ready') and
                       m['payload'].get('marker') == MARKER and
                       m['payload'].get('driver_sha256') == driver_sha256 and
                       m['payload'].get('driver_version') == profile['version']
                       for m in report['messages']):
                raise RuntimeError('Native callback did not report its startup marker')
            duration = 'no time limit' if args.minutes == 0 else str(args.minutes) + ' minutes'
            emit('EXPERIMENT ACTIVE for PID ' + str(pid) + ' (' + duration + '). Ctrl+C detaches it.')
            deadline = None if args.minutes == 0 else time.monotonic() + args.minutes * 60
            while not detached.is_set():
                if stop_event is not None and stop_event.is_set():
                    report['stop_reason'] = 'guard_stop'
                    break
                counters = script.exports_sync.status()
                inspection = fix.inspect_or_apply(pid, renderer, False)
                row = {'time': datetime.now().astimezone().isoformat(), 'pid': pid, **counters,
                       'semaphore_patch': inspection['after'], 'frida_usb_guard': usb_guard.snapshot(),
                       **inspection['metrics']}
                record_sample(report, row, output, history)
                if counters['cleanup_still_owned'] or counters['owner_mismatch']:
                    raise RuntimeError('Unexpected heap state; stopping the experiment')
                if args.with_semaphore and inspection['after'] != 'patched':
                    raise RuntimeError('Semaphore patch is no longer present')
                if on_sample is not None:
                    on_sample(report, row)
                emit(json.dumps(row))
                left = args.interval if deadline is None else deadline - time.monotonic()
                if left <= 0:
                    report['stop_reason'] = 'duration_elapsed'
                    break
                if wait_for_end(detached, stop_event, min(args.interval, left)):
                    report['stop_reason'] = 'target_detached' if detached.is_set() else 'guard_stop'
                    break
            report.setdefault('stop_reason', 'target_detached')
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
                if session is not None and not detached.is_set():
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
                try:
                    write_json(output, report)
                finally:
                    if history is not None:
                        history.close()
                emit('Experiment ended: ' + report.get('stop_reason', 'error') + '. Log: ' + str(output))
        return report
    finally:
        fix.K.CloseHandle(handle)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(1)
