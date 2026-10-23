"""Keep both validated process-local LD14 fixes active for one configured instance."""

import argparse
import ctypes as c
from ctypes import wintypes as w
from datetime import datetime
import faulthandler
import hashlib
import importlib.util
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import time
import traceback
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'logs' / 'guard'
STATUS = DIRECTORY / 'status.json'
HEARTBEAT_MAX_AGE = 90
K = c.WinDLL('kernel32', use_last_error=True)
K.CreateMutexW.argtypes = [c.c_void_p, w.BOOL, w.LPCWSTR]
K.CreateMutexW.restype = w.HANDLE
K.OpenMutexW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
K.OpenMutexW.restype = w.HANDLE
K.CreateEventW.argtypes = [c.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]
K.CreateEventW.restype = w.HANDLE
K.OpenEventW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
K.OpenEventW.restype = w.HANDLE
K.SetEvent.argtypes = [w.HANDLE]
K.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
K.WaitForSingleObject.restype = w.DWORD
K.CloseHandle.argtypes = [w.HANDLE]


def load_experiment():
    spec = importlib.util.spec_from_file_location('ld14_cleanup', Path(__file__).with_name('nvidia-thread-cleanup.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def control_name(console, index):
    identity = str(Path(console).resolve()).casefold() + ':' + str(index)
    return 'Local\\LD14CommunityFix-' + hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]


def is_running(name):
    handle = K.OpenMutexW(0x100000, False, name)
    if not handle:
        if c.get_last_error() != 2:
            raise c.WinError(c.get_last_error())
        return False
    K.CloseHandle(handle)
    return True


def request_stop(name):
    handle = K.OpenEventW(2, False, name + '-stop')
    if not handle:
        if c.get_last_error() != 2:
            raise c.WinError(c.get_last_error())
        return False
    try:
        if not K.SetEvent(handle):
            raise c.WinError(c.get_last_error())
        return True
    finally:
        K.CloseHandle(handle)


def status_view(snapshot, running, now=None):
    now = now or datetime.now().astimezone()
    try:
        age = (now - datetime.fromisoformat(snapshot['time'])).total_seconds()
    except (KeyError, TypeError, ValueError):
        age = None
    fresh = age is not None and 0 <= age <= HEARTBEAT_MAX_AGE
    if not running or not fresh:
        # Old samples are evidence, not a current measurement or a live hook check.
        value = {'state': 'not_running' if not running else 'unresponsive',
                 'nvidia_cleanup': False if not running else None,
                 'last_recorded': snapshot}
    else:
        value = dict(snapshot)
    value.update(running=running, checked_at=now.isoformat(),
                 heartbeat_age_seconds=round(age, 3) if age is not None else None)
    return value


class Control:
    def __init__(self, name):
        self.mutex = K.CreateMutexW(None, False, name)
        error = c.get_last_error()
        if not self.mutex:
            raise c.WinError(error)
        if error == 183:
            K.CloseHandle(self.mutex)
            self.mutex = None
            raise RuntimeError('A guard is already running for this LD14 instance')
        self.event = K.CreateEventW(None, True, False, name + '-stop')
        if not self.event:
            K.CloseHandle(self.mutex)
            self.mutex = None
            raise c.WinError(c.get_last_error())

    def wait(self, seconds):
        result = K.WaitForSingleObject(self.event, max(0, int(seconds * 1000)))
        if result == 0xffffffff:
            raise c.WinError(c.get_last_error())
        return result == 0

    def is_set(self):
        return self.wait(0)

    def close(self):
        K.CloseHandle(self.event)
        K.CloseHandle(self.mutex)


class StatusLog:
    def __init__(self, experiment, args):
        DIRECTORY.mkdir(parents=True, exist_ok=True)
        self.experiment = experiment
        self.base = {'marker': 'LD14-DUAL-FIX-GUARD-5', 'guard_pid': os.getpid(),
                     'parent_pid': os.getppid(), 'launcher': args.launcher,
                     'console': args.console, 'index': args.index, 'time_limit_minutes': None}
        self.handler = RotatingFileHandler(DIRECTORY / 'events.jsonl', maxBytes=512 * 1024,
                                          backupCount=2, encoding='utf-8')
        self.previous = None

    def update(self, state, **details):
        row = {**self.base, 'time': datetime.now().astimezone().isoformat(), 'state': state, **details}
        self.experiment.write_json(STATUS, row)
        transition = (state, details.get('target_pid'), details.get('error'))
        if transition != self.previous:
            self.handler.emit(logging.LogRecord('ld14.guard', logging.INFO, '', 0, json.dumps(row), (), None))
            self.previous = transition

    def close(self):
        self.handler.close()


def watch(fix, experiment, args, control, status):
    observed_pid = None
    blocked_pid = None
    blocked_error = None
    observed_at = 0
    while not control.is_set():
        try:
            pid = fix.backend_pid()
        except Exception as error:
            status.update('waiting_for_console', error=str(error))
            control.wait(5)
            continue
        if not pid:
            observed_pid = blocked_pid = None
            status.update('waiting_for_ld14')
            control.wait(5)
            continue
        if pid == blocked_pid:
            status.update('blocked', target_pid=pid, error=blocked_error)
            control.wait(5)
            continue
        if pid != observed_pid:
            observed_pid = pid
            observed_at = time.monotonic()
        try:
            renderer = fix.verify_target(pid)
            if renderer is None or 'nvoglv64.dll' not in fix.modules(pid):
                if time.monotonic() - observed_at > 120:
                    raise RuntimeError('LD14 renderer or NVIDIA driver did not become ready within 120 seconds')
                status.update('waiting_for_renderer', target_pid=pid)
                control.wait(2)
                continue
            status.update('applying', target_pid=pid)

            def sample(report, row):
                status.update('active', target_pid=pid, experiment_start=report['start'],
                              semaphore_patch=row['semaphore_patch'], nvidia_cleanup=True,
                              driver_version=report['driver_version'], driver_sha256=report['driver_sha256'],
                              frida_usb_guard=row['frida_usb_guard'],
                              sample_count=report['sample_count'], sample=row)

            result = experiment.main(['--apply', '--with-semaphore', '--minutes', '0', '--quiet',
                                      '--console', args.console, '--index', str(args.index)],
                                     stop_event=control, on_sample=sample,
                                     output=DIRECTORY / 'current-experiment.json', expected_pid=pid)
            if control.is_set() or result.get('stop_reason') == 'user_interrupt':
                return result
            # An unexpected detach must not repeatedly reapply to a still-live PID.
            blocked_pid = pid
            blocked_error = 'Session ended; waiting for a new LD14 process: ' + result.get('stop_reason', 'unknown')
            status.update('waiting_for_restart', target_pid=pid, session_end=result.get('stop_reason'))
        except Exception as error:
            blocked_pid = pid
            blocked_error = str(error)
            status.update('blocked', target_pid=pid, error=blocked_error)
        control.wait(5)
    return {}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--run', action='store_true')
    actions.add_argument('--status', action='store_true')
    actions.add_argument('--stop', action='store_true')
    parser.add_argument('--console')
    parser.add_argument('--index', type=int)
    parser.add_argument('--dependency-dir', type=Path, help='Optional local directory containing Frida 17.17.0')
    parser.add_argument('--launcher', default='direct', choices=('direct', 'task-scheduler'))
    args = parser.parse_args(argv)
    experiment = load_experiment()
    fix = experiment.load_existing_helper()
    saved = fix.read_config()
    selected = args.console or saved.get('console')
    args.index = args.index if args.index is not None else saved.get('index')
    if not selected or not isinstance(args.index, int) or isinstance(args.index, bool) or args.index < 0:
        parser.error('Configure LD14 first, or supply --console and --index')
    console = Path(selected).expanduser()
    if console.name.lower() != 'ldconsole.exe':
        console /= 'ldconsole.exe'
    args.console = str(console.resolve())
    name = control_name(args.console, args.index)
    if args.status or args.stop:
        snapshot = json.loads(STATUS.read_text(encoding='utf-8')) if STATUS.exists() else {}
        value = status_view(snapshot, is_running(name))
        if args.stop:
            value['stop_requested'] = request_stop(name)
        if sys.stdout is not None:
            print(json.dumps(value, indent=2), flush=True)
        return value
    control = Control(name)
    status = None
    try:
        status = StatusLog(experiment, args)
        status.update('starting')
        if args.dependency_dir is not None:
            sys.path.insert(0, str(args.dependency_dir.resolve(strict=True)))
        import frida
        if frida.__version__ != '17.17.0':
            raise RuntimeError('The validated Frida version is 17.17.0')
        fix.configure(SimpleNamespace(console=args.console, index=args.index, setup=False, list=False), saved)
        result = watch(fix, experiment, args, control, status)
        status.update('stopped', session_end=result.get('stop_reason'),
                      driver_code_restored=result.get('driver_code_restored'))
    except KeyboardInterrupt:
        if status is not None:
            status.update('stopped', session_end='user_interrupt')
    except Exception as error:
        if status is not None:
            status.update('failed', error=str(error))
        raise
    finally:
        if status is not None:
            status.close()
        control.close()


def run_cli():
    handler = None
    previous_stderr = sys.stderr
    exit_code = 0
    try:
        if '--run' in sys.argv[1:]:
            DIRECTORY.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(DIRECTORY / 'controller.log', maxBytes=512 * 1024,
                                          backupCount=2, encoding='utf-8')
            handler.emit(logging.LogRecord('ld14.controller', logging.INFO, '', 0, json.dumps({
                'marker': 'LD14-GUARD-CONTROLLER-3', 'event': 'start', 'pid': os.getpid(),
                'parent_pid': os.getppid(), 'time': datetime.now().astimezone().isoformat(),
            }), (), None))
            if sys.stderr is None:
                sys.stderr = handler.stream
            faulthandler.enable(file=handler.stream)
        main()
    except SystemExit as error:
        exit_code = error.code if isinstance(error.code, int) else 1
    except BaseException:
        exit_code = 1
        if sys.stderr is not None:
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
    finally:
        if handler is not None:
            faulthandler.disable()
            sys.stderr = previous_stderr
            handler.emit(logging.LogRecord('ld14.controller', logging.INFO, '', 0, json.dumps({
                'event': 'exit', 'pid': os.getpid(), 'exit_code': exit_code,
                'time': datetime.now().astimezone().isoformat(),
            }), (), None))
            handler.close()
    return exit_code


if __name__ == '__main__':
    sys.exit(run_cli())
