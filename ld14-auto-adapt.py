"""Bounded local compatibility analysis. Reports are evidence, never trusted code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime

ROOT = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 90
REPORT_LIMIT = 8 * 1024 * 1024
_verified = {}
on_progress = None


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def analyze(kind, path, pipe=None):
    path = Path(path).resolve(strict=True)
    pipe = Path(pipe).resolve(strict=True) if pipe is not None else None
    identity = (kind, str(path), sha256(path), str(pipe), sha256(pipe) if pipe is not None else None)
    if identity in _verified:
        return _verified[identity]
    if on_progress is not None:
        on_progress(kind, str(path))
    report_dir = ROOT / 'logs/auto-adapt'
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / (kind + '-' + identity[2] + ('-' + identity[4] if pipe else '') + '.json')
    result = {'kind': kind, 'sha256': identity[2], 'compatible': False,
              'time': datetime.now().astimezone().isoformat()}
    try:
        with tempfile.TemporaryDirectory(prefix='ld14-auto-adapt-') as directory:
            output = Path(directory) / 'result.json'
            command = [sys.executable, str(ROOT / 'compatibility/worker.py'), '--kind', kind,
                       '--image', str(path), '--result', str(output)]
            if pipe is not None:
                command.extend(['--pipe', str(pipe)])
            env = dict(os.environ)
            env['PYTHONPATH'] = os.pathsep.join(p for p in sys.path if p)
            try:
                completed = subprocess.run(command, capture_output=True, timeout=TIMEOUT_SECONDS,
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), env=env)
            except subprocess.TimeoutExpired as error:
                raise RuntimeError('Automatic analysis timed out; target was not modified') from error
            if not output.is_file():
                detail = completed.stderr.decode('utf-8', errors='replace')[-1500:]
                raise RuntimeError('Automatic analyzer failed before producing a report: ' + detail)
            if output.stat().st_size > REPORT_LIMIT:
                raise RuntimeError('Automatic analysis report exceeds size limit')
            result.update(json.loads(output.read_text(encoding='utf-8')))
            if completed.returncode or not result.get('compatible'):
                raise RuntimeError(result.get('error', 'Automatic compatibility proof failed'))
            if result.get('schema') != 1 or result.get('sha256') != identity[2]:
                raise RuntimeError('Analyzer result does not identify the requested file')
            if kind != 'pipe' and not result.get('native_verified'):
                raise RuntimeError('Automatic native self-test did not pass')
            if pipe is not None and result.get('pipe_sha256') != identity[4]:
                raise RuntimeError('Analyzer result does not identify the requested fastpipe pair')
            if sha256(path) != identity[2] or (pipe is not None and sha256(pipe) != identity[4]):
                raise RuntimeError('Installed files changed before adaptation could be accepted')
        result['report'] = str(report_path)
        profile = dict(result.get('profile', {}))
        if profile:
            profile['guards'] = [(rva, bytes.fromhex(value)) for rva, value in profile['guards']]
            if 'patches' in profile:
                profile['patches'] = [(rva, bytes.fromhex(old), bytes.fromhex(new))
                                      for rva, old, new in profile['patches']]
            profile['auto_adaptation'] = {k: result[k] for k in
                ('schema', 'sha256', 'baseline_sha256', 'native_verified', 'elapsed_seconds', 'report')}
        # Save JSON before caching decoded bytes in memory. Disk reports are
        # never loaded to grant permission on a later guard run.
        temporary = report_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
        temporary.replace(report_path)
        _verified[identity] = profile or result
        return _verified[identity]
    except Exception as error:
        result.update(compatible=False, error=str(error), report=str(report_path))
        temporary = report_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
        temporary.replace(report_path)
        raise RuntimeError('Automatic adaptation stopped: ' + str(error) + '; report: ' + str(report_path)) from error


def set_enabled(enabled):
    path = ROOT / 'ld14-fix.config.json'
    saved = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(saved, dict) or not saved.get('console') or not isinstance(saved.get('index'), int):
        raise RuntimeError('Configure the LD14 installation and instance before enabling adaptation')
    saved['auto_adapt'] = enabled
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(saved, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)
    return saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    setting = parser.add_mutually_exclusive_group()
    setting.add_argument('--enable', action='store_true')
    setting.add_argument('--disable', action='store_true')
    parser.add_argument('--kind', choices=('pipe', 'renderer', 'driver'))
    parser.add_argument('--image', type=Path)
    parser.add_argument('--pipe', type=Path)
    args = parser.parse_args()
    if args.enable or args.disable:
        if args.kind or args.image or args.pipe:
            parser.error('Configuration and offline analysis are separate operations')
        saved = set_enabled(args.enable)
        print(json.dumps({'auto_adapt': saved['auto_adapt'], 'reload_guard_required': True}))
    elif args.kind and args.image:
        if (args.kind == 'renderer') != (args.pipe is not None):
            parser.error('--pipe is required only for renderer analysis')
        profile = analyze(args.kind, args.image, args.pipe)
        print(json.dumps(profile.get('auto_adaptation', profile), indent=2))
    else:
        parser.error('Choose --enable, --disable, or --kind with --image')


if __name__ == '__main__':
    main()
