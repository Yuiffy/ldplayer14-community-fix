"""Build an explicit-file-list release archive without loading Windows APIs."""

import ast
import hashlib
from pathlib import Path
import zipfile


def build(root):
    tree = ast.parse((root / 'ld14-local-fix.py').read_text(encoding='utf-8'))
    version = next(node.value.value for node in tree.body
                   if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                   and any(isinstance(target, ast.Name) and target.id == 'VERSION' for target in node.targets))
    name = 'LD14-Semaphore-Fix-' + version
    inputs = {item: item for item in [
        'ld14-local-fix.py', 'Run-LD14-Fix.cmd', 'Setup-LD14-Fix.cmd',
        'Start-LD14-Fixed.cmd', 'Check-LD14-Fix.cmd', 'Record-LD14-Stats.cmd',
        'CHANGELOG.md', 'LICENSE']}
    inputs['README.zh-CN.md'] = 'docs/INSTALL.zh-CN.md'
    payload = {}
    for filename, source in inputs.items():
        contents = (root / source).read_text(encoding='utf-8-sig')
        if filename.endswith('.cmd'):
            contents = contents.replace('\n', '\r\n')
        payload[filename] = contents.encode('utf-8')
    manifest = ''.join(hashlib.sha256(data).hexdigest() + '  ' + filename + '\n'
                       for filename, data in sorted(payload.items()))
    payload['SHA256SUMS.txt'] = manifest.encode('ascii')
    output = root / 'dist'
    output.mkdir(exist_ok=True)
    archive_path = output / (name + '.zip')
    with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name + '/' + filename, (2026, 9, 5, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (output / (name + '.sha256')).write_text(digest + '  ' + archive_path.name + '\n', encoding='ascii')
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Archive CRC check failed')
        for filename, data in payload.items():
            if archive.read(name + '/' + filename) != data:
                raise RuntimeError('Archive content mismatch: ' + filename)
    print(str(archive_path))
    print('SHA256: ' + digest)
    return archive_path


if __name__ == '__main__':
    build(Path(__file__).resolve().parents[1])
