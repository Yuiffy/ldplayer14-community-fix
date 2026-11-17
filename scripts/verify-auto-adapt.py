"""Offline acceptance/refusal checks using disposable copies of local binaries."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

import pefile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('auto_acceptance_client', ROOT / 'ld14-auto-adapt.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in ('renderer', 'pipe', 'driver'):
        parser.add_argument('--' + kind, type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='ld14-compat-acceptance-') as directory:
        root = Path(directory)
        copies = {}
        originals = {}
        for kind in ('renderer', 'pipe', 'driver'):
            original = getattr(args, kind).read_bytes()
            originals[kind] = original
            data = bytearray(original)
            pe = pefile.PE(data=original)
            offset = pe.FILE_HEADER.get_field_absolute_offset('TimeDateStamp')
            struct.pack_into('<I', data, offset, pe.FILE_HEADER.TimeDateStamp ^ 1)
            copies[kind] = root / (kind + '.dll')
            copies[kind].write_bytes(data)
            assert client.sha256(copies[kind]) != client.sha256(getattr(args, kind))
        for kind in ('pipe', 'renderer', 'driver'):
            profile = client.analyze(kind, copies[kind], copies['pipe'] if kind == 'renderer' else None)
            result = profile.get('auto_adaptation', profile)
            results.append({'case': kind + '-unknown-hash-metadata-update', 'accepted': True,
                            'native_verified': result['native_verified'], 'sha256': result['sha256']})
        for kind in ('pipe', 'renderer', 'driver'):
            data = bytearray(copies[kind].read_bytes())
            pe = pefile.PE(data=data)
            if kind == 'renderer':
                offset = pe.get_offset_from_rva(0x60c7f + 3)  # destructor object field 0x4c0
            else:
                offset = next(s.PointerToRawData for s in pe.sections if s.Characteristics & 0x20000000)
            data[offset] ^= 1
            changed = root / (kind + '-changed.dll')
            changed.write_bytes(data)
            try:
                client.analyze(kind, changed, copies['pipe'] if kind == 'renderer' else None)
            except RuntimeError as error:
                results.append({'case': kind + '-changed-implementation', 'accepted': False, 'error': str(error)})
            else:
                raise AssertionError('Changed ' + kind + ' implementation was accepted')
        # Header-only TLS redirection must also fail even though section bytes
        # (including the old TLS directory) are completely unchanged.
        data = bytearray(copies['driver'].read_bytes())
        pe = pefile.PE(data=data)
        tls = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        struct.pack_into('<I', data, tls.get_field_absolute_offset('VirtualAddress'), tls.VirtualAddress + 8)
        changed = root / 'driver-changed-tls.dll'
        changed.write_bytes(data)
        try:
            client.analyze('driver', changed)
        except RuntimeError as error:
            results.append({'case': 'driver-changed-loader-tls', 'accepted': False, 'error': str(error)})
        else:
            raise AssertionError('Changed loader TLS directory was accepted')
        for kind, original in originals.items():
            assert getattr(args, kind).read_bytes() == original, 'Original binary was modified'
    output = ROOT / 'logs/auto-adapt/acceptance.json'
    output.write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps({'passed': len(results), 'report': str(output)}, indent=2))


if __name__ == '__main__':
    main()
