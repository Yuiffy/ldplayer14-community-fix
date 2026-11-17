"""Developer tool: regenerate fingerprints only from reviewed exact binaries."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('compatibility_engine', ROOT / 'compatibility/engine.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--renderer', required=True)
    parser.add_argument('--pipe', required=True)
    parser.add_argument('--driver', required=True)
    args = parser.parse_args()
    renderer, pipe, driver = [engine.Image(p) for p in (args.renderer, args.pipe, args.driver)]
    expected = ['cf97012df87e43398b7946abacce012448dd914e7ee546a7aabec690fd351cf6',
                '60dd3b2ab06204de47f5f339a2d35ad4da534a03d5d89d67537bd698cbe37484',
                'b57e4c1e92950fbba9bdfc9267e0951b633a16a9b2f4700a7b1194b2d3365642']
    engine.require([i.sha256 for i in (renderer, pipe, driver)] == expected,
                   'Baseline creation is restricted to the manually validated 2026-11-17 binaries')
    try:
        driver_graph = engine.build_graph(driver, {
            'entry': (0x10a5458, None), 'thread_done': (0xa9bef0, 354),
            'current_teb': (0xa9c060, 10), 'tls_detach': (0xaa3830, 26),
            'dllmain': (0xa3ec30, 817), 'thread_init': (0xa9bd50, None),
            'thread_data_init': (0xa9c0c0, None), 'tld_create': (0xa9c1d0, None)})
        driver_graph['mode'] = 'graph'
    except engine.Incompatible as error:
        # Unsupported dispatch tables are a proof boundary, not permission to
        # drop dependencies. Fall back to exact non-resource image identity.
        driver_graph = {'mode': 'image-equivalent', 'source_sha256': driver.sha256,
                        'identity': engine.pipe_identity(driver), 'graph_stop_reason': str(error)}
    result = {'schema': engine.ENGINE_VERSION, 'renderer': engine.build_graph(renderer, {
        'constructor': (0x60660, 882), 'destructor': (0x60b10, 524)}),
        'driver': driver_graph,
        'driver_rvas': {'entry': 0x10a5458, 'thread_done': 0xa9bef0, 'current_teb': 0xa9c060,
                        'tls_index': 0x2784df8, 'empty_heap': 0x1a972c0, 'main_heap': 0x2678280},
        'driver_guards': [[rva, driver.read(rva, size).hex()] for rva, size in
                          [(0x10a5458, 14), (0xa9bef0, 9), (0xa9c060, 10),
                           (0xa9bef9, 6), (0xa9bf3b, 7), (0xa9bf9f, 7)]],
        'pipe_identity': engine.pipe_identity(pipe), 'pipe_sha256': pipe.sha256}
    # No file contents or full instruction streams are included: hashes,
    # graph topology, nine-byte anchors and structural metadata only.
    output = ROOT / 'compatibility/baseline-v1.json'
    output.write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
    print(json.dumps({'path': str(output), 'sha256': engine.digest(output.read_bytes()),
                      'renderer_nodes': len(result['renderer']['nodes']),
                      'driver_mode': result['driver']['mode'],
                      'driver_nodes': len(result['driver'].get('nodes', {}))}, indent=2))


if __name__ == '__main__':
    main()
