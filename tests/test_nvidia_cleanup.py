"""Exercise the shipped native callback in a disposable child, without a GPU."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest

try:
    import frida
except ImportError:
    frida = None

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cleanup_native_tests', ROOT / 'experimental' / 'nvidia-thread-cleanup.py')
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)

FIXTURE = r'''
const fixtureData = Memory.alloc(4096);
const tlsIndex = Memory.alloc(4);
tlsIndex.writeU32(0);
const fixture = new CModule(`
#include <glib.h>
#include <string.h>
extern guint8 data[];
void *current_teb(void) { return data; }
void thread_done(void *heap) {
    (*(guint32 *) (data + 0xf00))++;
    *(guint8 **) (data + 0x210) = data + 0x300;
}
int target(void *module, int reason, void *reserved) {
    volatile int result = 0x12345678;
    result = result + reason - reason;
    return result;
}
void configure(int mode) {
    memset(data, 0, 4096);
    *(guint8 **) (data + 0x58) = data + 0x100;
    *(guint8 **) (data + 0x100) = data + 0x200;
    guint8 *heap = data + (mode == 0 ? 0x300 : mode == 1 ? 0x500 : 0x700);
    *(guint8 **) (data + 0x210) = mode == 5 ? NULL : heap;
    *(guint8 **) heap = data + 0x900;
    *(guint8 **) (data + 0x900) = mode == 2 ? data + 0x10 : data;
    *(guint8 **) (data + 0x920) = mode == 3 ? data + 0x500 : heap;
}
`, {data: fixtureData});
const offsets = new Map([
    [PROFILE_RVAS.tls_index, tlsIndex], [PROFILE_RVAS.current_teb, fixture.current_teb],
    [PROFILE_RVAS.thread_done, fixture.thread_done], [PROFILE_RVAS.entry, fixture.target],
    [PROFILE_RVAS.empty_heap, fixtureData.add(0x300)], [PROFILE_RVAS.main_heap, fixtureData.add(0x500)]
]);
const testDriver = {base: {add(rva) {
    if (!offsets.has(rva)) throw new Error('Unexpected driver offset');
    return offsets.get(rva);
}}};
const originalBytes = Array.from(new Uint8Array(fixture.target.readByteArray(16)));
const shipped = new Function('Process', SHIPPED_SOURCE + '\nreturn {native, counts, hook};')({id: Process.id, getModuleByName(name) {
    if (name !== 'nvoglv64.dll') throw new Error('Unexpected module lookup');
    return testDriver;
}});
const configure = new NativeFunction(fixture.configure, 'void', ['int']);
const target = new NativeFunction(fixture.target, 'int', ['pointer', 'int', 'pointer'], {traps: 'all'});
rpc.exports.runcase = function(mode, reason) {
    configure(mode);
    const before = rpc.exports.status();
    const returned = target(ptr(0), reason, ptr(0));
    const after = rpc.exports.status();
    return {returned, freeCalls: fixtureData.add(0xf00).readU32(),
        detached: after.thread_detaches - before.thread_detaches,
        cleaned: after.cleaned_heaps - before.cleaned_heaps,
        mismatch: after.owner_mismatch - before.owner_mismatch,
        stillOwned: after.cleanup_still_owned - before.cleanup_still_owned};
};
rpc.exports.restored = function() {
    rpc.exports.stop();
    return JSON.stringify(Array.from(new Uint8Array(fixture.target.readByteArray(16)))) === JSON.stringify(originalBytes);
};
'''


@unittest.skipUnless(sys.platform == 'win32' and frida is not None, 'Windows and optional Frida dependency required')
class NvidiaCleanupTests(unittest.TestCase):
    def test_native_ownership_and_detach_contract(self):
        for digest, profile in cleanup.DRIVERS.items():
            with self.subTest(driver=profile['version']):
                self.run_profile(digest, profile)

    def run_profile(self, digest, profile):
        child = subprocess.Popen([sys.executable, '-u', '-c', 'import sys; print("ready"); sys.stdin.readline()'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        session = None
        watchdog = threading.Timer(20, child.kill)
        watchdog.start()
        try:
            self.assertEqual(child.stdout.readline().strip(), b'ready')
            session = frida.attach(child.pid)
            source = cleanup.build_script(digest, profile)
            script = session.create_script('const PROFILE_RVAS = ' + json.dumps(profile['rvas']) + ';\n' +
                                           'const SHIPPED_SOURCE = ' + json.dumps(source) + ';\n' + FIXTURE)
            messages = []
            script.on('message', lambda message, data: messages.append(message))
            script.load()
            self.assertFalse([m for m in messages if m.get('type') == 'error'], messages)
            ready = next(m['payload'] for m in messages if m.get('payload', {}).get('ready'))
            self.assertEqual(ready['driver_version'], profile['version'])
            self.assertEqual(ready['driver_sha256'], digest)
            cases = [
                ('process-detach', 4, 0, 0, 0), ('process-attach', 4, 1, 0, 0),
                ('thread-attach', 4, 2, 0, 0), ('empty-heap', 0, 3, 0, 0),
                ('main-heap', 1, 3, 0, 0), ('foreign-owner', 2, 3, 0, 1),
                ('other-backing-heap', 3, 3, 0, 1), ('owned-heap', 4, 3, 1, 0),
                ('null-heap', 5, 3, 0, 0),
            ]
            for name, mode, reason, cleanups, mismatches in cases:
                with self.subTest(name=name):
                    row = script.exports_sync.runcase(mode, reason)
                    self.assertEqual(row['returned'], 0x12345678)
                    self.assertEqual(row['freeCalls'], cleanups)
                    self.assertEqual(row['cleaned'], cleanups)
                    self.assertEqual(row['mismatch'], mismatches)
                    self.assertEqual(row['stillOwned'], 0)
                    self.assertEqual(row['detached'], int(reason == 3))
            self.assertTrue(script.exports_sync.restored())
            script.unload()
        finally:
            if session is not None:
                session.detach()
            try:
                child.communicate(b'\n', timeout=5)
            finally:
                watchdog.cancel()
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
