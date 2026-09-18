'use strict';

const driver = Process.getModuleByName('nvoglv64.dll');
const rvas = DRIVER_PROFILE.rvas;
const counts = Memory.alloc(16);
counts.writeByteArray(new Uint8Array(16));
const native = new CModule(`
#include <gum/guminterceptor.h>
#include <glib.h>
extern volatile gint counts[];
extern guint32 tls_index;
extern guint8 empty_heap[];
extern guint8 main_heap[];
extern void *current_teb(void);
extern void thread_done(void *heap);

static guint8 *default_heap(guint8 *teb) {
    guint8 **vector = *(guint8 ***) (teb + 0x58);
    guint8 *tls = vector ? vector[tls_index] : NULL;
    return tls ? *(guint8 **) (tls + 0x10) : NULL;
}

void on_enter(GumInvocationContext *ctx) {
    guint64 *reason = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(guint64));
    *reason = (guint64) gum_invocation_context_get_nth_argument(ctx, 1);
}

void on_leave(GumInvocationContext *ctx) {
    guint64 *reason = gum_invocation_context_get_listener_invocation_data(ctx, sizeof(guint64));
    if (*reason != 3) return;
    g_atomic_int_add(&counts[0], 1);
    guint8 *teb = current_teb();
    guint8 *heap = default_heap(teb);
    if (heap == empty_heap || heap == main_heap) return;
    guint8 *tld = heap ? *(guint8 **) heap : NULL;
    if (!tld || *(guint64 *) tld == 0) return;
    if (*(guint8 **) tld != teb || *(guint8 **) (tld + 0x20) != heap) {
        g_atomic_int_add(&counts[3], 1);
        return;
    }
    // DllMain can allocate a new heap after the earlier TLS detach callback.
    thread_done(NULL);
    g_atomic_int_add(&counts[1], 1);
    heap = default_heap(teb);
    tld = heap ? *(guint8 **) heap : NULL;
    if (tld && *(guint8 **) tld == teb) g_atomic_int_add(&counts[2], 1);
}
`, {counts, tls_index: driver.base.add(rvas.tls_index), current_teb: driver.base.add(rvas.current_teb),
    thread_done: driver.base.add(rvas.thread_done), empty_heap: driver.base.add(rvas.empty_heap),
    main_heap: driver.base.add(rvas.main_heap)});

const hook = Interceptor.attach(driver.base.add(rvas.entry), {
    onEnter: native.on_enter, onLeave: native.on_leave
});

function status() {
    return {thread_detaches: counts.readU32(), cleaned_heaps: counts.add(4).readU32(),
        cleanup_still_owned: counts.add(8).readU32(), owner_mismatch: counts.add(12).readU32()};
}

rpc.exports = {
    status,
    stop() { hook.detach(); Interceptor.flush(); return status(); }
};
send({ready: true, marker: 'LD14-NVIDIA-TLS-CLEANUP-EXPERIMENT-2', pid: Process.id,
    driver_version: DRIVER_PROFILE.version, driver_sha256: DRIVER_PROFILE.sha256});
