# Unreleased

- Guard null device paths in two bundled libusb comparisons inside the hash-locked Frida 17.17.0 controller. Original native fragments reproduce the captured `0xC0000409 / FAST_FAIL_INVALID_ARG`; guarded fragments preserve valid comparisons and local attachment.
- Apply this process-local dependency fix before device discovery in both cleanup modes, expose its status and skip count, and gracefully upgrade older running controllers on Start. No emulator restart is required for the controller update.
- Correct stale guard status after controller exit and add controller exception diagnostics. A real run lost its controller without an exit record; the cause remains unconfirmed.
- Launch the guard through a current-user Windows scheduled task with unlimited execution time and recorded exit results. Migrate the old owned Startup shortcut; graceful Stop pauses the task, and Start re-enables it. Automatic failure recovery remains unverified.
- Add explicit unlimited duration (`--minutes 0`) and a combined semaphore/NVIDIA guard that revalidates new emulator processes, supports graceful stop and optional user-login startup, and bounds diagnostic logs.
- Add Windows guard lifecycle and session tests; keep the existing native driver cleanup and semaphore patch bytes unchanged.
- Confirm a NVIDIA 616.64 cleanup-order defect in the tested LD14 workload: driver thread detach creates a new mimalloc heap after TLS cleanup.
- Add an opt-in, hash-locked native cleanup prototype and Chinese installation/rollback instructions under `experimental/`.
- Verify a 12-cycle A/B/A comparison with 13, 0, and 13 newly retained heaps; validate the packaged prototype and native ownership guards.
- Keep the existing semaphore release unchanged. Long-running game validation and other driver versions remain pending.

# 0.1.0-alpha.1 - 2026-09-05

First experimental community release.

- Fix the missing first-semaphore CloseHandle in the hash-locked MyRenderThread destructor.
- Restrict changes to one explicitly configured LD14 process, with restart rollback.
- Reject unsupported installations, renderer hashes, and unexpected instructions.
- Add configurable launchers, status reports, and a bounded read-only CSV recorder.
- Include Chinese installation, diagnosis, roadmap, and contribution documentation.
- Add Windows tests for native handle behavior and target-selection guards.

Known limitation: large private-memory growth and display blackouts remain unresolved. Long-running and cross-environment testing is pending.
