# Unreleased

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
