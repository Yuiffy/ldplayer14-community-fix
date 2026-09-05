# 0.1.0-alpha.1 - 2026-09-05

First experimental community release.

- Fix the missing first-semaphore CloseHandle in the hash-locked MyRenderThread destructor.
- Restrict changes to one explicitly configured LD14 process, with restart rollback.
- Reject unsupported installations, renderer hashes, and unexpected instructions.
- Add configurable launchers, status reports, and a bounded read-only CSV recorder.
- Include Chinese installation, diagnosis, roadmap, and contribution documentation.
- Add Windows tests for native handle behavior and target-selection guards.

Known limitation: large private-memory growth and display blackouts remain unresolved. Long-running and cross-environment testing is pending.
