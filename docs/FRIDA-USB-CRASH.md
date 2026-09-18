# Frida USB notification crash

## Evidence

A Windows crash dump captured the Frida 17.17.0 controller terminating in
`_frida.pyd + 0xec975c` with `0xC0000409`, subcode 5 (`FAST_FAIL_INVALID_ARG`).
The failing thread was the bundled libusb Windows device notification loop,
not the NVIDIA callback running in the separate LD14 process.

The stack returns through `_frida + 0xdc42ba`, immediately after the arrival
loop's `_stricmp(priv->path, change->device_name)` call. Disassembly shows its
null-argument branch leading to the CRT invalid-parameter failure. The exact
bundled source omits a null check in both arrival and removal loops. The
minidump does not contain the relevant heap objects, so it cannot establish
which of the two pointers was null or which device caused the notification.

Source references:

- [Frida 17.17.0 dependency revision](https://github.com/frida/frida-core/blob/17.17.0/subprojects/libusb.wrap)
- [libusb removal comparison](https://github.com/frida/libusb/blob/ffff4bdfe8faa38cecfad5aab106cae923502d55/libusb/os/windows_hotplug.c#L133)
- [libusb arrival comparison](https://github.com/frida/libusb/blob/ffff4bdfe8faa38cecfad5aab106cae923502d55/libusb/os/windows_hotplug.c#L160)
- [Default device-manager backends](https://github.com/frida/frida-core/blob/17.17.0/src/host-session-service.vala)

Frida's default device manager starts nonlocal discovery alongside the local
backend. Local process attachment can therefore encounter USB notification
failures even when the application never asks to connect to a USB device.

Before this failure, 165 consecutive samples over 82 minutes showed private
commit between 4.27 and 5.47 GiB, with 1,566 cleaned thread heaps and no cleanup
ownership errors. After the controller crashed, the same LD14 process grew to
about 9.99 GiB. This supports continuing the memory experiment while addressing
the separate controller failure; it does not establish indefinite stability.

## Correction

`experimental/frida-usb-guard.py` redirects only the two device-list comparison
calls through a native null guard. Either null string yields a non-match, so
the existing loop skips that entry. Valid strings tail-call the original
`_stricmp`, preserving its case-insensitive behavior and Windows x64 ABI.

The dependency guard is installed before the first Frida device-manager use.
It validates the exact Windows x64 `_frida.pyd` SHA256 and both surrounding
instruction sequences. It also rejects late initialization after a libusb
event window is already present. The published code remains in the controller
for later LD14 sessions, including emulator restarts.

Only two five-byte call instructions in the current controller change. The
auxiliary allocation uses one executable, read-only code page and one writable
counter page, totaling 8 KiB. Disk files and USB hardware settings do not change.
The ordinary comparison routine, device-discovery behavior, NVIDIA callback,
and semaphore patch retain their existing logic.

Supported module:

```text
Frida: 17.17.0, Windows x64
_frida.pyd SHA256:
93638a16bf0a651c6fdc8f41228ce9069e7b79d56834cce7aec9f8b6639c671c
Guarded call RVAs: 0xdc423a, 0xdc42b5
Original comparator RVA: 0xec2e40
```

## Verification

`tests/test_frida_usb_guard.py` runs disposable processes. It copies the two
validated call-site fragments into a native fixture and resolves their call
targets from the actual loaded dependency. This exercises the original or
guarded comparator without changing physical devices or accessing LD14.

- Each original fragment, given a null device path, exits with the same
  `0xC0000409` recorded in the production dump.
- The installed guard passes 14 cases across the two paths: either null,
  both null, equal paths with different case, different paths and empty strings.
- Six null comparisons increment the counter exactly six times.
- Repeated initialization is idempotent; unsupported hashes and changed
  instruction signatures are rejected before writes.
- A guarded controller can attach to its own test child, execute an RPC and
  detach normally, then reuse the already-installed protection. Existing
  NVIDIA, semaphore and guard lifecycle tests pass.

Live deployment also verified the normal upgrade path: the older controller
recorded `driver_code_restored: true` and exited with code 0. The new controller
then attached to the same still-running LD14 process and reported both emulator
fixes and the dependency guard active. This upgrade did not restart LD14.

The deterministic fixture targets the observed null-argument failure. It does
not recreate the original hardware event or prove every libusb error is fixed.
The earlier controller disappearance without a dump remains unattributed.

## Updating

Update the full repository, then run `Start-LD14-Guard.cmd`. It gracefully
replaces a controller with an older marker and reattaches to the same LD14
process. `Check-LD14-Guard.cmd` should show `LD14-DUAL-FIX-GUARD-4` and
`frida_usb_guard.active: true`. `skipped_null_paths` starts at zero and counts
null comparisons handled by that controller.

The controller update does not require an emulator restart. A normal LD14
restart is useful to discard memory already retained during an unprotected
period and start a clean long-duration test. Stop and Uninstall continue to
remove the NVIDIA hook normally; the dependency guard disappears with its
Python process. Automatic recovery from unrelated controller crashes remains
unimplemented.
