
# Honor X50 (ALI-AN00): KernelSU LKM port on a locked bootloader

A working **KernelSU kernel-module (LKM) port** for the Honor X50
(ALI-AN00 / ALI-TN00), together with the privilege escalation required to load
it on a device whose bootloader cannot be unlocked.

The port is the substance. [`port/`](port/) turns a one-shot uid 0 into `su` for
authorised apps, a Manager that actually talks to the kernel, and per-app
authorisation — on a vendor kernel (5.10.236) that has no matching source release
and does not export much of what KernelSU calls. Engineering write-up:
[docs/LKM-PORT.md](docs/LKM-PORT.md).

The escalation is the enabling step: CVE-2026-43499, a use-after-free in the
kernel `rtmutex` `remove_waiter` path, used to obtain a controlled 8-byte write
and then swap `cred` for `init_cred`.

Kernel-address offsets in both target profiles were measured from **this
device's own boot images** rather than copied from another model.

## What makes the port hard

Worth reading even if you never run it:

* 91 kernel symbols resolved at runtime through naked asm trampolines. The
  obvious C function-pointer macro compiles fine, passes every test you can run
  without hardware, and **hard-resets the device**: compiler-generated indirect
  calls carry CFI type hashes, and Honor's HISEC treats a mismatch as an attack.
* `sys_call_table` on this kernel points at `.cfi_jt` thunks, not at
  `__arm64_sys_ni_syscall`, so the usual "find a free slot" scan finds nothing.
* Registering the `sys_enter` tracepoint against a local copy of the struct
  succeeds, returns 0, and never fires. The hook has to go on the real symbol.
* `track_throne()` resets the device from module init and is fine from a
  workqueue.

Root is still **per boot**: the cred swap and the module both live in RAM.
`port/host/restore.ps1` re-runs the chain, and has to start within about a minute
of boot.


## Targets

| Profile | Device | Firmware | Kernel |
| :--- | :--- | :--- | :--- |
| `annap-ALI-AN00_9.0.0.220` | Honor X50 (ALI-AN00) | MagicOS 9.0.0.220, build CNC00E206R9P4 | `5.10.236-android12-9-gf68ed03ce0d2` |
| `annap-ALI-TN00_9.0.0.230` | Honor X50 (ALI-TN00) | MagicOS 9.0.0.230 | `5.10.236-android12-9-g4b262e5255ed` |

Offsets were extracted with `kallsyms.c` from the kernel Image sliced out of
each boot dump (140,046 symbols each).

**Pick the profile matching the firmware actually on the device.** The two
differ where it matters: 11 of the 16 kernel symbols the exploit reads are
identical, but the whole `sched_class` group shifts by `0x200`, which moves
`SLIDE_RT_SCHED_CLASS_OFF` — the value stamped into `fake_task->sched_class` to
defuse `check_class_changed()`. Using the wrong profile's value leaves a
wild-pointer call in the `rt_mutex_setprio` tail.

Before flashing, confirm which firmware you are on:

```bash
adb shell getprop ro.build.display.id
adb shell uname -a
```

Firmware version strings are **not** recoverable from inside the boot images —
neither dump contains `build.prop`, `MagicOS`, or `ALI-*` strings. The version
labels above rest on how the dumps were sourced; the kernel hashes are measured.

## Build

Requires an Android NDK. Both profiles build clean with r29:

```bash
cd exploit
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-AN00_9.0.0.220 bin
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-TN00_9.0.0.230 bin
```

Outputs, per profile, under `exploit/build/<PROJECT>/bin/`:

| File | Size | Use |
| :--- | :--- | :--- |
| `exploit` | ~65 KB | PIE dynamic, run over `adb shell` |
| `exploit_static` | ~2.2 MB | fully static bionic, self-contained |

The Makefile detects the NDK host tag (`windows-x86_64`, `darwin-x86_64`,
`linux-x86_64`) rather than assuming Linux, so no extra flags are needed on
Windows.

## Run

Everything runs from the device. Push the release bundle and start the exploit
stage:

```bash
cd release
./setup.sh              # detects the running kernel, picks the matching profile
```

`setup.sh` matches the running kernel against the bundled manifest, runs the
chain, and retries when an attempt fails. A failed attempt reboots the phone;
re-running is normally enough.

After a successful jailbreak the KernelSU manager is opened automatically. The
chain restores `sig_enforce`, SELinux enforcing, and the hijacked
`boot_id` ctl entry on the way out — and a reboot restores everything regardless.

Not 100% per run. A failed race usually means the anchor died before its cred
write landed; re-run.

## What is verified, and what is not

**Measured on this device** (see [docs/](docs/)):

- all 16 kernel symbols the exploit reads, per profile
- `CONFIG_FUTEX_PI=y` — the only kernel option CVE-2026-43499 requires, so the
  device is in scope
- `CONFIG_MODULE_SIG_FORCE=y` — why the chain flips `sig_enforce` to 0 before
  `init_module`, and restores it afterwards
- `CONFIG_CFI_CLANG=y`, non-permissive
- both profiles compile, and each build resolves its own offsets

**Not verified:**

- **Struct-layout offsets.** kallsyms resolves kernel addresses; it carries no
  type information, so `FAKE_TASK_*` (including `pi_blocked_on`, the field the
  UAF leaves dangling), `WAITER_*`, `TASK_CRED_OFF`, `MM_OWNER_OFF`, and the
  `random_table + 0x100` boot_id entry offset are inherited from the reference
  profile and **not confirmed on this device**. Each is flagged inline in
  `target.h`.
- **`SLIDE_RT_SCHED_CLASS_OFF` for ALI-AN00** is derived
  (`rt_sched_class - 0x500`), not measured. The `0x500` relationship is
  confirmed on the other profile; re-derive this one first if a run panics in
  `check_class_changed()`.
- **No run on real hardware yet.**

## Documentation

- **[docs/ALI-AN00-TN-COMPARISON.md](docs/ALI-AN00-TN-COMPARISON.md)** — the two
  boot images compared symbol by symbol, the `sched_class` shift, build
  verification, and reproduction steps
- **[docs/ALI-AN00-VERIFICATION.md](docs/ALI-AN00-VERIFICATION.md)** — extraction
  procedure and provenance of every offset
- **[docs/ALI-AN00-SYMBOLS.txt](docs/ALI-AN00-SYMBOLS.txt)** — measured symbol
  table for both boots plus the relevant `kernel config`
- **[docs/cmp_boots.py](docs/cmp_boots.py)**,
  **[docs/verify_offsets.py](docs/verify_offsets.py)** — reproducible comparisons

## Why a custom .ko and loader

`CONFIG_MODULE_SIG_FORCE=y` means the runtime `sig_enforce` flag blocks unsigned
module loads. The exploit flips it to 0 for the load; the loader script restores
it to 1 once the module is in.

Honor also strips `commit_creds` and friends from `/proc/kallsyms`, so the
kernel loader cannot resolve the `.ko`'s undefined symbols. The flow bind-mounts
a fake kallsyms with the stripped symbols prepended at their true runtime
addresses (link address + KASLR slide).

GKI struct layouts also differ from Honor's, so the stock GKI
`android12-5.10_kernelsu.ko` cannot be used. `ksu/` rebuilds KernelSU against
MagicOS kernel source matching the firmware sublevel and the device's own kernel
config. See [`ksu/README.md`](ksu/README.md).

## Credits

This X50 port builds on the exploit and target framework from
[yakidango-official/GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT),
which in turn derives from:

- [NebuSec/CyberMeowfia — IonStack / CVE-2026-43499](https://github.com/NebuSec/CyberMeowfia)
  (the original public exploit; the rtmutex UAF was found by VEGA at Nebula
  Security and fixed upstream in commit `3bfdc63936dd`, Linux 7.1)
- [BuSung-dev/CVE-2026-43499-S25U](https://github.com/BuSung-dev/CVE-2026-43499-S25U)
- [F-19-F/IonStackQuest3](https://github.com/F-19-F/IonStackQuest3)
- [KernelSU](https://github.com/tiann/KernelSU)
- [Magisk](https://github.com/topjohnwu/Magisk)

Struct-layout offsets in the X50 profiles are carried over from the reference
project's 80 GT profiles. That project was the source of the extraction workflow
(`kallsyms.c`) reused here. Full provenance is in [NOTICE](NOTICE).

## Attribution

Built with assistance from **DeepSeek-V4.1-Flash** — 此项目由 DeepSeek-V4.1-Flash 提供。

## License

- The exploit and tooling in this repository (`exploit/`, top-level `docs/`) are
  under the **Apache License 2.0** (see [LICENSE](LICENSE)), matching the
  upstream project this port derives from.
- The files under [`ksu/`](ksu/) are **GPL-2.0** (see [ksu/LICENSE](ksu/LICENSE)):
  `init-bootid.patch` and `ksu_rules.annotated` derive from KernelSU's `kernel/`
  directory, which is GPL-2.0.
- [`port/kernelsu-3.3.0-honor-5.10.226.patch`](port/) patches that GPL-2.0 tree
  and is therefore **GPL-2.0** too. `port/build.sh` and `port/fix-versions.py`
  ship under the same terms so the module build stays under one licence. The
  rest of `port/` (host and device tooling) is Apache-2.0.
- Shipping a built `kernelsu.ko` obliges you to offer its source — KernelSU
  v3.3.0 plus this patch — to whoever receives the binary.

## Warning

For security research on your own device. Running this modifies kernel memory
through a UAF; a failed attempt reboots the phone. Root is full control of the
device. Flashes, partition writes, and disabling protections after rooting are
not covered by this tool and can permanently brick a device.

Use the profile that matches your firmware. Several struct offsets in both X50
profiles are inherited from another Honor model and are marked `UNVERIFIED` in
the headers; a wrong value does not fail loudly, it either dies silently mid-chain
or writes a cred pointer somewhere unintended. Confirm the build first:

```bash
adb shell getprop ro.build.display.id
adb shell uname -a
```

Root here is temporary by construction: the cred swap and the kernel module both
live in RAM, and a reboot undoes everything. There is no persistent install, and
none is possible without an unlocked bootloader.