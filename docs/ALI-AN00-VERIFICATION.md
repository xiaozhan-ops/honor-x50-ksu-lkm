# ALI-AN00 target verification

How the offsets in `exploit/src/targets/annap-ALI-AN00_9.0.0.220/target.h` were
established, and what remains unproven.

> Two boot images are now in play — AN 9.0.0.220 and TN 9.0.0.230. This
> document covers the extraction method and the single-boot analysis. For the
> two-boot comparison and the per-version `SLIDE_RT_SCHED_CLASS_OFF` difference,
> see **docs/ALI-AN00-TN-COMPARISON.md**.


> The 80 GT target profiles this analysis compares against are no longer
> shipped in this repository (see NOTICE). Their numbers are kept here as the
> measurement record the X50 offsets were derived from.

## Summary

All 9 kernel symbols the exploit depends on were read directly out of this
device's `boot.img` and **all 9 match the sibling 80 GT profile byte-for-byte**,
even though the two kernels have different sublevel hashes.

| | |
| :--- | :--- |
| Device | Honor X50, ALI-AN00 |
| Firmware | MagicOS 9.0.0.230 |
| Kernel (this device) | `5.10.236-android12-9-gf68ed03ce0d2` |
| Kernel (80 GT profile) | `5.10.236-android12-9-gd671cf8c2b02` |
| Kernel (device README) | `5.10.236-android12-9-g4b262e5255ed` |
| Symbols extracted | 140,046 |
| Offsets matched | **9 / 9** |
| Hardware tested | **No** |

Note that three different kernel hashes circulate for what may be one firmware:
the device README, the 80 GT profile, and the boot image itself. Hashes differ
between any two builds, so they do not by themselves prove different sources —
the boot image is simply the authority here, being the artifact that actually
boots. The differences sit in the vendor sublevel, below the GKI 5.10.236 base.

## Extraction procedure

Reproducible from scratch:

```bash
# 1. slice the kernel Image out of boot.img
#    ANDROID! header v0, header occupies one 4096-byte page
#    kernel_size = 51771404 at header offset 8
dd if=boot.img of=Image bs=4096 skip=1 count=12640 2>/dev/null   # see script below

# 2. build and run the kallsyms extractor
gcc -O2 kallsyms.c -o kallsyms
./kallsyms Image > kallsyms.txt          # 140,046 symbols

# 3. compare against the target profile
python docs/verify_offsets.py kallsyms.txt
```

The slice step in full, since the header page size field reads 0 and the
`MZ` bytes at the kernel start are coincidental:

```python
import struct
d = open("boot.img", "rb").read()
kernel_size = struct.unpack_from("<I", d, 8)[0]      # 51771404
img = d[4096:4096 + kernel_size]
assert img[0x38:0x3c] == b"ARM\x64"                  # arm64 Image magic at +0x38
open("Image", "wb").write(img)
```

`Image[0:2]` reads as `MZ`, which looks like a PE header and is not one. The
real arm64 magic `ARM\x64` sits at `+0x38`, and `+0x08` holds `text_offset=0`.
Do not let the `MZ` bytes send you down the wrong path.

## Symbol comparison

Raw kallsyms addresses, minus `KIMAGE_TEXT_BASE = 0xffffffc008000000`:

| Symbol | This device | 80 GT profile | Match |
| :--- | :--- | :--- | :--- |
| `init_task` | `0x281bf80` | `0x281bf80` | yes |
| `init_cred` | `0x2830c18` | `0x2830c18` | yes |
| `root_task_group` | `0x2d54080` | `0x2d54080` | yes |
| `selinux_state` | `0x2e84b38` | `0x2e84b38` | yes |
| `sig_enforce` | `0x2bbfd80` | `0x2bbfd80` | yes |
| `g_rscan_skip_flag` | `0x2e8889c` | `0x2e8889c` | yes |
| `nfulnl_logger` | `0x2811430` | `0x2811430` | yes |
| `commit_creds` | `0x355258` | `0x355258` | yes |
| `random_table` | `0x2c4a5c0` | (boot_id ctl at `0x2c4a6c0`) | base matches |

Also confirmed present and consistent:

| Symbol | This device |
| :--- | :--- |
| `sysctl_bootid` | `0x2e9cedd` (matches the `LINK_BOOTID_BUF_ADDR` in both profiles) |
| `loggers` | `0x2811358` (matches) |
| `rt_sched_class` | `0x2344ae0` |
| `idle_sched_class` | `0x2344920` |
| `fair_sched_class` | `0x2344a00` |
| `dl_sched_class` | `0x2344bc0` |
| `stop_sched_class` | `0x2344ca0` |

## Kernel config (from `extract-ikconfig`, 7091 lines)

```
CONFIG_CFI_CLANG=y
CONFIG_CFI_CLANG_SHADOW=y
# CONFIG_CFI_PERMISSIVE is not set
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_ASHMEM=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
```

Two consequences worth stating plainly:

- **`CONFIG_FUTEX_PI=y`** — this is the only config CVE-2026-43499 needs. It is
  on, so the device is in scope.
- **`CONFIG_MODULE_SIG_FORCE=y`** — unsigned modules are blocked at runtime.
  This is why the chain must flip `sig_enforce` to 0 before `init_module`, and
  why the loader restores it to 1 afterwards.

### Why the IonStack route was abandoned

The first attempt at this port used
[sarabpal-dev/IonStack-S22U](https://github.com/sarabpal-dev/IonStack-S22U) as
the template. That was wrong for this device, for two reasons:

1. **Wrong exploitation path.** IonStack builds its arbitrary R/W primitive by
   hijacking `ashmem_misc.fops` + configfs buffer fields. GhostLock instead
   hijacks the `boot_id` sysctl ctl_table. Different primitives, different
   post-exploitation paths.
2. **Wrong post-root delivery.** IonStack restores fops and starts a root umh
   daemon. GhostLock writes `task->cred = init_cred`, calls `commit_creds`,
   loads a KernelSU module, then restores SELinux enforcing as the last step.
   The shipped `payload/` in this project is a KernelSU-based build, so the
   GhostLock route is also the one that matches the artifact we actually have.

The abandoned IonStack scaffold was left out of this repository. Nothing from
it is used here.

## Build status

Both profiles compile clean with NDK r29 — zero errors, four binaries produced.
Full output and the Makefile fix required for Windows hosts are in
**docs/ALI-AN00-TN-COMPARISON.md** (section "Build verified").

```bash
cd exploit
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-AN00_9.0.0.220 bin
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-TN00_9.0.0.230 bin
```

`make -n bin` resolves each profile and generates the full compile line; an
unknown `PROJECT` is rejected by the Makefile's `$(error ...)`. Each `target.h`
also compiles standalone (`gcc -fsyntax-only`, exit 0).

That each build really sees its own offsets is confirmed through the
preprocessor:

```bash
echo '#include "target.h"
MARKER SLIDE_RT_SCHED_CLASS_OFF' | \
  $NDK_TOOLCHAIN/bin/aarch64-linux-android35-clang -E -P -x c - -I src/targets/<PROJECT>
# AN-220 -> MARKER 0x23445e0ULL
# TN-230 -> MARKER 0x23447e0ULL
```

## What is still unverified

**kallsyms validates kernel addresses. It cannot validate struct layouts.**
Field offsets live in DWARF type info, which this vendor kernel Image does not
carry. The following are inherited from the 80 GT profile and are unproven on
ALI-AN00:

| Group | Offsets | Why it matters |
| :--- | :--- | :--- |
| `FAKE_TASK_*` | `usage` `0x40`, `prio` `0x84`, `normal_prio` `0x8c`, `sched_class` `0x98`, `pi_lock` `0x8b4`, `pi_waiters` `0x8b8`, `pi_top_task` `0x8c8`, `pi_blocked_on` `0x8d0` | `pi_blocked_on` is the field the UAF leaves dangling and the one the exploit writes. Wrong value → silent failure. |
| `FAKE_WAITER_*` / `WAITER_*` | `task` `0x30`, `lock` `0x38`, `prio` `0x40`, `deadline` `0x48`, `pi_tree_entry` `0x18` | Forged waiter must pass the kernel's structural checks. |
| `TASK_CRED_OFF` | `0x7b8` | The cred write target. |
| `MM_OWNER_OFF` | `0x348` | Anchor selection. |
| `SLIDE_MCAST_OPT_DEFAULT` | `44` | Race choreography timing. |
| `CTL_BOOTID_ENTRY_OFF` | `0x2c4a6c0` | `random_table + 0x100`. Table base confirmed; the `+0x100` is inherited. |

`CONFIG_DEBUG_RT_MUTEXES` is off, so 5.10's waiter really is the 80-byte layout
with no `wake_state`/`ww_ctx` — that part is sound by config, not by assumption.

How to settle them, in order of cost:

1. **Run it.** If the UAF fires and the chain stalls, `pi_blocked_on` and the
   waiter offsets are the suspects. `kmsg_dumper` in `ksu/tools/` will show
   whether the kernel took the forged pointers.
2. **Live kallsyms read.** With root, compare `&init_task->pi_blocked_on`
   against `0x8d0` by reading the symbol address + offset at runtime.
3. **GDB against a matching debug build.** Only if a `vmlinux` with matching
   `CONFIG_DEBUG_INFO` exists. Not expected for a vendor Image.

If a first run fails, `SLIDE_CARRIER_MCAST` can be switched to the pselect
carrier — the GhostLock binary in `payload/` contains both `slide_pselect_*`
and `slide_mcast_*` thread families, and `env_defaults.h` will show which
carrier the static build defaults to.

## Result to expect

Not 100% per run. The upstream README reports the chain verified on real devices
for versions marked verified, with failures rebooting the phone and the setup
script retrying. `boot_id`, `ctl.data`, and `sig_enforce` are all restored on
the way out; a reboot also restores everything.

Back up the device first. This is unsigned kernel memory corruption on the
running kernel.