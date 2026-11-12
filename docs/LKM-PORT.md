# KernelSU LKM port for Honor X50 (kernel 5.10.236)

This document describes how `kernelsu.ko` was made loadable and functional on a
Honor X50 (ALI-AN00, MagicOS 9.0.0.220) running kernel
`5.10.236-android12-9-gf68ed03ce0d2`, starting from the vendor's published
10.226 source tree.

It is a record of what actually worked on hardware, not a general tutorial. Every
claim below was observed on the device; the ones that were not are marked.

---

## 1. Scope and starting point

| Item | Value |
| :--- | :--- |
| Device | Honor X50, ALI-AN00 |
| Firmware | MagicOS 9.0.0.220 (CNC00E206R9P4) |
| Shipping kernel | `5.10.236-android12-9-gf68ed03ce0d2` |
| Vendor source available | 10.226 (does **not** match the shipping 10.236) |
| Bootloader | locked, unlock not available |
| KernelSU base | v3.3.0 |
| Module size | ~6.8 MB, 121 undefined imports |

Because the bootloader cannot be unlocked, there is no way to flash a patched
boot image. The only option is a **loadable kernel module (LKM)**, which is what
KernelSU calls `CONFIG_KSU=m`. That is also the reason the whole chain is
temporary: see §7.

### Why the version mismatch matters

The published 10.226 tree is close enough to build against, but:

* `Module.symvers` does not match what the shipping kernel exports, so the
  in-kernel loader rejects the module ("Exec format error") — §6.1.
* Some symbols KernelSU uses are simply not exported by the vendor kernel
  (`CONFIG_TRIM_UNUSED_KSYMS`), so they cannot be linked at build time at all —
  §2.

---

## 2. Missing exports: asm trampolines, not C function pointers

KernelSU calls a fair number of kernel internals that the vendor kernel does not
export. The port resolves them at runtime by name (`kallsyms_lookup_name`) into
91 slots, defined in `kernel/infra/ext_fns.c`:

* **83 function slots** — each is a naked asm trampoline:
  ```
  adrp x16, ksu_ext_p_<name>
  ldr  x16, [x16, #:lo12:ksu_ext_p_<name>]
  br   x16
  ```
* **8 data slots** — the pointer holds the real symbol address. Four of them
  also get a 256-byte snapshot copied at init, and those snapshots are vestigial:
  nothing reads them any more. `__tracepoint_sys_enter` is one of the eight, and
  §4 explains why the snapshot must never be what the kernel sees.

### The trap: C function-pointer macros trigger CFI

The intuitive implementation is a macro or an inline wrapper:

```c
#define filp_open(...) ((typeof(&filp_open))ksu_ext_p_filp_open)(__VA_ARGS__)
```

**This hard-resets the device.** Honor ships CFI enforcement (HISEC). A
compiler-generated indirect call through a function pointer carries a type hash;
if the target's hash does not match, `__cfi_check_fail` fires and HISEC treats
it as a control-flow-integrity attack. There is no oops and no log — the device
just reboots.

The symptom is extremely misleading: the crash lands on whatever the *first*
such call is (in our case, `set_memory_rw` during syscall-table patching), which
looks like a syscall-patching bug rather than a linkage bug.

Naked asm trampolines via `br x16` have no CFI check, which is why every one of
the 83 function slots is asm.

### Do not disable CFI

Building with `-fno-sanitize=cfi-icall -fno-sanitize=cfi` produces a module
that **never loads at all**: the loader expects the module to carry `__cfi_`
signatures. This was verified by control experiment. Keep CFI on, route calls
through trampolines.

---

## 3. sys_call_table entries are `.cfi_jt` thunks

To install a dispatcher, KernelSU needs a free slot in `sys_call_table`. A slot
is "free" if it points at the generic not-implemented handler.

On this kernel, the table does **not** contain the address of
`__arm64_sys_ni_syscall`. With CFI enabled, the compiler emits thin jump-table
thunks and the table points at `__arm64_sys_ni_syscall.cfi_jt`. Comparing
against the function symbol finds zero candidates.

The port resolves the thunk first and falls back:

```
kallsyms_lookup_name("__arm64_sys_ni_syscall.cfi_jt")
  -> kallsyms_lookup_name("__arm64_sys_ni_syscall")
```

With that, the dispatcher installs and the log shows
`dispatcher installed at <nr>`.

---

## 4. `__tracepoint_sys_enter` must be the real address

This one cost the most time, because everything *looks* correct.

KernelSU hooks the `sys_enter` tracepoint to intercept `execve` (for `su`) and
`setresuid` (for the Manager fd injection). The upstream code calls
`register_trace_prio_sys_enter(handler, data, prio)`, which expands to a
*static inline* that references the tracepoint symbol directly.

Because the symbol is not exported, the port shimmed it as a 256-byte local copy
and passed that copy's address to `tracepoint_probe_register_prio()`.

**Result: the hook is accepted, returns success, and never fires.** The
tracepoint's callback list lives at the real symbol; the kernel walks the real
list, which stays empty. `su` then silently behaves like stock `su` — the
execve interception never happens — with no error anywhere.

Fix: resolve the **real** `__tracepoint_sys_enter` address with
`kallsyms_lookup_name` and register against it:

```c
tracepoint_probe_register_prio(
    (struct tracepoint *)ksu_ext_p___tracepoint_sys_enter,
    ksu_sys_enter_handler, NULL, INT_MIN);
```

The 256-byte snapshot of the struct is still taken at init, but nothing
registers against it any more; it is dead weight from the first attempt.

Rule of thumb from this port: **data that the kernel itself dereferences must
never be a local copy.** A copy is only safe for data the module reads itself.

---

## 5. Deferred `track_throne`

The Manager only gets its driver fd if the kernel knows which app the Manager is.
KernelSU does that by scanning `/data/system/packages.list` and `/data/app` and
matching the Manager's signature (`track_throne()`).

Calling `track_throne(false)` directly from `kernelsu_init()` **hard-resets the
device**. The same code is fine from a workqueue. So init schedules it:

```c
static void ksu_throne_scan_workfn(struct work_struct *work)
{
    track_throne(false);
}
static DECLARE_DELAYED_WORK(ksu_throne_work, ksu_throne_scan_workfn);
...
schedule_delayed_work(&ksu_throne_work, 5 * HZ);
```

Observed on success:

```
[kworker/0:2] KernelSU: manager pkg: me.weishu.kernelsu
[kworker/0:2] KernelSU: Crowning manager: me.weishu.kernelsu(uid=10087)
```

Without this the Manager shows "not installed" forever, even though `su` works.

---

## 6. Small things that each break the whole load

### 6.1 `__versions` / vermagic

The module is built against the 10.226 tree, so `__versions` carries CRCs that
do not match the shipping kernel and the loader refuses it with
"Exec format error". `port/fix-versions.py` replaces the section with a 64-byte
dummy entry; symbol resolution is already handled by the shim, so the CRCs were
not doing any useful work.

### 6.2 `KSU_VERSION` defaults to 16

`kernel/Kbuild` derives the version from `git describe`. Without a `.git`
directory it falls back to `-DKSU_VERSION=16`, and the Manager (v3.3.1, build
32680) then reports the module as **not installed**. Pin it explicitly:

```
ccflags-y += -DKSU_VERSION=33001
```

After this the Manager shows `33001-2` and the status flips to working. The
"kernel update" banner it keeps displaying was not chased down; the uapi version
(this port reports 2) is the most likely remaining mismatch.

### 6.3 Allowlist entries need a non-empty `selinux_domain`

`profile_valid()` rejects an entry whose `rp_config.profile.selinux_domain` is
empty, and the rejection is only visible in dmesg:

```
load_allow_uid, name: shell, uid: 2000, allow: 1
invalid selinux_domain in app_profile: shell
```

Set it to `u:r:su:s0` (`KSU_DEFAULT_SELINUX_DOMAIN` upstream). See
`port/tools/gen-allowlist.c`.

### 6.4 `setup_ksu_cred()` cannot run here

The SELinux domain transition into the KernelSU context needs SELinux internals
this port does not drive; calling it resets the device. init uses a plain
`prepare_creds()` instead. The exploit already leaves uid 0, so it is a usable
root cred — but `su` ends up in `u:r:shell:s0`, not `u:r:su:s0`. That is a known
limitation, not a bug in the chain.

---

## 7. Init sequence as shipped

`kernel/core/init.c`, in order (all of it inside `kernelsu_init`):

```
ksu_ext_syms_init()            resolve the 91 shim slots first (prepare_creds is a trampoline)
ksu_init_symbol_resolver()     no-op on this port
ksu_syscall_hook_init()        locate sys_call_table + a free ni slot, install dispatcher
ksu_feature_init()
ksu_sulog_init()
ksu_supercalls_init()          reboot kprobe + [ksu_driver] anon inode
ksu_allowlist_init()           default profiles
ksu_load_allow_list()          /data/adb/ksu/.allowlist
prepare_creds()                no domain transition (see 6.4)
ksu_syscall_hook_manager_init() sys_enter tracepoint (§4) + su_compat
schedule_delayed_work(...)     throne scan in 5s (§5)
```

Deliberately skipped, each because it hard-resets the device on this firmware:
`ksu_adb_root_init`, `ksu_lsm_hook_init`, `ksu_selinux_hide_init`,
`ksu_app_profile_init`, `setup_ksu_cred`.

`ksu_init_symbol_resolver()` is a no-op: its implementation walks every kallsyms
entry and resets the device on this kernel. The name lookups are done with
`kallsyms_lookup_name` instead.

---

## 8. Build

```bash
# 1. KernelSU tree with the port applied
tar xzf ksu-v3.3.0.tar.gz
patch -p1 -d KernelSU-3.3.0 < port/kernelsu-3.3.0-honor-5.10.226.patch

# 2. Build against the vendor kernel tree
KDIR=/path/to/vendor/kernel \
KSU_SRC=$(pwd)/KernelSU-3.3.0 \
OUT=$PWD/out \
port/build.sh

# 3. Patch __versions
python3 port/fix-versions.py out/kernelsu.ko
```

The module was only ever built with `LLVM=1 LLVM_IAS=1`. The module carries CFI
type hashes, so a different toolchain would produce different ones; another
toolchain is untested, and a CFI mismatch is what HISEC resets the device on.

---

## 9. Known limitations

* **Not persistent.** Root here is a cred swap in RAM plus a module loaded by
  hand; a reboot undoes all of it. `port/host/restore.ps1` re-runs the chain,
  and it must start within ~1 minute of boot.
* **`su` lands in `u:r:shell:s0`** (no domain transition, §6.4).
* **The Manager still shows a "kernel update" banner** even while reporting the
  module as working. Cause not confirmed; the uapi version (2 here) is the
  likely mismatch. Because the UI stays in that limited state, per-app grants go
  through `port/host/grant.ps1` and take effect on the next module load.
* **No module loading/unloading at runtime.** While any app holds the driver fd,
  the module refcount is non-zero and `rmmod` fails; a new build needs a reboot.
* **Offsets were measured, not read from source.** Anything marked
  `UNVERIFIED` in `exploit/src/targets/` is inferred from another Honor model's
  disassembly; a wrong value fails silently.

---

## 10. Attribution

* KernelSU v3.3.0 — GPL-2.0, https://github.com/tiann/KernelSU
* The exploit and its target profiles — Apache-2.0, see `NOTICE`
