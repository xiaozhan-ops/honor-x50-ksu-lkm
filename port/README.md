# port/ — KernelSU LKM port for Honor X50 (5.10.236)

`kernelsu.ko` is built as an external module against the vendor's published
10.226 source tree and loaded at runtime by the exploit. Read
[../docs/LKM-PORT.md](../docs/LKM-PORT.md) first: it explains why the module
looks the way it does, including the two mistakes that cost the most time (C
function-pointer shims tripping CFI, and registering the `sys_enter` tracepoint
against a local copy of the struct).

## Layout

| Path | What it is |
| :--- | :--- |
| `kernelsu-3.3.0-honor-5.10.226.patch` | apply with `patch -p1` inside the KernelSU v3.3.0 tree |
| `build.sh` | builds the module against `KDIR` |
| `fix-versions.py` | rewrites `__versions` so the loader accepts the module |
| `device/ksu_loader.sh` | run as root by the exploit (`KSU_LOADER=1`): waits for `sig_enforce=N`, insmods, sets up `su` |
| `device/restore_ondevice.sh` | re-runs the chain from a shell-uid context, no PC needed |
| `host/restore.ps1` | host-side recovery: reboot → exploit → module, with retries |
| `host/grant.ps1` | grant/revoke per-app root via the allowlist |
| `tools/gen-allowlist.c` | generates `/data/adb/ksu/.allowlist` |

## Quick start

```bash
tar xzf ksu-v3.3.0.tar.gz
patch -p1 -d KernelSU-3.3.0 < port/kernelsu-3.3.0-honor-5.10.226.patch

KDIR=/path/to/vendor/kernel KSU_SRC=$PWD/KernelSU-3.3.0 OUT=$PWD/out port/build.sh
python3 port/fix-versions.py out/kernelsu.ko
```

Build with `LLVM=1 LLVM_IAS=1`. A different toolchain changes the CFI type
hashes and HISEC resets the device on load.

## Authorisation

The module denies every uid unless it is listed in `/data/adb/ksu/.allowlist`,
which is read at module init:

```bash
cc -I<kernelsu>/uapi port/tools/gen-allowlist.c -o gen-allowlist
./gen-allowlist allowlist.bin 2000,10087      # shell + Manager
adb push allowlist.bin /data/local/tmp/ && \
  adb shell 'cp /data/local/tmp/allowlist.bin /data/adb/ksu/.allowlist && \
             chmod 600 /data/adb/ksu/.allowlist'
```

`host/grant.ps1` wraps the same thing by package name. Changes take effect the
next time the module loads (a reboot), because the module cannot be unloaded
while apps hold its driver fd.

Passing `allow_shell=1` to `insmod` skips the allowlist for uid 2000 only.
`device/ksu_loader.sh` does this when `ALLOW_SHELL=1`.

## Licence

The KernelSU tree this patch applies to is GPL-2.0; the port inherits that.
The exploit side of this repository is Apache-2.0 — see `../NOTICE`.
