#!/usr/bin/env bash
# Build kernelsu.ko as an external module against a vendor 5.10 kernel tree.
#
# Prerequisites:
#   * KernelSU tree with port/kernelsu-3.3.0-honor-5.10.226.patch applied
#   * the vendor kernel source tree (the one matching the running kernel)
#   * clang/lld + LLVM_IAS (the module must be built with the same toolchain
#     family the kernel was built with, otherwise CFI type hashes will not match)
#
# Environment:
#   KSU_SRC  KernelSU source root            (default: repo root)
#   KDIR     vendor kernel source root       (required, contains top Makefile)
#   OUT      output directory for artifacts  (default: ./out)
#   JOBS     parallel jobs                   (default: nproc)
#
# Why LLVM=1: Honor builds this kernel with clang. Mixing toolchains changes
# the CFI type hashes, and HISEC resets the device on a CFI mismatch.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KSU_SRC="${KSU_SRC:-$(cd "$here/.." && pwd)}"
KDIR="${KDIR:?set KDIR to the vendor kernel source root}"
OUT="${OUT:-$PWD/out}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

[[ -f "$KDIR/Makefile" ]] || { echo "KDIR=$KDIR does not look like a kernel tree" >&2; exit 1; }
[[ -d "$KSU_SRC/kernel" ]] || { echo "KSU_SRC=$KSU_SRC has no kernel/ directory" >&2; exit 1; }

mkdir -p "$OUT"
echo "--- building kernelsu.ko ---"
make -C "$KDIR" M="$KSU_SRC/kernel" \
  LLVM=1 LLVM_IAS=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
  CONFIG_KSU=m KCFLAGS=-Wno-error modules -j"$JOBS"

ko="$KSU_SRC/kernel/kernelsu.ko"
[[ -f "$ko" ]] || { echo "build produced no kernelsu.ko" >&2; exit 1; }
cp "$ko" "$OUT/kernelsu.ko"
echo "--- ok: $OUT/kernelsu.ko ---"
ls -l "$OUT/kernelsu.ko"
echo
echo "next: python3 $here/fix-versions.py $OUT/kernelsu.ko"
