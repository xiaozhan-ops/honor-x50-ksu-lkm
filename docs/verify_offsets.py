#!/usr/bin/env python
"""Check a target profile's kernel offsets against a measured kallsyms table.

Reads the reference profile's offsets and verifies each one against symbols
extracted from a boot image, reporting any mismatch.

Usage:
    python verify_offsets.py <kallsyms.txt> [--ref <profile-dir>]
"""
import sys

# Offsets as recorded in the reference profile
# exploit/src/targets/annap-AGT-AN00_9.0.0.230/target.h
REFERENCE = {
    "init_task":            0x281bf80,
    "init_cred":            0x2830c18,
    "root_task_group":      0x2d54080,
    "selinux_state":        0x2e84b38,
    "sig_enforce":          0x2bbfd80,
    "g_rscan_skip_flag":    0x2e8889c,
    "nfulnl_logger":        0x2811430,
    "loggers":              0x2811358,
    "sysctl_bootid":        0x2e9cedd,
    "random_table":         0x2c4a5c0,
    "commit_creds":         0x355258,
    "rt_sched_class":       0x2344ae0,
}

# Not kallsyms symbols. Recorded in profile comments, so they need a manual
# cross-check against a disassembly or a live device.
MANUAL_CHECK = {
    "SLIDE_LOGGERS_0_1":0x2811358,
    "SLIDE_RT_SCHED_CLASS":    0x23445e0,   # derived, see ALI-AN00-TN-COMPARISON.md
}

KIMAGE_TEXT_BASE = 0xffffffc008000000


def load(path):
    syms = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    syms[parts[2]] = int(parts[0], 16)
                except ValueError:
                    pass
    return syms


def main(path):
    syms = load(path)
    print(f"loaded {len(syms):,} symbols\n")

    print(f"{'symbol':<22}{'profile OFF':<14}{'measured':<18}"
          f"{'OFF':<12}verdict")
    print("-" * 82)
    ok = diff = absent = 0
    for name, want in REFERENCE.items():
        got = syms.get(name)
        if got is None:
            print(f"{name:<22}{want:#010x}   {'absent':<18}{'-':<12}not found")
            absent += 1
            continue
        off = got - KIMAGE_TEXT_BASE
        if off == want:
            print(f"{name:<22}{want:#010x}   {got:#018x}   {off:#010x}   match")
            ok += 1
        else:
            print(f"{name:<22}{want:#010x}   {got:#018x}   {off:#010x}   "
                  f"MISMATCH (delta {off - want:#x})")
            diff += 1
    print("-" * 82)
    print(f"match {ok} / mismatch {diff} / absent {absent}"
          f"   (of {len(REFERENCE)})")

    if diff:
        print("\nA mismatch means the profile's offsets do not belong to this "
              "kernel. Do not run it against this device.")

    print("\nvalues that are not kallsyms symbols and need a manual check:")
    for name, val in MANUAL_CHECK.items():
        print(f"   {name:<28}{val:#010x}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1])