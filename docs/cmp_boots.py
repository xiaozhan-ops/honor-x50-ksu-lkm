#!/usr/bin/env python
"""Compare the kallsyms tables of two boot images.

Tells whether the kernel symbols the GhostLock exploit reads resolve to the same
addresses in both, and reports how much of the whole table moved.

Usage:
    python cmp_boots.py <an220_kallsyms.txt> <tn230_kallsyms.txt>
"""
import sys

# Every kernel symbol the exploit reads at runtime.
DEPS = [
    "init_task", "init_cred", "root_task_group", "selinux_state",
    "sig_enforce", "g_rscan_skip_flag", "nfulnl_logger", "loggers",
    "sysctl_bootid", "random_table", "commit_creds",
    "rt_sched_class", "idle_sched_class", "fair_sched_class",
    "dl_sched_class", "stop_sched_class",
]


def load(path):
    """Parse a kallsyms dump; lines look like '<addr> <type> <name>'."""
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


def main(path_a, path_b):
    a, b = load(path_a), load(path_b)
    print(f"image A: {len(a):,} symbols")
    print(f"image B: {len(b):,} symbols\n")

    print(f"{'symbol':<22}{'A':<18}{'B':<18}verdict")
    print("-" * 78)
    same = diff = skipped = 0
    for sym in DEPS:
        va, vb = a.get(sym), b.get(sym)
        if va is None or vb is None:
            miss_a = "absent" if va is None else hex(va)
            miss_b = "absent" if vb is None else hex(vb)
            print(f"{sym:<22}{miss_a:<18}{miss_b:<18}skipped")
            skipped += 1
        elif va == vb:
            print(f"{sym:<22}{hex(va):<18}{hex(vb):<18}same")
            same += 1
        else:
            print(f"{sym:<22}{hex(va):<18}{hex(vb):<18}"
                  f"DIFFERS (delta {vb - va:#x})")
            diff += 1
    print("-" * 78)
    print(f"exploit dependencies: {same} same / {diff} differ / "
          f"{skipped} skipped   (of {len(DEPS)})")

    common = set(a) & set(b)
    moved = {k: (a[k], b[k]) for k in common if a[k] != b[k]}
    only_a = set(a) - set(b)
    only_b = set(b) - set(a)
    print(f"\nwhole table: {len(common):,} shared symbols, "
          f"{len(moved):,} at different addresses")
    print(f"only in A: {len(only_a):,}   only in B: {len(only_b):,}")

    # A moved dependency is the actionable case: the two profiles then need
    # different offset values.
    bad = [s for s in DEPS if s in moved]
    if bad:
        print(f"\nWARNING dependencies that moved: {bad}")
        print("         -> separate target profiles required")
    else:
        print("\n=> every dependency symbol resolves to the same address")

    if moved:
        print("\nsample of moved symbols (first 15):")
        for k in sorted(moved)[:15]:
            print(f"   {k:<32}{hex(moved[k][0])} -> {hex(moved[k][1])}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])