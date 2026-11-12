#!/usr/bin/env python3
"""Rewrite the module's __versions section to a 64-byte dummy entry.

Why this is needed
------------------
kernelsu.ko is built against the vendor's published kernel source, whose
Module.symvers does not match the symbols the *shipping* kernel actually
exports. The loader then refuses the module with "Exec format error", because
same_magic() compares CRCs for every symbol listed in __versions.

A dummy entry keeps same_magic() from rejecting the module outright; symbol
resolution is done at runtime by the shim in kernel/infra/ext_fns.c instead
(see docs/LKM-PORT.md).

Usage:  fix-versions.py <kernelsu.ko> [output.ko]
"""
import struct
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src

    data = bytearray(open(src, "rb").read())
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    shstr = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

    off = len(data)
    data += struct.pack("<Q56s", 0, b"zz_dummy_unused")

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, sh)[0]
        end = data.index(b"\0", shstr + name_off)
        if data[shstr + name_off:end] == b"__versions":
            struct.pack_into("<Q", data, sh + 0x18, off)
            struct.pack_into("<Q", data, sh + 0x20, 64)
            break
    else:
        print("note: no __versions section found; nothing patched")

    open(dst, "wb").write(data)
    print(f"wrote {dst} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
