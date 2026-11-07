#!/usr/bin/env python3
"""Rewrite only the x0 MOV64 chain so the kernel writes a smaller SCTLR set.

Both chains currently load 0x3454593d. Lowering x0 only (leaving x1 at the
default) makes `cmp x0,x1` fail, and `b.ne +4` then lands on the stage-3 site
which the probe already instruments -- so one boot tells us whether the
MMU-enable msr survives with that smaller bit set.

The chain is MOVK x0,#0,lsl48 / MOVK x0,#0,lsl32 / MOVK x0,#hi,lsl16 /
MOVK x0,#lo  (high half already zero in x0 on entry), so rewriting means
setting the two low-half immediates and leaving the two zero MOVKs alone.
"""
import argparse
import struct
from pathlib import Path

DEFAULT_SCTLR = 0x3454593d
CHAIN_VA = 0xfffffff007423340  # x0 build chain for this kernel layout


def parse(data):
    magic, cputype, cpusub, ft, ncmds, size, flags, _ = struct.unpack_from("<8I", data, 0)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", data, off)
        if cmd == 0x19:
            name = bytes(data[off + 8:off + 24]).split(b"\x00", 1)[0].decode()
            vm, vs, fo, fs = struct.unpack_from("<4Q", data, off + 24)
            if name == "__TEXT_EXEC":
                return vm, vs, fo, fs
        off += cmdsize
    raise SystemExit("no __TEXT_EXEC")


def movk(rd, imm16, sh):
    return 0xF2800000 | (sh << 21) | (imm16 << 5) | rd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("value", type=lambda s: int(s, 0))
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    data = bytearray(Path(args.kernel).read_bytes())
    vm, vs, fo, fs = parse(data)
    off = fo + (CHAIN_VA - vm)

    words = [struct.unpack_from("<I", data, off + k * 4)[0] for k in range(4)]
    expect = [0xF2E00000, 0xF2C00000, 0xF2A68A80, 0xF28B27A0]
    if words != expect:
        raise SystemExit("x0 chain mismatch: %s" % [hex(w) for w in words])

    v = args.value
    lo = v & 0xFFFF
    hi = (v >> 16) & 0xFFFF
    struct.pack_into("<I", data, off + 8, movk(0, hi, 16))
    struct.pack_into("<I", data, off + 12, movk(0, lo, 0))
    print("x0 chain: %#x -> %#x (hi=%#x lo=%#x)" % (DEFAULT_SCTLR, v, hi, lo))

    # verify by re-reading
    words = [struct.unpack_from("<I", data, off + k * 4)[0] for k in range(4)]
    got = ((words[2] >> 5) & 0xFFFF) << 16 | ((words[3] >> 5) & 0xFFFF)
    assert got == v, "rebuild check failed: %#x" % got
    print("verified chain now yields %#x" % got)

    Path(args.output).write_bytes(data)
    print("wrote", args.output)


if __name__ == "__main__":
    main()
