#!/usr/bin/env python3
"""Rewrite BOTH MOV64 chains (x0 and x1) to the same bisect value.

Both chains load SCTLR constants right before the MMU-enable msr in
start_first_cpu. Keeping them EQUAL matters: the original code ends with
cmp x0,x1; b.ne <self> (imm19=0, a deliberate upstream trap), so an x0
value that differs from x1 spins forever instead of falling through.
Writing the same value to both chains keeps cmp equal and lets the boot
continue with the bisect value.
"""
import argparse
import struct
from pathlib import Path

X0_CHAIN_VA = 0xfffffff007423340
X1_CHAIN_VA = 0xfffffff007423358
DEFAULT_SCTLR = 0x3454593d


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


def chain_words(v, rd):
    # Preserve each chain's register field: x0 uses rd=0, x1 uses rd=1.
    hi = (v >> 16) & 0xFFFF
    lo = v & 0xFFFF
    return [movk(rd, 0, 48), movk(rd, 0, 32), movk(rd, hi, 16), movk(rd, lo, 0)]


DEFAULT_WORDS = {
    0: [0xF2E00000, 0xF2C00000, 0xF2A68A80, 0xF28B27A0],  # x0 chain
    1: [0xF2E00001, 0xF2C00001, 0xF2A68A81, 0xF28B27A1],  # x1 chain
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel")
    ap.add_argument("value", type=lambda s: int(s, 0))
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()

    data = bytearray(Path(args.kernel).read_bytes())
    vm, vs, fo, fs = parse(data)

    for label, va, rd in (("x0", X0_CHAIN_VA, 0), ("x1", X1_CHAIN_VA, 1)):
        off = fo + (va - vm)
        words = [struct.unpack_from("<I", data, off + k * 4)[0] for k in range(4)]
        if words != DEFAULT_WORDS[rd]:
            raise SystemExit("%s chain mismatch: %s" % (label, [hex(w) for w in words]))
        for k, w in enumerate(chain_words(args.value, rd)):
            struct.pack_into("<I", data, off + k * 4, w)
        # verify by re-reading
        words = [struct.unpack_from("<I", data, off + k * 4)[0] for k in range(4)]
        got = sum(((w >> 5) & 0xFFFF) << (((w >> 21) & 3) * 16) for w in words)
        assert got == args.value, "%s rebuild check failed: %#x" % (label, got)
        print("%s chain: %#x -> %#x" % (label, DEFAULT_SCTLR, got))

    Path(args.output).write_bytes(data)
    print("wrote", args.output)


if __name__ == "__main__":
    main()
