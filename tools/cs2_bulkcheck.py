"""Does the bulk buffer read actually contain the local pawn's fields?"""
import array
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cs2_pool_enum as P  # noqa: E402


def main():
    pid = P.find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    h = P.k32.OpenProcess(0x0410, False, pid)
    base = P.module_base(pid, "client.dll")

    def rd(va, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        ok = P.k32.ReadProcessMemory(h, ctypes.c_void_p(va), b, n, ctypes.byref(g))
        return b.raw if (ok and g.value == n) else None

    def rq(v):
        r = rd(v, 8)
        return struct.unpack("<Q", r)[0] if r else 0

    pawn = rq(base + 0x2560698)
    m = P.MBI()
    P.k32.VirtualQueryEx(h, ctypes.c_void_p(pawn), ctypes.byref(m),
                         ctypes.sizeof(P.MBI))
    rs = m.BaseAddress or 0
    rz = int(m.RegionSize)
    off = pawn - rs
    print(f"pawn 0x{pawn:X}  region 0x{rs:X} size 0x{rz:X}  offset 0x{off:X}")

    for want in (rz, 1 << 20, 0x40000, 0x2000):
        blob = rd(rs, want)
        print(f"  read 0x{want:X} -> "
              f"{'OK ' + str(len(blob)) + ' bytes' if blob else 'FAILED'}")

    blob = rd(rs, rz)
    if not blob:
        print("bulk read failed - that is why the scan found nothing")
        return 1
    print(f"  raw at pawn+0x34C = {blob[off+0x34C:off+0x350].hex(' ')}")
    print(f"  int32 there       = "
          f"{struct.unpack('<i', blob[off+0x34C:off+0x350])[0]}")
    print(f"  byte at pawn+0x3E7= {blob[off+0x3E7]}")
    i32 = array.array("i")
    i32.frombytes(blob[:len(blob) - (len(blob) % 4)])
    print(f"  i32 view at that  = {i32[(off + 0x34C) >> 2]}")
    print(f"  i32 len           = {len(i32)}  (need > "
          f"{(off + 0x34C) >> 2})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())