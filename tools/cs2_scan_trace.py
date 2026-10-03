"""Trace the pool scan at the local pawn's own offset to find why it is missed."""
import array
import ctypes
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

    def mapped(va):
        m = P.MBI()
        if P.k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                                ctypes.sizeof(P.MBI)) == 0:
            return False
        return m.State == 0x1000 and (int(m.Protect) & 0x02)

    pawn = rq(base + P.LOCAL_PAWN)
    m = P.MBI()
    P.k32.VirtualQueryEx(h, ctypes.c_void_p(pawn), ctypes.byref(m),
                         ctypes.sizeof(P.MBI))
    rs, rz = m.BaseAddress or 0, int(m.RegionSize)
    blob = rd(rs, rz)
    print(f"pawn 0x{pawn:X}  rs 0x{rs:X} rz 0x{rz:X}  blob={len(blob) if blob else None}")

    i32 = array.array("i")
    i32.frombytes(blob[:len(blob) - (len(blob) % 4)])
    i = pawn - rs
    print(f"\nat i=0x{i:X}:")
    print(f"  hp      = {i32[(i + P.OFF_HEALTH) >> 2]}")
    print(f"  team    = {blob[i + P.OFF_TEAM]}")
    node = rq(pawn + P.OFF_SCENE_NODE)
    print(f"  node    = 0x{node:X}  canonical={0x10000 < node < (1 << 47)}  "
          f"mapped={mapped(node) if node else False}")
    oraw = rd(node + P.OFF_ABS_ORIGIN, 12) if node else None
    xyz = struct.unpack("<3f", oraw) if oraw else None
    print(f"  origin  = {xyz}")
    if xyz:
        x, y, z = xyz
        print(f"  range ok= {abs(x) < 20000 and abs(y) < 20000 and -1000 < z < 4000}")
        print(f"  not-near-origin ok= {not (abs(x) < 1.0 and abs(y) < 1.0)}")

    # how many candidates pass the cheap test in this whole region?
    lim = len(blob) - P.TAIL
    hits = 0
    for k in range(0, lim, 8):
        hp = i32[(k + P.OFF_HEALTH) >> 2]
        if 0 <= hp <= 100:
            hits += 1
    print(f"\naddresses with m_iHealth-like value in 0..100: {hits}")
    print(f"TAIL=0x{P.TAIL:X} lim=0x{lim:X}  loop reaches i=0x{i:X}? "
          f"{i < lim}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())