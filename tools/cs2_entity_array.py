"""Find the entity array by its contents, and derive the real stride.

The reference sweep (with the PAGE_READWRITE bug fixed) found 228 references to
the local pawn, clustered around 0x2BA98C9xxxx - the same area as the value read
at dwEntityList+0x10. That area is therefore where entity pointers live, but the
tutorial's 0x70 stride did not resolve the local pawn there.

So: scan that region for pointers that are genuine entities, collect their
offsets, and let the offsets reveal the stride. No offset is assumed.
"""
from cs2_header_offsets import offsets

o = offsets()
import array
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.restype = wt.BOOL
k32.Module32FirstW.restype = wt.BOOL
k32.Module32NextW.restype = wt.BOOL

ENTITY_LIST = o.ENTITY_LIST   # was 0x2715828; cs2_header_offsets.py
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_ARMOR = 0x1ECC
OFF_NAME = 0x6FC

CHUNK = 1 << 22
TAIL = 0x1000


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


class PE32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


class ME32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
                ("szModule", wt.WCHAR * 256), ("szExePath", wt.WCHAR * 260)]


def find_pid(name):
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
    pid = 0
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name:
                pid = pe.th32ProcessID; break
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return pid


def module_base(pid, name):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    b = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == name:
                b = me.modBaseAddr or 0; break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return b


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0410, False, pid)
    base = module_base(pid, "client.dll")

    def rd(va, n):
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), b, n,
                                     ctypes.byref(g)) or g.value != n:
            return None
        return b.raw

    def rq(v):
        r = rd(v, 8)
        return struct.unpack("<Q", r)[0] if r else 0

    def ri(v):
        r = rd(v, 4)
        return struct.unpack("<i", r)[0] if r else 0

    def mapped(va):
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return False
        p = int(m.Protect)
        return m.State == 0x1000 and not (p & 0x01) and not (p & 0x100)

    def can(v):
        return 0x10000 < v < (1 << 47)

    el = rq(base + ENTITY_LIST)
    pawn = rq(base + LOCAL_PAWN)
    page = rq(el + 0x10)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"entitySystem 0x{el:X}   *(+0x10) = 0x{page:X}  readable={mapped(page)}")
    print(f"local pawn   0x{pawn:X}")

    m = MBI()
    k32.VirtualQueryEx(h, ctypes.c_void_p(page), ctypes.byref(m),
                       ctypes.sizeof(MBI))
    rs, rz = m.BaseAddress or 0, int(m.RegionSize)
    print(f"\nregion 0x{rs:X} .. 0x{rs+rz:X}  ({rz/2**20:.1f} MiB)")

    # Collect every slot holding a genuine entity pointer.
    slots = []
    pos = 0
    while pos < rz:
        want = min(CHUNK, rz - pos)
        blob = rd(rs + pos, want)
        if blob is None:
            pos += want
            continue
        for i in range(0, len(blob) - 8, 8):
            v = struct.unpack_from("<Q", blob, i)[0]
            if not can(v) or not mapped(v):
                continue
            hp = ri(v + OFF_HEALTH)
            if hp < 0 or hp > 100:
                continue
            node = rq(v + OFF_SCENE_NODE)
            if not can(node) or not mapped(node):
                continue
            oraw = rd(node + OFF_ABS_ORIGIN, 12)
            if oraw is None:
                continue
            x, y, z = struct.unpack("<3f", oraw)
            if not (abs(x) < 20000 and abs(y) < 20000 and -2000 < z < 4000):
                continue
            # Same discriminator that made the pool scan work: a real entity
            # sits at real map coordinates. Without this, a 200-entry table of
            # consecutive pointers (health 0, origin 0) dominated the results
            # and the stride analysis was meaningless.
            if not (abs(x) > 50 or abs(y) > 50):
                continue
            slots.append((rs + pos + i, v, hp, x, y, z))
        pos += want

    print(f"\n{len(slots)} slots hold an entity pointer")
    if not slots:
        print("none - the array is elsewhere")
        k32.CloseHandle(h)
        return 1

    offs = sorted(s[0] for s in slots)
    diffs = Counter(b - a for a, b in zip(offs, offs[1:]))
    print("\nmost common gaps between consecutive slots:")
    for d, c in diffs.most_common(10):
        print(f"   0x{d:X} ({d:6d} bytes)  x{c}")

    # Find runs with a consistent stride.
    print("\n-- runs at a constant stride --")
    for stride, count in diffs.most_common(3):
        if count < 3:
            continue
        runs, cur = [], [offs[0]]
        for a, b in zip(offs, offs[1:]):
            if b - a == stride:
                cur.append(b)
            else:
                if len(cur) >= 3:
                    runs.append(cur)
                cur = [b]
        if len(cur) >= 3:
            runs.append(cur)
        for run in runs:
            alive = [s for s in slots if s[2] >= 1]
            if not alive:
                continue
            print(f"  stride 0x{stride:X}: {len(run)} entries "
                  f"from 0x{run[0]:X} to 0x{run[-1]:X}  "
                  f"({len(alive)} alive)")
            # Only alive entities are players; the hp=0 majority are world props
            # and buried the signal in the earlier run.
            for s in alive:
                tag = "  <== LOCAL PAWN" if s[1] == pawn else ""
                print(f"      0x{s[0]:016X} -> 0x{s[1]:016X} hp={s[2]:3d} "
                      f"({s[3]:8.1f},{s[4]:9.1f},{s[5]:7.1f}){tag}")

    print(f"\nlocal pawn appears in {sum(1 for s in slots if s[1] == pawn)} slot(s)")
    print("\n-- ALL alive entities in the region, with their slot addresses --")
    alive = sorted(s for s in slots if s[2] >= 1)
    print(f"{len(alive)} alive")
    for s in alive:
        tag = "  <== LOCAL PAWN" if s[1] == pawn else ""
        print(f"   slot 0x{s[0]:016X} -> 0x{s[1]:016X} hp={s[2]:3d} "
              f"({s[3]:8.1f},{s[4]:9.1f},{s[5]:7.1f}){tag}")
    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())