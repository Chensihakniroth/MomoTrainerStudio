"""Test the controller array at entityList + i*0x70, and chain handle -> pawn.

The reference video walks controllers at the SAME 0x70 stride it uses for
entities. If that holds on build 14188, names come for free:

    controller = *(entityList + i * 0x70)        i < 64
    name       = inline CUtlString at controller + 0x6FC
    handle     = int32 at controller + 0x92C
    slot       = handle & 0x1FF
    pawn       = *(page + 0x70 * slot)

That closes the loop: entity walk gives position/health, controller gives the
name, and the handle links them.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

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
PAGE_OFFSET = o.PAGE_OFFSET   # was 0x10; cs2_header_offsets.py
SLOT_STRIDE = o.SLOT_STRIDE   # was 0x70; cs2_header_offsets.py
MAX_SLOTS = o.MAX_SLOTS   # was 512; cs2_header_offsets.py
CTL_COUNT = 64
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_IS_LOCAL = 0x790
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_ARMOR = 0x1ECC
PRINTABLE = set(range(0x20, 0x7F))


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

    def inline_name(addr, cap=48):
        raw = rd(addr, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        if not (2 <= len(s) <= 40):
            return None
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        return t if all(ord(c) in PRINTABLE for c in t) else None

    el = rq(base + ENTITY_LIST)
    page = rq(el + PAGE_OFFSET) if can(el) else 0
    localPawn = rq(base + LOCAL_PAWN)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"entityList 0x{el:X}  page 0x{page:X}  local pawn 0x{localPawn:X}")
    if not can(el) or not can(page):
        print("entity list not available"); return 1

    # The video's `listEntry` is *(entityList + 0x10), i.e. the PAGE - not the
    # entityList itself. Controllers hang off listEntry at the same stride.
    bases = [("page(=listEntry)", page), ("entityList", el)]
    best = None
    for base_name, base_addr in bases:
        for stride in (0x70, 0x78, 0x8, 0x10):
            cands = []
            for i in range(CTL_COUNT):
                ctl = rq(base_addr + stride * i)
                if not can(ctl) or not mapped(ctl):
                    continue
                nm = inline_name(ctl + OFF_NAME)
                if nm:
                    cands.append((i, ctl, nm))
            print(f"  {base_name} + i*0x{stride:X}: {len(cands)} named "
                  f"controllers of {CTL_COUNT}")
            if len(cands) > len(best[2]) if best else len(cands) > 0:
                best = (base_name, stride, cands)
    if not best:
        print("\nno controller array found at any base/stride combination")
        k32.CloseHandle(h)
        return 1
    base_name, stride, cands = best
    print(f"\n-- BEST: {base_name} + i*0x{stride:X}, {len(cands)} named --")
    rows = []
    for i, ctl, nm in cands:
        hd = ri(ctl + OFF_HANDLE)
        islocal = rd(ctl + OFF_IS_LOCAL, 1)
        rows.append((i, ctl, nm, hd, islocal[0] if islocal else -1))

    print(f"\n{'i':>3} {'controller':<18} {'handle':>10} {'slot':>5} {'loc':>4} "
          f"{'hp':>4} {'tm':>3}  name / origin")
    linked = 0
    for i, ctl, nm, hd, loc in rows:
        slot = hd & 0x1FF
        pawn = rq(page + SLOT_STRIDE * slot) if hd else 0
        hp = ri(pawn + OFF_HEALTH) if can(pawn) else -1
        team = ri(pawn + OFF_TEAM) & 0xFF if can(pawn) else -1
        org = ""
        if can(pawn) and hp >= 0:
            node = rq(pawn + OFF_SCENE_NODE)
            if can(node):
                raw = rd(node + OFF_ABS_ORIGIN, 12)
                if raw:
                    x, y, z = struct.unpack("<3f", raw)
                    org = f"({x:8.1f},{y:9.1f},{z:7.1f})"
        if can(pawn) and pawn == localPawn:
            linked += 1
        print(f"{i:3d} 0x{ctl:016X} 0x{hd:08X} {slot:5d} {loc:4d} "
              f"{hp:4d} {team:3d}  {nm!r} {org}")

    print(f"\ncontrollers resolving to the LOCAL pawn via handle: {linked}")
    if linked:
        print("=> controller -> handle -> slot -> pawn WORKS; names are solved")
    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())