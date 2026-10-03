"""Locate the embedded CEntityList offset, then enumerate every player.

The screenshot's formula is right, but `entityList` is NOT the pointer stored at
dwEntityList - reading it directly yields 0x2BA98C90008, which is unmapped. In
CS2 the CEntityList is embedded in the CGameEntitySystem at a fixed offset, so
`entityList = entitySystem + N` for some N.

Search every plausible N, keep the one whose slot 174 resolves to the known
local pawn, then walk the whole list with the same formula.
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
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py
OFF_HANDLE = 0x92C
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_ARMOR = 0x1ECC
PAGE_SHIFT = 9
BASE_OFF = 0x10
LINKS = (0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48)
MAX_ENTITIES = 1024


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

    def rq(va):
        r = rd(va, 8)
        return struct.unpack("<Q", r)[0] if r else 0

    def ri(va):
        r = rd(va, 4)
        return struct.unpack("<i", r)[0] if r else 0

    def mapped(va):
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return False
        return m.State == 0x1000 and (int(m.Protect) & 0x02)

    def can(v):
        return 0x10000 < v < (1 << 47)

    pawn = rq(base + LOCAL_PAWN)
    ctl = rq(base + LOCAL_CONTROLLER)
    es = rq(base + ENTITY_LIST)
    handle = ri(ctl + OFF_HANDLE) if ctl else 0
    idx15 = handle & 0x7FFF
    page, slot = idx15 >> PAGE_SHIFT, idx15 & 0x1FF
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn   0x{pawn:X}")
    print(f"entitySystem 0x{es:X}")
    print(f"handle 0x{handle:08X} -> index {idx15}, page {page}, slot {slot}")
    if not (pawn and es and handle):
        print("need a live round"); return 1

    # search the embedded CEntityList offset
    print(f"\n-- searching entityList = entitySystem + N --")
    found = None
    for n in range(0, 0x800, 8):
        lst = es + n
        entry = rq(lst + 0x8 * page + BASE_OFF)
        if not can(entry) or not mapped(entry):
            continue
        for link in LINKS:
            if entry == pawn and link == 0:
                found = (n, None)
                break
            if rq(entry + link) == pawn:
                found = (n, link)
                break
        if found:
            break

    if not found:
        print("   no offset N resolved index {idx15} to the local pawn".format(
            idx15=idx15))
        print("   showing what each N yields for diagnostics:")
        for n in range(0, 0x100, 8):
            entry = rq(es + n + 0x8 * page + BASE_OFF)
            if can(entry):
                print(f"     N=0x{n:03X}  entry=0x{entry:016X} "
                      f"mapped={mapped(entry)}")
        k32.CloseHandle(h)
        return 1

    n, link = found
    print(f"   entityList = entitySystem + 0x{n:X}")
    print(f"   identity link: entry{'+0x%X' % link if link is not None else ' itself'}"
          f" == entity")
    print(f"   ==> CHAIN VERIFIED against the local pawn")

    lst = es + n
    print(f"\n-- enumerating the list --")
    rows = []
    seen = set()
    for i in range(MAX_ENTITIES):
        p, s = (i & 0x7FFF) >> PAGE_SHIFT, (i & 0x7FFF) & 0x1FF
        entry = rq(lst + 0x8 * p + BASE_OFF)
        if not can(entry) or not mapped(entry):
            continue
        ent = entry if link is None else rq(entry + link)
        if not can(ent) or ent in seen or not mapped(ent):
            continue
        seen.add(ent)
        hp = ri(ent + OFF_HEALTH)
        team = ri(ent + OFF_TEAM) & 0xFF
        arm = ri(ent + OFF_ARMOR)
        node = rq(ent + OFF_SCENE_NODE)
        org = None
        if can(node) and mapped(node):
            raw = rd(node + OFF_ABS_ORIGIN, 12)
            if raw:
                org = struct.unpack("<3f", raw)
        rows.append((i, ent, hp, team, arm, org))

    print(f"{len(rows)} live entities")
    print(f"{'idx':>5} {'entity':<18} {'hp':>4} {'tm':>3} {'arm':>4}  origin")
    for i, ent, hp, team, arm, org in rows:
        o = f"({org[0]:8.1f},{org[1]:9.1f},{org[2]:7.1f})" if org else "-"
        tag = "  <== LOCAL" if ent == pawn else ""
        print(f"{i:5d} 0x{ent:016X} {hp:4d} {team:3d} {arm:4d}  {o}{tag}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())