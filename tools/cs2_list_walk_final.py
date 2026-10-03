"""The CS2 entity list walk, taken from the screenshot.

    listEntry2 = ReadPointer(entityList,
                            0x8 * ((pawnHandle & 0x7FFF) >> 9) + 0x10);

Three things were wrong in every earlier attempt:
  * mask is 0x7FFF (15 bits), not the 0x3FFF I read off m_hPlayerPawn
  * the page shift is 9 (512 entries per page), not the 0x4000 I inferred from
    the constant at dwEntityList+0x278
  * it is ONE dereference at entityList + (page*8 + 0x10), not a pointer to a
    page table that must then be indexed again

Verified against the local pawn's independently-known address.
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

    def origin_of(ent):
        node = rq(ent + OFF_SCENE_NODE)
        if not can(node) or not mapped(node):
            return None
        raw = rd(node + OFF_ABS_ORIGIN, 12)
        return struct.unpack("<3f", raw) if raw else None

    pawn = rq(base + LOCAL_PAWN)
    ctl = rq(base + LOCAL_CONTROLLER)
    el = rq(base + ENTITY_LIST)
    handle = ri(ctl + OFF_HANDLE) if ctl else 0
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn    0x{pawn:X}")
    print(f"entityList    0x{el:X}")
    print(f"pawnHandle    0x{handle:08X}   &0x7FFF = {handle & 0x7FFF}")
    if not (pawn and el and handle):
        print("need a live round"); return 1

    # ---- the walk from the screenshot ----
    page = (handle & 0x7FFF) >> 9
    slot = (handle & 0x7FFF) & 0x1FF
    off = 0x8 * page + 0x10
    print(f"\npage={page} slot={slot}  ->  read pointer at entityList+0x{off:X}")
    list_entry2 = rq(el + off)
    print(f"listEntry2 = 0x{list_entry2:X}  mapped={mapped(list_entry2) if can(list_entry2) else False}")

    resolved = None
    if can(list_entry2) and mapped(list_entry2):
        for link in (0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30):
            cand = rq(list_entry2 + link)
            if cand == pawn:
                resolved = link
                print(f"  listEntry2 + 0x{link:X} == local pawn   <== LINK")
                break
        if resolved is None:
            if list_entry2 == pawn:
                resolved = -1
                print(f"  listEntry2 IS the pawn   <== LINK")
            else:
                print("  no link to the pawn at listEntry2+0x00..0x30")
                for link in (0x0, 0x8, 0x10, 0x18):
                    c = rq(list_entry2 + link)
                    if can(c):
                        print(f"    +0x{link:X} = 0x{c:X}  health={ri(c + OFF_HEALTH)}")
    if resolved is None:
        print("\nwalking the same formula across every index instead")
        resolved = None

    # ---- enumerate every entity with the same formula ----
    print("\n-- enumerate the list (same formula per index) --")
    entities = []
    for idx in range(MAX_ENTITIES):
        p = (idx & 0x7FFF) >> 9
        s = (idx & 0x7FFF) & 0x1FF
        entry = rq(el + 0x8 * p + 0x10)
        if not can(entry) or not mapped(entry):
            continue
        ent = entry if resolved == -1 else (rq(entry + resolved) if resolved is not None else 0)
        if not can(ent) or not mapped(ent):
            continue
        hp = ri(ent + OFF_HEALTH)
        team = ri(ent + OFF_TEAM) & 0xFF
        org = origin_of(ent)
        entities.append((idx, entry, ent, hp, team, ri(ent + OFF_ARMOR), org))

    print(f"{len(entities)} live entities")
    print(f"{'idx':>5} {'entity':<18} {'hp':>4} {'tm':>3} {'arm':>4}  origin")
    for idx, entry, ent, hp, team, arm, org in entities:
        o = f"({org[0]:8.1f},{org[1]:9.1f},{org[2]:7.1f})" if org else "-"
        tag = "  <== LOCAL" if ent == pawn else ""
        print(f"{idx:5d} 0x{ent:016X} {hp:4d} {team:3d} {arm:4d}  {o}{tag}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())