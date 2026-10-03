"""Brute-force the CS2 entity list from dwEntityList / dwGameEntitySystem.

Both dumper names resolve to the SAME global (0x2715828) and it is a valid
pointer live, so this is the entry point. Its internals were never resolved.

Oracle: the local pawn's address is known independently, and m_hPlayerPawn
encodes index 174. So the correct chain is whichever one turns
index -> (page, slot) -> identity -> entity into the pawn. Nothing is assumed:
every candidate offset is accepted only if it reproduces a known-good value.
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
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
MAX_OFF = 0x400
PAGE_SHIFTS = (0x80, 0x100, 0x200, 0x400, 0x800)
ENTITY_LINK = (0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30)


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
    el = rq(base + ENTITY_LIST)
    handle = ri(ctl + OFF_HANDLE) if ctl else 0
    index = handle & 0x3FFF
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn        0x{pawn:X}   health {ri(pawn+OFF_HEALTH) if pawn else '?'}")
    print(f"dwEntityList      0x{el:X}")
    print(f"m_hPlayerPawn     0x{handle:08X} -> index {index}, serial {handle >> 14}")
    if not (pawn and el):
        print("not in a usable state"); return 1

    blob = rd(el, MAX_OFF)
    if blob is None:
        print("entity list unreadable"); return 1

    print(f"\n-- pointers inside the entity list (first 0x{MAX_OFF:X}) --")
    ptrs = []
    for o in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, o)[0]
        if can(v):
            ptrs.append((o, v))
            print(f"   +0x{o:03X}  0x{v:016X}  {'mapped' if mapped(v) else 'UNMAPPED'}")
    print(f"   {len(ptrs)} candidate(s)")

    # chain: el+o -> P ; page table at P+po ; identity = page[(index>>log)*8 + slot*8]
    print(f"\n-- brute force: reproduce the local pawn from index {index} --")
    hits = []
    for o, p1 in ptrs:
        for po in range(0, 0x40, 8):
            ptable = rq(p1 + po)
            if not can(ptable):
                continue
            for shift in PAGE_SHIFTS:
                if shift > 0x2000:
                    continue
                page_idx = index >> (shift.bit_length() - 1)
                slot = index & (shift - 1)
                page = rq(ptable + page_idx * 8)
                if not can(page):
                    continue
                ident = rq(page + slot * 8)
                if not can(ident):
                    continue
                for link in ENTITY_LINK:
                    ent = rq(ident + link)
                    if ent == pawn:
                        hits.append((o, po, shift, page_idx, slot, link))
    if not hits:
        print("   no chain reproduced the pawn - the list is not a")
        print("   pointer->page-table->identity array in this shape")
    else:
        for o, po, shift, page_idx, slot, link in hits:
            print(f"   MATCH  el+0x{o:X} -> +0x{po:X} -> page[{page_idx}] "
                  f"slot {slot} (shift 0x{shift:X}) -> identity+0x{link:X} == PAWN")

    # Also try the direct forms: no paging at all.
    print("\n-- direct forms (no paging) --")
    for o, p1 in ptrs:
        for so in range(0, 0x40, 8):
            slot = rq(p1 + so)
            if slot == pawn:
                print(f"   MATCH el+0x{o:X} -> p1+0x{so:X} == PAWN")
            ent = rq(slot + 0x10) if can(slot) else 0
            if ent == pawn:
                print(f"   MATCH el+0x{o:X} -> p1+0x{so:X} -> *+0x10 == PAWN")
        if p1 == pawn:
            print(f"   MATCH el+0x{o:X} == PAWN directly")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())