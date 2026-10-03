"""Locate the CS2 entity list and learn the identity -> entity link.

The schema says CEntityIdentity is a doubly-linked list: m_pPrev at 0x50,
m_pNext at 0x58. That mutual prev/next agreement is a near-certain signature -
random memory will not satisfy it - so it is a safe discovery probe.

Then the identity -> C_BaseEntity offset is learned rather than guessed: the
local pawn's address is already known, so whichever node/offset reproduces it is
by definition the correct link.
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

GAME_ENTITY_SYSTEM = 0x2715828
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py
OFF_P_HANDLE = 0x92C          # CCSPlayerController::m_hPlayerPawn
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8

ID_PREV = 0x50
ID_NEXT = 0x58


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


def module_base(pid, module):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    base = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == module:
                base = me.modBaseAddr or 0; break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base


def canonical(v):
    return 0x10000 < v < (1 << 47)


def mapped(h, va):
    mbi = MBI()
    if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(mbi),
                          ctypes.sizeof(MBI)) == 0:
        return False
    return mbi.State == 0x1000 and (int(mbi.Protect) & 0x02)


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
    base = module_base(pid, "client.dll")

    def rd(va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return buf.raw

    def rq(va):
        raw = rd(va, 8)
        return struct.unpack("<Q", raw)[0] if raw else 0

    def ri(va):
        raw = rd(va, 4)
        return struct.unpack("<i", raw)[0] if raw else 0

    pawn = rq(base + LOCAL_PAWN)
    controller = rq(base + LOCAL_CONTROLLER)
    entsys = rq(base + GAME_ENTITY_SYSTEM)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn   0x{pawn:X}")
    print(f"entitySystem 0x{entsys:X}")
    handle = ri(controller + OFF_P_HANDLE) if controller else 0
    print(f"m_hPlayerPawn handle = 0x{handle:08X}  (index {handle & 0x3FFF}, "
          f"serial {handle >> 14})")
    if not pawn or not entsys:
        print("need a live round (pawn must exist)")
        return 1

    def is_node(p):
        """A CEntityIdentity node: next and prev agree."""
        if not canonical(p) or not mapped(h, p):
            return None
        nxt = rq(p + ID_NEXT)
        prv = rq(p + ID_PREV)
        if nxt and not canonical(nxt):
            return None
        if prv and not canonical(prv):
            return None
        if nxt and not mapped(h, nxt):
            return None
        # the strong test: the neighbour points back
        if nxt and rq(nxt + ID_PREV) != p:
            return None
        if prv and rq(prv + ID_NEXT) != p:
            return None
        return (nxt, prv)

    # Search the entity system and its direct children for a list head.
    print("\n-- probing for a doubly-linked list head --")
    blob = rd(entsys, 0x2000)
    if blob is None:
        print("entity system unreadable"); return 1
    seeds = []
    for i in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, i)[0]
        if canonical(v) and mapped(h, v):
            seeds.append((entsys + i, v))
    print(f"   {len(seeds)} pointer candidates in the entity system")

    best = None
    for src, p in seeds:
        got = is_node(p)
        if got:
            print(f"   HIT: entsys+0x{src - entsys:X} -> 0x{p:X} is an identity node")
            best = (src - entsys, p)
            break
    if not best:
        print("   no linked-list head directly in the entity system")
        print("   trying one level of indirection...")
        for src, p in seeds:
            b2 = rd(p, 0x400)
            if not b2:
                continue
            for i in range(0, len(b2) - 8, 8):
                q = struct.unpack_from("<Q", b2, i)[0]
                if canonical(q) and is_node(q):
                    print(f"   HIT: entsys+0x{src-entsys:X} -> 0x{p:X} "
                          f"+0x{i:X} -> 0x{q:X}")
                    best = ((src - entsys, p, i, q))
                    break
            if best:
                break
    if not best:
        print("   not found")
        k32.CloseHandle(h)
        return 1

    # Walk the list.
    if len(best) == 2:
        head = best[1]
    else:
        head = best[3]
    print(f"\n-- walking the list from 0x{head:X} --")
    nodes = []
    seen = set()
    cur = head
    while canonical(cur) and cur not in seen and len(nodes) < 20000:
        seen.add(cur)
        nodes.append(cur)
        cur = rq(cur + ID_NEXT)
    print(f"   {len(nodes)} nodes walked")

    # Learn identity -> C_BaseEntity: which offset of which node gives the pawn?
    print("\n-- learning identity -> entity (the local pawn must appear) --")
    link = None
    for n in nodes[:4000]:
        nb = rd(n, 0x80)
        if not nb:
            continue
        for i in range(0, len(nb) - 7, 8):
            v = struct.unpack_from("<Q", nb, i)[0]
            if v == pawn:
                link = (n, i)
                break
        if link:
            break
    if link:
        print(f"   identity 0x{link[0]:X} + 0x{link[1]:X} == local pawn")
    else:
        print("   pawn not directly in any identity (0x00-0x80)")
        print("   dumping the local-pawn-adjacent node layout instead")
        link = (None, None)

    # What do identities look like? Sample a few with names.
    print("\n-- sample identities --")
    for n in nodes[:6]:
        nb = rd(n, 0x60)
        if not nb:
            continue
        name_ptr = struct.unpack_from("<Q", nb, 0x18)[0]
        s = rd(name_ptr, 48) if canonical(name_ptr) else None
        s = s.split(b"\x00")[0].decode("utf-8", "replace") if s else ""
        print(f"   0x{n:X}  m_nameStringTableIndex="
              f"{struct.unpack_from('<i', nb, 0x14)[0]:5d}  m_name={s!r}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())