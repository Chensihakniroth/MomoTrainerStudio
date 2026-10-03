"""Crack the CS2 entity page table, using the local pawn as the only oracle.

Established facts:
  dwEntityList (== dwGameEntitySystem)  -> 0x2BA7B542800, a valid pointer
  dwEntityList+0x278 = 0x0000400000004000 -> identity page shift is 0x4000
  m_hPlayerPawn = 0x001B00AE -> index 174, serial 108  (174 < 0x4000, page 0)

So the walk is entsys -> CEntityList -> CEntityIdentities -> page[0] -> slot[174]
-> identity -> entity, with three unknown intermediate offsets.

Earlier attempts failed because they read only 0x400 bytes of the entity system
(the interesting fields sit past that) and tried at most two levels. This walks
three, over a wider span, with every plausible index-math variant, and accepts a
chain ONLY when it reproduces the pawn's known address.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from collections import deque

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

SPAN = 0x2000          # read this much of the entity system
CHILD_SPAN = 0x800     # read this much of each child
SHIFTS = (0x4000, 0x2000, 0x1000, 0x200, 0x100)
LINKS = (0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40)


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


_cache = {}


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0410, False, pid)
    base = module_base(pid, "client.dll")

    def rd(va, n):
        key = (va, n)
        if key in _cache:
            return _cache[key]
        b = ctypes.create_string_buffer(n)
        g = ctypes.c_size_t(0)
        out = b.raw if (k32.ReadProcessMemory(h, ctypes.c_void_p(va), b, n,
                                               ctypes.byref(g)) and g.value == n) else None
        _cache[key] = out
        return out

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
    print(f"local pawn     0x{pawn:X}  health {ri(pawn + OFF_HEALTH) if pawn else '?'}")
    print(f"dwEntityList   0x{el:X}")
    print(f"handle index   {index}   page shift 0x4000 -> page {index >> 14}, "
          f"slot {index & 0x3FFF}")
    if not (pawn and el):
        print("not in a usable state"); return 1

    blob = rd(el, SPAN)
    if blob is None:
        print("entity system unreadable"); return 1

    lvl0 = []
    for o in range(0, len(blob) - 8, 8):
        v = struct.unpack_from("<Q", blob, o)[0]
        if can(v) and mapped(v):
            lvl0.append((o, v))
    print(f"\nlevel 0: {len(lvl0)} mapped pointer(s) in +0x0..0x{SPAN:X}")
    for o, v in lvl0:
        print(f"   +0x{o:04X}  0x{v:016X}")

    found = []

    # level 0 -> level 1
    lvl1 = []
    for o0, v0 in lvl0:
        cb = rd(v0, CHILD_SPAN)
        if not cb:
            continue
        for i in range(0, len(cb) - 8, 8):
            w = struct.unpack_from("<Q", cb, i)[0]
            if can(w) and mapped(w):
                lvl1.append((o0, i, v0, w))
    print(f"level 1: {len(lvl1)} mapped pointer(s)")

    # level 1 -> identity, via every index-math variant
    def try_identity(chain, base_ptr, shift):
        """From `base_ptr`, try flat and paged index math for `index`."""
        out = []
        # flat: base_ptr[index]
        out.append(("flat", rq(base_ptr + index * 8)))
        # paged: page table at base_ptr (or a small offset), page = page>>shift
        for po in (0x0, 0x8, 0x10, 0x18, 0x20):
            tbl = rq(base_ptr + po)
            if not can(tbl) or not mapped(tbl):
                continue
            page = rq(tbl + (index >> (shift.bit_length() - 1)) * 8)
            if not can(page) or not mapped(page):
                continue
            out.append((f"paged+0x{po:X}/0x{shift:X}",
                        rq(page + (index & (shift - 1)) * 8)))
        return out

    checked = 0
    for o0, o1, v0, v1 in lvl1:
        for shift in SHIFTS:
            for kind, ident in try_identity(None, v1, shift):
                checked += 1
                if not can(ident):
                    continue
                if ident == pawn:
                    found.append((o0, o1, kind, "ident==pawn"))
                    continue
                for link in LINKS:
                    ent = rq(ident + link)
                    if ent == pawn:
                        found.append((o0, o1, kind, f"ident+0x{link:X}==pawn"))
                    elif can(ent) and mapped(ent):
                        hp = ri(ent + OFF_HEALTH)
                        # a same-shape neighbour is weak evidence; log it
                        if 0 <= hp <= 100:
                            _cache.setdefault(("near",), []).append(
                                (o0, o1, kind, link, ent, hp))

    print(f"\nchecked {checked} index-math variants")
    if found:
        print("=== CHAIN FOUND ===")
        for f in found:
            print(f"   el+0x{f[0]:04X} -> +0x{f[1]:04X} -> {f[2]} -> {f[3]}")
    else:
        print("   no chain reproduced the pawn")
        near = _cache.get(("near",)) or []
        # dedupe by entity address
        uniq = {}
        for o0, o1, kind, link, ent, hp in near:
            uniq.setdefault(ent, (o0, o1, kind, link, hp))
        print(f"   {len(uniq)} distinct entities with m_iHealth in 0..100 "
              f"(weak candidates, NOT confirmed)")
        for ent, (o0, o1, kind, link, hp) in list(uniq.items())[:15]:
            print(f"      0x{ent:016X} hp={hp}  via el+0x{o0:X}->+0x{o1:X} "
                  f"{kind} +0x{link:X}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())