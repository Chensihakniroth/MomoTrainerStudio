"""Locate the entity array slots that hold the local pawn, and read neighbours.

With the PAGE_READWRITE bug fixed, the local pawn shows up in 6 slots inside the
region at 0x2BA98C90000. Those slots define the array: their spacing is the
stride, and the slots around them hold the other players.

Prints the pawn's slots, the stride between them, and each slot's neighbour
group with health/origin, so the array layout can be read off directly.
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
OFF_NAME = 0x6FC
OFF_IS_LOCAL = 0x790

CHUNK = 1 << 22


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

    def origin_of(e):
        node = rq(e + OFF_SCENE_NODE)
        if not can(node) or not mapped(node):
            return None
        raw = rd(node + OFF_ABS_ORIGIN, 12)
        return struct.unpack("<3f", raw) if raw else None

    def inline_name(a):
        raw = rd(a + OFF_NAME, 48)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        return t if len(t) >= 2 and all(32 <= ord(c) < 127 for c in t) else None

    el = rq(base + ENTITY_LIST)
    pawn = rq(base + LOCAL_PAWN)
    ctl = rq(base + LOCAL_CONTROLLER)
    page = rq(el + 0x10)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"entitySystem 0x{el:X}  *(+0x10)=0x{page:X}  local pawn 0x{pawn:X}")

    m = MBI()
    k32.VirtualQueryEx(h, ctypes.c_void_p(page), ctypes.byref(m),
                       ctypes.sizeof(MBI))
    rs, rz = m.BaseAddress or 0, int(m.RegionSize)

    # find every slot whose target is the local pawn
    hits, pos = [], 0
    while pos < rz:
        blob = rd(rs + pos, min(CHUNK, rz - pos))
        if blob is None:
            pos += CHUNK
            continue
        t = struct.pack("<Q", pawn)
        i = blob.find(t)
        while i >= 0:
            if i % 8 == 0:
                hits.append(rs + pos + i)
            i = blob.find(t, i + 8)
        pos += CHUNK
    hits = sorted(set(hits))
    print(f"\nslots containing the local pawn: {[hex(x) for x in hits]}")
    if not hits:
        print("none found this time")
        return 1
    print("gaps between them:",
          [hex(b - a) for a, b in zip(hits, hits[1:])])

    print("\n-- neighbour groups around each pawn slot --")
    for hslot in hits:
        print(f"\nslot 0x{hslot:X}:")
        for d in range(-4, 5):
            a = hslot + d * 0x70
            v = rq(a)
            if not can(v) or not mapped(v):
                print(f"   [{d:+d}] 0x{a:X} = 0x{v:X}  (not a pointer)")
                continue
            hp = ri(v + OFF_HEALTH)
            org = origin_of(v)
            o = f"({org[0]:8.1f},{org[1]:9.1f},{org[2]:7.1f})" if org else "-"
            mark = "  <== LOCAL" if v == pawn else ""
            print(f"   [{d:+d}] 0x{a:X} -> 0x{v:016X} hp={hp:3d} "
                  f"arm={ri(v+OFF_ARMOR):3d} {o}{mark}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())