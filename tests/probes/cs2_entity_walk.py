"""Discover the CS2 entity-list walk, without guessing any offsets.

Approach: breadth-first search for the VALUE of the local pawn's address. We
already know that address independently (dwLocalPlayerPawn), so whatever chain
leads to it is by definition the right one. Any guessed offset would instead have
to be validated against a known-good result.

The pawn is reachable from the entity system, so BFS from dwGameEntitySystem,
following canonical pointers, looking for the pawn's 8-byte value. Once found,
report the full chain plus the stride between consecutive slots, which tells us
whether we landed on an array of entities or a single struct field.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from collections import deque
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenProcess.restype = wt.HANDLE
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wt.BOOL
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.restype = wt.BOOL
k32.Module32FirstW.restype = wt.BOOL
k32.Module32NextW.restype = wt.BOOL

GAME_ENTITY_SYSTEM = 0x2715828
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_NAME = 0x6FC
OFF_PENTITY = 0x10          # CEntityInstance::m_pEntity

CHUNK = 0x1000
MAX_DEPTH = 4
MAX_NODES_PER_LEVEL = 400


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
    """Windows x64 user-space pointer.

    The user half of the address space is 0..2^47-1, so the bound is an UPPER
    limit. Using 1 << 47 as a lower bound rejects every real heap pointer
    (they look like 0x000002BA7B542800) and silently collapses the search.
    """
    return 0x10000 < v < (1 << 47)


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
    base = module_base(pid, "client.dll")
    reads = 0

    def rd(va, n):
        nonlocal reads
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        reads += 1
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

    print(f"pid={pid} client.dll 0x{base:X}")

    pawn = rq(base + LOCAL_PAWN)
    controller = rq(base + LOCAL_CONTROLLER)
    entsys = rq(base + GAME_ENTITY_SYSTEM)
    if not (pawn and entsys):
        print(f"pawn=0x{pawn:X} entitySystem=0x{entsys:X} - not in a usable state")
        return 1
    health = ri(pawn + OFF_HEALTH)
    node = rq(pawn + OFF_SCENE_NODE)
    origin = struct.unpack("<3f", rd(node + OFF_ABS_ORIGIN, 12)) if node else (0, 0, 0)
    print(f"local pawn   0x{pawn:X}  health={health}  origin={origin}")
    print(f"controller   0x{controller:X}")
    print(f"entitySystem 0x{entsys:X}")
    if controller:
        raw = rd(controller + OFF_NAME, 32)
        # f-string expressions cannot contain backslashes - build the decoded
        # name outside the f-string.
        name = raw.split(b"\x00")[0].decode("utf-8", "replace") if raw else "?"
        print(f"player name  {name}")

    pawn_bytes = struct.pack("<Q", pawn)

    # BFS for the pawn's value.
    visited = {entsys}
    frontier = deque([(entsys, [])])       # (address, chain)
    found = None
    depth = 0
    while frontier and depth < MAX_DEPTH and not found:
        print(f"\n-- depth {depth}: {len(frontier)} node(s) --")
        nxt = deque()
        count = 0
        for addr, chain in frontier:
            if count >= MAX_NODES_PER_LEVEL:
                print(f"   (capped at {MAX_NODES_PER_LEVEL} nodes this level)")
                break
            count += 1
            blob = rd(addr, CHUNK)
            if blob is None:
                continue
            if pawn_bytes in blob:
                off = blob.find(pawn_bytes)
                found = (addr, off, chain)
                break
            for i in range(0, CHUNK - 8, 8):
                v = struct.unpack_from("<Q", blob, i)[0]
                if canonical(v) and v not in visited:
                    visited.add(v)
                    nxt.append((v, chain + [(addr, i)]))
        print(f"   scanned {count} nodes, frontier grew to {len(nxt)}")
        frontier = nxt
        depth += 1

    print(f"\n[reads so far: {reads}]")
    if not found:
        print("PAWN VALUE NOT FOUND in the walked graph - the entity list is not")
        print("reachable from dwGameEntitySystem by canonical pointers at depth "
              f"{MAX_DEPTH}.")
        print("It likely needs a handle->entity index lookup, not a pointer chain.")
        k32.CloseHandle(h)
        return 1

    addr, off, chain = found
    print("\n=== CHAIN TO LOCAL PAWN ===")
    for parent, coff in chain:
        print(f"  0x{parent:X} + 0x{coff:03X}  ->  0x{rq(parent + coff):X}")
    print(f"  0x{addr:X} + 0x{off:03X}  == local pawn 0x{pawn:X}   <== FOUND")

    # Is the containing block an array? Look at the neighbouring slots.
    print("\n-- neighbours of the hit (is this an array?) --")
    for delta in (-4, -3, -2, -1, 0, 1, 2, 3, 4):
        v = rq(addr + off + delta * 8)
        mark = "  <== local pawn" if v == pawn else ""
        print(f"   [{delta:+d}] 0x{addr + off + delta * 8:X} = 0x{v:016X}{mark}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())