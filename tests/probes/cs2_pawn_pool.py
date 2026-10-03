"""Enumerate CS2 player pawns by scanning the local pawn's allocation pool.

The linked-list route is fragile: the CEntityIdentity list head is not reachable
from dwGameEntitySystem by a simple pointer chain, and a naive prev/next probe
produces false positives inside client.dll's own image.

This takes the reliable route instead. Same-class objects are allocated from the
same pool, so the other players' pawns live near the local pawn. A candidate is
only accepted when ALL of these hold simultaneously, which random memory will
essentially never satisfy:

    +0x34C  m_iHealth      int32 in 0..100
    +0x3E7  m_iTeamNum     byte in 0..2
    +0x330  m_pGameSceneNode -> canonical heap pointer
    node+0xC8  m_vecAbsOrigin -> |x|,|y| < 20000 and -1000 < z < 4000

The local pawn is a known address, so finding it is the built-in proof the scan
is calibrated correctly.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import re
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

LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_VIEW_OFFSET = 0xF60
OFF_ARMOR = 0x1ECC
OFF_NAME = 0x6FC

# health is int32 0..100 at +0x34C, team is a byte 0..2 at +0x3E7
TEAM_DELTA = OFF_TEAM - OFF_HEALTH      # 0x9B
HEALTH_RE = re.compile(rb"[\x00-\x64]{4}" + b"(.{%d})" % (TEAM_DELTA - 4)
                       + rb"[\x00\x01\x02]", re.DOTALL)


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

    def rstr(va, cap=48):
        if not canonical(va):
            return None
        raw = rd(va, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        try:
            t = s.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return t if t.isprintable() and len(t) > 0 else None

    pawn = rq(base + LOCAL_PAWN)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn 0x{pawn:X}")
    if not pawn:
        print("no local pawn - be alive in a round")
        return 1

    # Which region holds the pawn? Same-class objects share the pool.
    # Use the region that CONTAINS the pawn, not the allocation base: querying
    # VirtualQueryEx at the allocation base returns a different (earlier) region,
    # which silently scans a range the pawn is not in - and then the calibration
    # check fails for a reason that has nothing to do with the pool idea.
    mbi = MBI()
    k32.VirtualQueryEx(h, ctypes.c_void_p(pawn), ctypes.byref(mbi),
                       ctypes.sizeof(MBI))
    reg_start = mbi.BaseAddress or 0
    reg_size = int(mbi.RegionSize)
    alloc = mbi.AllocationBase or 0
    print(f"region  0x{reg_start:X} .. 0x{reg_start+reg_size:X} "
          f"({reg_size/2**20:.1f} MiB, allocBase 0x{alloc:X})")

    if not (reg_start <= pawn < reg_start + reg_size):
        print("local pawn is not inside the reported region - aborting")
        k32.CloseHandle(h)
        return 1

    start = reg_start
    size = reg_size
    print(f"scanning 0x{start:X} .. 0x{start+size:X} "
          f"({size/2**20:.1f} MiB)")

    STEP = 1 << 22                                  # 4 MiB, with overlap
    OVERLAP = 0x2000                                # > max field offset
    found = {}
    pos = 0
    while pos < size:
        want = min(STEP, size - pos)
        blob = rd(start + pos, want)
        if blob is None:
            pos += want
            continue
        for m in HEALTH_RE.finditer(blob):
            cand = start + pos + m.start() - OFF_HEALTH
            if cand in found:
                continue
            # verify the scene node + origin
            node = rq(cand + OFF_SCENE_NODE)
            if not canonical(node):
                continue
            oraw = rd(node + OFF_ABS_ORIGIN, 12)
            if oraw is None:
                continue
            x, y, z = struct.unpack("<3f", oraw)
            if not (abs(x) < 20000 and abs(y) < 20000 and -1000 < z < 4000):
                continue
            if x == 0.0 and y == 0.0 and z == 0.0:
                continue
            found[cand] = (struct.unpack("<i", m.group(0)[0:4])[0],
                           m.group(0)[TEAM_DELTA], x, y, z, node)
        pos += STEP - OVERLAP
        if pos < 0:
            pos = 0

    print(f"\naccepted {len(found)} player-pawn candidates")
    print(f"local pawn present in results: {pawn in found}"
          f"   <== calibration proof")
    print(f"\n{'address':<18} {'hp':>4} {'team':>4} {'armor':>6}  origin")
    for a in sorted(found):
        hp, team, x, y, z, node = found[a]
        armor = ri(a + OFF_ARMOR)
        tag = "  <== LOCAL" if a == pawn else ""
        print(f"0x{a:016X} {hp:4d} {team:4d} {armor:6d}  "
              f"({x:8.1f}, {y:8.1f}, {z:7.1f}){tag}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())