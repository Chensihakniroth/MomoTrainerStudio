"""Look for a CEntityIdentity adjacent to the local pawn.

A complete memory sweep (651 regions, 0.23 GiB readable, 1 hole) finds ZERO
references to the pawn's address, so Source 2 never stores it - it is computed.
In CS2 the CEntityIdentity and the CEntityInstance share one allocation, so the
identity sits at a fixed delta from the entity rather than behind a pointer.

So: dump the memory around the pawn and look for the identity shape
(m_name / m_designerName as pointers to short ASCII, m_nameStringTableIndex a
small int) at some negative offset. If it is there, the delta is the whole
entity list mechanism - read identity - delta to get any entity.
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
OFF_ARMOR = 0x1ECC
OFF_HINSTANCE = 0x8            # CEntityInstance::m_iszPrivateVScripts (a CUtlString)
OFF_PENTITY = 0x10              # CEntityInstance::m_pEntity

IDX_STRIDX = 0x14
IDX_NAME = 0x18
IDX_DESIGNER = 0x20
ID_PREV = 0x50
ID_NEXT = 0x58
ID_PREV_CLASS = 0x60
ID_NEXT_CLASS = 0x68

PRINTABLE = re.compile(rb"[\x20-\x7e]{2,48}\x00")


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

    def mapped(va):
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return False
        return m.State == 0x1000 and (int(m.Protect) & 0x02)

    def as_str(p):
        if not canonical(p) or not mapped(p):
            return None
        raw = rd(p, 48)
        if not raw:
            return None
        m = PRINTABLE.match(raw)
        return m.group(0)[:-1].decode("ascii") if m else None

    pawn = rq(base + LOCAL_PAWN)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn 0x{pawn:X}")
    if not pawn:
        print("be alive in a round"); return 1
    node = rq(pawn + OFF_SCENE_NODE)
    origin = struct.unpack("<3f", rd(node + OFF_ABS_ORIGIN, 12)) if node else None
    print(f"local health {ri(pawn+OFF_HEALTH)}  origin {origin}")

    # Dump 1 KiB below and above the pawn; the identity should be adjacent.
    BACK = 0x1000
    print(f"\n-- identity shape within -0x{BACK:X}..+0x{BACK:X} of the pawn --")
    blob = rd(pawn - BACK, BACK * 2)
    if blob is None:
        print("   could not read around the pawn")
        return 1

    hits = []
    for i in range(0, len(blob) - 0x70, 8):
        addr = pawn - BACK + i
        name = struct.unpack_from("<Q", blob, i + IDX_NAME)[0]
        des = struct.unpack_from("<Q", blob, i + IDX_DESIGNER)[0]
        if not (canonical(name) and canonical(des)):
            continue
        stridx = struct.unpack_from("<i", blob, i + IDX_STRIDX)[0]
        if not (0 <= stridx < 1000000):
            continue
        nxt = struct.unpack_from("<Q", blob, i + ID_NEXT)[0]
        prv = struct.unpack_from("<Q", blob, i + ID_PREV)[0]
        nc = struct.unpack_from("<Q", blob, i + ID_NEXT_CLASS)[0]
        if nxt and not (canonical(nxt) and mapped(nxt)):
            continue
        if nc and not (canonical(nc) and mapped(nc)):
            continue
        hits.append((addr, stridx, as_str(name), as_str(des), nxt, prv, nc))

    print(f"   {len(hits)} candidate identities")
    for addr, stridx, n, d, nxt, prv, nc in hits:
        delta = addr - pawn
        print(f"   0x{addr:X} (pawn{delta:+#x})  strIdx={stridx}  "
              f"name={n!r} designer={d!r}")
        print(f"        m_pPrev=0x{prv:X} m_pNext=0x{nxt:X} m_pNextByClass=0x{nc:X}")
        # does identity - delta give a valid entity? check +0x10 == pawn
        for cand in (addr, addr - 0x8, addr - 0x10, addr - 0x18, addr - 0x20):
            if cand + OFF_PENTITY == pawn:
                print(f"        => instance = identity{delta if cand==addr else 0:+#x}"
                      f", m_pEntity(+0x10) == pawn  <== LINK FOUND")
        # or the identity IS the instance: identity + 0x10 -> entity
        e = rq(addr + OFF_PENTITY)
        if e:
            hp = ri(e + OFF_HEALTH)
            print(f"        identity+0x10 = 0x{e:X}  its m_iHealth = {hp}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())