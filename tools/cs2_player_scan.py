"""Find every CS2 player pawn in the heap, without using the entity list.

Earlier attempts anchored on the local pawn, which is transient: it changes on
respawn, so a slot count taken in one run did not reproduce in the next. This
scan is anchor-free - it looks for any object with a live health value at a real
map coordinate - and only checks the local pawn at the END, so a mid-scan
respawn cannot invalidate it.

Speed: m_iHealth is an int32 in 1..100 at +0x34C. Rather than test every address
with a syscall, the chunk is searched for the 100 possible 4-byte encodings with
bytes.find (C speed), and only the handful of hits per chunk pay for the external
reads needed to validate health, team, scene node and origin.
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

LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_ARMOR = 0x1ECC

STEP = 1 << 22
OVERLAP = 0x400
HEAP_LO = 0x0000020000000000
HEAP_HI = 0x0000040000000000

# int32 1..100 little-endian
HP_PATTERNS = [struct.pack("<i", v) for v in range(1, 101)]


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

    pawn0 = rq(base + LOCAL_PAWN)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn at scan start: 0x{pawn0:X} health={ri(pawn0+OFF_HEALTH) if pawn0 else '?'}")

    regions, addr = [], 0x10000
    LIMIT = 1 << 47
    while addr < LIMIT:
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            addr += 0x10000
            continue
        base_addr = m.BaseAddress or addr
        size = int(m.RegionSize)
        prot = int(m.Protect)
        if (m.State == 0x1000 and not (prot & 0x01) and not (prot & 0x100)
                and HEAP_LO <= base_addr < HEAP_HI):
            regions.append((base_addr, size))
        nxt = base_addr + size
        if nxt <= addr:
            break
        addr = nxt
    total = sum(s for _, s in regions)
    print(f"heap regions: {len(regions)}  ({total/2**30:.2f} GiB)")

    found = {}
    done = 0
    for rb, rz in regions:
        pos = 0
        while pos < rz:
            want = min(STEP + OVERLAP, rz - pos)
            blob = rd(rb + pos, want)
            if blob is None:
                pos += STEP
                continue
            lim = len(blob) - OVERLAP
            seen_here = set()
            for pat in HP_PATTERNS:
                i = blob.find(pat)
                while i >= 0:
                    a = rb + pos + (i - 0x34C)
                    if a & 7 == 0 and 0 <= (i - 0x34C) < len(blob) and a not in found \
                            and a not in seen_here:
                        seen_here.add(a)
                        node = rq(a + OFF_SCENE_NODE)
                        if not (HEAP_LO <= node < HEAP_HI) or not mapped(node):
                            i = blob.find(pat, i + 4)
                            continue
                        oraw = rd(node + OFF_ABS_ORIGIN, 12)
                        if oraw is None:
                            i = blob.find(pat, i + 4)
                            continue
                        x, y, z = struct.unpack("<3f", oraw)
                        if not (abs(x) < 20000 and abs(y) < 20000
                                and -2000 < z < 4000):
                            i = blob.find(pat, i + 4)
                            continue
                        if not (abs(x) > 50 or abs(y) > 50):
                            i = blob.find(pat, i + 4)
                            continue
                        arm = ri(a + OFF_ARMOR)
                        if arm < 0 or arm > 100:
                            i = blob.find(pat, i + 4)
                            continue
                        found[a] = (ri(a + OFF_HEALTH), ri(a + OFF_TEAM) & 0xFF,
                                    x, y, z)
                    i = blob.find(pat, i + 4)
            pos += STEP
        done += 1
        if done % 50 == 0:
            print(f"  [{done}/{len(regions)}] regions, {len(found)} candidates",
                  flush=True)

    pawn1 = rq(base + LOCAL_PAWN)
    print(f"\n{len(found)} alive player-like entities found")
    print(f"local pawn now 0x{pawn1:X}  present in results: "
          f"{pawn1 in found}   <== calibration")
    print(f"\n{'address':<18} {'hp':>4} {'tm':>3} {'arm':>4}  origin")
    for a in sorted(found):
        hp, tm, x, y, z = found[a]
        tag = "  <== LOCAL" if a == pawn1 else ""
        print(f"0x{a:016X} {hp:4d} {tm:3d} {ri(a+OFF_ARMOR):4d}  "
              f"({x:8.1f},{y:9.1f},{z:7.1f}){tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())