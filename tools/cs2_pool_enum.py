"""Enumerate CS2 players by scanning the local pawn's / controller's pool.

The entity list at dwEntityList is empty on build 14188, so the handle walk has
nowhere to go. But same-class objects are allocated from the same pool, so the
other players live near the ones we can already address. The local pawn and the
local controller are both known-good anchors, and finding them in the results is
the built-in proof the scan is calibrated.

Two earlier attempts at this failed for fixable reasons:
  * it scanned from AllocationBase, which is a different region than the pawn
  * the "health 0..100" regex bounded each BYTE to <= 0x64, so 0x424F4E30 passed

Here the health test is a real int32 comparison, and both health and team are
read straight out of a bulk buffer via a typed memoryview, so a candidate costs
one indexed load instead of a syscall. Only survivors pay for external reads.
"""
from cs2_header_offsets import offsets

o = offsets()
import array
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
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_IS_LOCAL = 0x790
OFF_PAWN_HEALTH = 0x938

CHUNK = 1 << 22
# Must exceed EVERY field offset used below. It was 0x500, which is smaller than
# OFF_HANDLE (0x92C) and caused an array index out of range.
TAIL = 0x1000
PRINTABLE = range(0x20, 0x7F)


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
        # Readable = not NOACCESS and not GUARD. `Protect & 0x02` tests
        # PAGE_READONLY, so it rejected every PAGE_READWRITE page and made the
        # pool scan find zero candidates in a region that provably holds the
        # local pawn.
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return False
        prot = int(m.Protect)
        return (m.State == 0x1000
                and not (prot & 0x01) and not (prot & 0x100))

    def can(v):
        return 0x10000 < v < (1 << 47)

    def ascii_at(p, cap=48):
        if not can(p) or not mapped(p):
            return None
        raw = rd(p, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        if not (1 <= len(s) <= 40):
            return None
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        if all(c in PRINTABLE for c in t):
            return t
        return None

    def inline_ascii(addr, cap=64):
        """Read a CUtlString stored INLINE, not behind a pointer.

        m_iszPlayerName at 0x6FC holds the bytes directly: reading it as a
        pointer gives 0x3038383061746562, which is just "beta0880" interpreted
        as a little-endian integer. Dereferencing that is what made the earlier
        controller scan find nothing.
        """
        raw = rd(addr, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        if not (1 <= len(s) <= 40):
            return None
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        if len(t) >= 2 and all(c in PRINTABLE for c in t):
            return t
        return None

    pawn = rq(base + LOCAL_PAWN)
    ctl = rq(base + LOCAL_CONTROLLER)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn      0x{pawn:X}  health {ri(pawn+OFF_HEALTH) if pawn else '?'}")
    print(f"local controller 0x{ctl:X}  name "
          f"{inline_ascii(ctl + OFF_NAME) if ctl else None}")
    if not (pawn and ctl):
        print("need a live round"); return 1

    def region_of(addr):
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return 0, 0
        return m.BaseAddress or 0, int(m.RegionSize)

    # ---------------- pawns ----------------
    print("\n" + "=" * 70)
    print("PAWN POOL")
    print("=" * 70)
    rs, rz = region_of(pawn)
    print(f"region 0x{rs:X} .. 0x{rs+rz:X}  ({rz/2**20:.1f} MiB)")
    found = {}
    pos = 0
    while pos < rz:
        want = min(CHUNK + TAIL, rz - pos)
        blob = rd(rs + pos, want)
        if blob is None:
            pos += want - TAIL
            continue
        i32 = array.array("i")
        i32.frombytes(blob[:len(blob) - (len(blob) % 4)])
        lim = len(blob) - TAIL
        for i in range(0, lim, 8):
            hp = i32[(i + OFF_HEALTH) >> 2]
            if hp < 0 or hp > 100:
                continue
            # m_iTeamNum is NOT a usable filter: it reads 2, 3 or 0 depending on
            # round state, so requiring 2..3 rejected the known local pawn.
            # Record it, never gate on it.
            tm = blob[i + OFF_TEAM]
            a = rs + pos + i
            if a in found:
                continue
            node = rq(a + OFF_SCENE_NODE)
            if not can(node) or not mapped(node):
                continue
            oraw = rd(node + OFF_ABS_ORIGIN, 12)
            if oraw is None:
                continue
            x, y, z = struct.unpack("<3f", oraw)
            if not (abs(x) < 20000 and abs(y) < 20000 and -1000 < z < 4000):
                continue
            # Reject denormals and the origin: they print as 0.0 but pass a
            # naive `== 0.0` test, and they were the bulk of the false positives.
            if abs(x) < 1.0 and abs(y) < 1.0:
                continue
            # Real map coordinates are hundreds to thousands of units. Combined
            # with a sane armour value this separates players from the several
            # hundred other objects that happen to carry a small int at +0x34C.
            if not (abs(x) > 50 or abs(y) > 50):
                continue
            arm = ri(a + OFF_ARMOR)
            if arm < 0 or arm > 100:
                continue
            found[a] = (hp, tm, x, y, z)
        pos += CHUNK
    print(f"accepted {len(found)} player-pawn candidates")
    print(f"LOCAL PAWN PRESENT: {pawn in found}   <== calibration")
    print(f"\n{'address':<18} {'hp':>4} {'tm':>3} {'arm':>5}  origin")
    for a in sorted(found):
        hp, team, x, y, z = found[a]
        tag = "  <== LOCAL" if a == pawn else ""
        print(f"0x{a:016X} {hp:4d} {team:3d} {ri(a+OFF_ARMOR):5d}  "
              f"({x:8.1f},{y:9.1f},{z:7.1f}){tag}")

    # ---------------- controllers ----------------
    print("\n" + "=" * 70)
    print("CONTROLLER POOL")
    print("=" * 70)
    cs, cz = region_of(ctl)
    print(f"region 0x{cs:X} .. 0x{cs+cz:X}  ({cz/2**20:.1f} MiB)")
    ctl_found = {}
    pos = 0
    while pos < cz:
        want = min(CHUNK + TAIL, cz - pos)
        blob = rd(cs + pos, want)
        if blob is None:
            pos += want - TAIL
            continue
        i32 = array.array("i")
        i32.frombytes(blob[:len(blob) - (len(blob) % 4)])
        lim = len(blob) - TAIL
        for i in range(0, lim, 8):
            a = cs + pos + i
            if a in ctl_found:
                continue
            hd = i32[(i + OFF_HANDLE) >> 2]
            if hd == 0:
                continue
            idx = hd & 0x7FFF
            if idx == 0 or idx > 0x4000:
                continue
            nm = inline_ascii(a + OFF_NAME)
            if not nm:
                continue
            ctl_found[a] = (hd, idx, nm, blob[i + OFF_IS_LOCAL] if i + OFF_IS_LOCAL < len(blob) else 0)
        pos += CHUNK
    print(f"accepted {len(ctl_found)} player-controller candidates")
    print(f"LOCAL CONTROLLER PRESENT: {ctl in ctl_found}   <== calibration")
    print(f"\n{'address':<18} {'handle':>10} {'idx':>5} {'loc':>4}  name")
    for a in sorted(ctl_found):
        hd, idx, nm, loc = ctl_found[a]
        tag = "  <== LOCAL" if a == ctl else ""
        print(f"0x{a:016X} 0x{hd:08X} {idx:5d} {loc:4d}  {nm!r}{tag}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())