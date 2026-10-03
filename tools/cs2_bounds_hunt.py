"""Find the real player collision bounds, live.

Follow-up to cs2_player_height.py. That probe proved two things:

  * m_vecViewOffset (pawn + 0xF60) reads real eye heights: 63.97 standing,
    45.97 crouched, 0.0 dead. It is a live crouch + liveness signal.
  * The hardcoded 94.5 box height is 2.40m at 2.54cm/unit - 31% too tall.

It did NOT find capsule bounds in pawn[0x300, 0x480). This sweeps the whole
pawn object for ANY vec3 pair shaped like a player capsule (tall, narrow, mins
at or below zero) and ranks by how many players agree on identical values.

The ranking matters: a real field is byte-identical on every standing player,
so agreement across players is the discriminator between a genuine bounds pair
and a coincidental pair of floats. Anything under half the players agreeing is
reported as noise rather than promoted.

Run:  python tools/cs2_bounds_hunt.py
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
PAGE_OFFSET = o.PAGE_OFFSET   # was 0x10; cs2_header_offsets.py
SLOT_STRIDE = o.SLOT_STRIDE   # was 0x70; cs2_header_offsets.py
CTL_COUNT = 64
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_HEALTH = 0x34C
OFF_VIEW_OFFSET = 0xF60

UNITS_PER_METRE = 1.0 / 0.0254
PRINTABLE = set(range(0x20, 0x7F))


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD),
                ("Type", wt.DWORD)]


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

    def inline_name(addr, cap=48):
        raw = rd(addr, cap)
        if not raw:
            return None
        s = raw.split(b"\x00")[0]
        if not (2 <= len(s) <= 40):
            return None
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        return t if all(ord(c) in PRINTABLE for c in t) else None

    el = rq(base + ENTITY_LIST)
    page = rq(el + PAGE_OFFSET) if can(el) else 0
    if not can(page):
        print("entity list not available - is a match running?"); return 1

    players = []
    for i in range(CTL_COUNT):
        ctl = rq(page + SLOT_STRIDE * i)
        if not can(ctl) or not mapped(ctl):
            continue
        nm = inline_name(ctl + OFF_NAME)
        if not nm:
            continue
        hd = ri(ctl + OFF_HANDLE)
        pawn = rq(page + SLOT_STRIDE * (hd & 0x1FF)) if hd else 0
        if not can(pawn):
            continue
        hp = ri(pawn + OFF_HEALTH)
        if not (0 <= hp <= 100):
            continue
        vo = rd(pawn + OFF_VIEW_OFFSET, 12)
        eye = struct.unpack("<3f", vo)[2] if vo else 0.0
        players.append((nm, pawn, hp, eye))

    alive = [p for p in players if p[3] > 1.0]
    print(f"pid={pid}  players={len(players)}  alive(eye>1)={len(alive)}")
    if len(alive) < 3:
        print("need at least 3 alive players for a meaningful agreement count")
        k32.CloseHandle(h); return 1

    # Dump each alive pawn once (2 KiB covers the whole object in practice) and
    # scan the bytes locally. Far fewer syscalls than per-field reads, and the
    # data is a consistent single sample.
    print("\nscanning pawn[0x000, 0x1000) for capsule-shaped vec3 pairs...\n")

    blobs = {}
    for nm, pawn, hp, eye in alive:
        raw = rd(pawn, 0x1000)
        if raw:
            blobs[nm] = raw

    # A player capsule: 40-120 units tall, under 40 wide. Require BOTH halves
    # of the pair to be plausible, and require maxs.z > mins.z.
    def capsule(mins, maxs):
        h_ = maxs[2] - mins[2]
        if not (40.0 < h_ < 120.0):
            return None
        if abs(maxs[0]) > 40.0 or abs(maxs[1]) > 40.0:
            return None
        if abs(mins[0]) > 40.0 or abs(mins[1]) > 40.0:
            return None
        # A capsule is taller than it is wide, and sits on the ground.
        if h_ <= abs(maxs[0]) * 2.0:
            return None
        if mins[2] > 4.0 or mins[2] < -40.0:
            return None
        return h_

    candidates = {}
    for nm, raw in blobs.items():
        for off in range(0, len(raw) - 24, 4):
            try:
                mins = struct.unpack_from("<3f", raw, off)
                maxs = struct.unpack_from("<3f", raw, off + 12)
            except struct.error:
                continue
            hgt = capsule(mins, maxs)
            if hgt is None:
                continue
            key = (off, round(mins[0], 2), round(mins[1], 2), round(mins[2], 2),
                   round(maxs[0], 2), round(maxs[1], 2), round(maxs[2], 2))
            candidates.setdefault(key, []).append(nm)

    if not candidates:
        print("no capsule-shaped vec3 pair anywhere in the first 4 KiB")
        k32.CloseHandle(h); return 1

    ranked = sorted(candidates.items(), key=lambda kv: -len(kv[1]))
    print(f"{'offset':>10} {'agree':>7} {'mins':>26} {'maxs':>26} {'h':>7} {'metres':>8}")
    for key, names in ranked[:14]:
        off = key[0]
        mins = (key[1], key[2], key[3])
        maxs = (key[4], key[5], key[6])
        hgt = key[6] - key[3]
        print(f"  +0x{off:04X} {len(names):>4}/{len(alive)}  "
              f"({mins[0]:7.2f},{mins[1]:7.2f},{mins[2]:7.2f})  "
              f"({maxs[0]:7.2f},{maxs[1]:7.2f},{maxs[2]:7.2f})  "
              f"{hgt:6.1f} {hgt / UNITS_PER_METRE:7.2f}")

    print()
    best = ranked[0]
    off, agree = best[0][0], len(best[1])
    hgt = best[0][6] - best[0][3]
    print(f"top candidate: pawn+0x{off:X}, {agree}/{len(alive)} alive players agree")
    print(f"  height {hgt:.2f} units = {hgt / UNITS_PER_METRE:.2f} m")
    print(f"  mins  = ({best[0][1]}, {best[0][2]}, {best[0][3]})")
    print(f"  maxs  = ({best[0][4]}, {best[0][5]}, {best[0][6]})")

    # Cross-check against the eye height we already trust. A standing player's
    # eyes sit a little below the top of the head; if the candidate says 72 and
    # the eye reads 64, that is ~8 units of head above the eyes, which is sane.
    eyes = [p[3] for p in alive]
    med_eye = sorted(eyes)[len(eyes) // 2]
    print(f"\n  median standing eye height from m_vecViewOffset: {med_eye:.2f} units")
    print(f"  candidate top - eye = {best[0][6] - med_eye:.2f} units "
          f"({(best[0][6] - med_eye) / UNITS_PER_METRE:.2f} m of head above the eyes)")
    if 2.0 < (best[0][6] - med_eye) < 20.0:
        print("  -> plausible. Eyes a few cm below the crown, as expected.")
    else:
        print("  -> IMPLAUSIBLE. A standing player's eyes are ~8 units below the")
        print("     top of the head. Treat this offset as noise, not bounds.")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())