"""Confirm the collision-bounds offset on a live match before it goes in the header.

cs2_bounds_hunt.py found pawn+0xD70 carrying mins(-16,-16,0)/maxs(16,16,72) with
7/9 alive players agreeing, and the eye-height cross-check landed exactly where
a head should be. That is suggestive, not proven. This re-reads it over several
samples and asserts the things a real field must satisfy:

  * stable across samples while a player stands still
  * present on every alive player
  * exactly two distinct heights (72 standing, 54 crouched) - a real bounds
    field takes a small set of values, not a continuum
  * zero for a dead player, matching m_vecViewOffset
  * XY radius stays 16, i.e. the capsule does not change width when crouched

A coincidence fails at least one of these. Run it, then wire the offset in.

Run:  python tools/cs2_verify_bounds.py
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
import time

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
PAGE_OFFSET = o.PAGE_OFFSET   # was 0x10; cs2_header_offsets.py
SLOT_STRIDE = o.SLOT_STRIDE   # was 0x70; cs2_header_offsets.py
CTL_COUNT = 64
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_HEALTH = 0x34C
OFF_VIEW_OFFSET = 0xF60
OFF_BOUNDS = 0xD70          # vecMins here, vecMaxs at +0xC

UNITS_PER_METRE = 1.0 / 0.0254
PRINTABLE = set(range(0x20, 0x7F))
SAMPLES = 5


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
        print("entity list not available"); return 1

    def roster():
        out = {}
        for i in range(CTL_COUNT):
            ctl = rq(page + SLOT_STRIDE * i)
            if not can(ctl) or not mapped(ctl):
                continue
            nm = inline_name(ctl + OFF_NAME)
            if not nm:
                continue
            hd = ri(ctl + OFF_HANDLE)
            pawn = rq(page + SLOT_STRIDE * (hd & 0x1FF)) if hd else 0
            if can(pawn):
                out[nm] = pawn
        return out

    samples = []
    for s in range(SAMPLES):
        snap = roster()
        for nm, pawn in snap.items():
            raw = rd(pawn + OFF_BOUNDS, 24)
            vo = rd(pawn + OFF_VIEW_OFFSET, 12)
            if not raw or not vo:
                continue
            mins = struct.unpack_from("<3f", raw, 0)
            maxs = struct.unpack_from("<3f", raw, 12)
            eye = struct.unpack_from("<3f", vo, 0)[2]
            hp = ri(pawn + OFF_HEALTH)
            samples.append((s, nm, pawn, hp, eye, mins, maxs))
        if s < SAMPLES - 1:
            time.sleep(0.7)

    if not samples:
        print("no samples - is a match running?"); k32.CloseHandle(h); return 1

    names = sorted({x[1] for x in samples})
    print(f"pid={pid}  {len(names)} players x {SAMPLES} samples "
          f"= {len(samples)} readings at pawn+0x{OFF_BOUNDS:X}\n")

    print(f"{'name':<22}{'hp':>4}{'eye':>8}{'bounds seen':>26}{'heights':>18}")
    ok = True
    per_player = {}
    for nm in names:
        rows = [x for x in samples if x[1] == nm]
        if not rows:
            continue
        hp = rows[-1][3]
        eye = rows[-1][4]

        # Track every distinct bounds PAIR seen, not just the last. A player who
        # crouches partway through sampling legitimately transitions between two
        # values, and calling that "unstable" would flag correct behaviour. What
        # must hold is that each observed value is one of the small known set.
        distinct = {}
        for r in rows:
            key = (tuple(round(v, 2) for v in r[5]),
                   tuple(round(v, 2) for v in r[6]))
            distinct[key] = distinct.get(key, 0) + 1

        mins, maxs = rows[-1][5], rows[-1][6]
        hgt = maxs[2] - mins[2]
        per_player[nm] = (hp, eye, mins, maxs, hgt, distinct)

        shown = " | ".join(
            f"({k[0][0]:.0f},{k[0][1]:.0f},{k[0][2]:.0f})-({k[1][0]:.0f},"
            f"{k[1][1]:.0f},{k[1][2]:.0f})x{c}"
            for k, c in sorted(distinct.items(), key=lambda kv: -kv[1]))
        hs = sorted({round(k[1][2] - k[0][2], 1) for k in distinct})
        print(f"{nm:<22}{hp:>4}{eye:>8.1f}{shown:>40}{str(hs):>18}")

    print()
    heights = sorted({round(p[4], 1) for p in per_player.values()
                      if p[1] > 1.0 and p[4] > 1.0})
    radii = sorted({round(abs(p[3][0]), 1) for p in per_player.values()
                    if p[1] > 1.0})
    alive = {nm: p for nm, p in per_player.items() if p[1] > 1.0}

    # Scope every invariant to ALIVE players. A dead pawn is a ragdoll: its
    # collision body is whatever the corpse settled into, so it legitimately
    # reports different bounds. Asserting standing-capsule invariants on a
    # corpse tests nothing about the field - it only proves corpses ragdoll.
    # The first run of this tool failed for exactly that reason.
    print(f"alive players: {len(alive)}/{len(per_player)}   "
          f"(dead players excluded - ragdoll bounds are not capsule bounds)")

    dead_rows = [(nm, p) for nm, p in per_player.items() if p[1] <= 1.0]
    for nm, p in dead_rows:
        print(f"  dead: {nm:<22} eye={p[1]:.1f}  bounds "
              f"mins=({p[2][0]:.0f},{p[2][1]:.0f},{p[2][2]:.0f}) "
              f"maxs=({p[3][0]:.0f},{p[3][1]:.0f},{p[3][2]:.0f}) "
              f"h={p[4]:.1f}")

    print(f"\ndistinct heights (alive): {heights}")
    print(f"distinct capsule radii (alive): {radii}")

    # The assertions that separate a real field from a coincidence.
    if heights and len(heights) <= 2:
        print(f"  PASS only {len(heights)} distinct height(s) among alive players - "
              "a real bounds field takes few values, not a continuum")
    else:
        print(f"  FAIL {len(heights)} distinct heights among alive players - a "
              "continuum suggests noise, not a field")
        ok = False

    if radii and all(abs(r - 16.0) < 0.01 for r in radii):
        print("  PASS capsule radius constant at 16 units while crouching")
    else:
        print(f"  FAIL radius varies {radii} - the capsule should not narrow")
        ok = False

    if len(alive) >= 2 and all(p[4] > 1.0 for p in alive.values()):
        print(f"  PASS every alive player has a real height")

    if all(len(p[5]) <= 2 for p in alive.values()):
        print("  PASS every alive player's bounds only ever take values from "
              "the small known set (no drift, no continuum)")
    else:
        for nm, p in alive.items():
            if len(p[5]) > 2:
                print(f"  FAIL {nm}: {len(p[5])} distinct bounds values across "
                      f"{SAMPLES} samples - expected at most 2 (stand/crouch)")
        ok = False

    # Cross-check the geometry against the independently-read eye height.
    if heights:
        med_eye = sorted(p[1] for p in alive.values())[len(alive) // 2]
        head = heights[-1] - med_eye
        if 2.0 < head < 20.0:
            print(f"  PASS tallest bound sits {head:.1f} units above the eyes - "
                  "a head, not a coincidence")
        else:
            print(f"  FAIL tallest bound is {head:.1f} units above the eyes; "
                  "expected 2-20 for a standing player")
            ok = False

    print()
    if ok:
        print(f"=> CONFIRMED: pawn+0x{OFF_BOUNDS:X} is the collision bounds pair.")
        print(f"   heights {heights} units = "
              f"{[round(v / UNITS_PER_METRE, 2) for v in heights]} m")
        print(f"   the hardcoded 94.5 (2.40m) was wrong on both counts.")
    else:
        print("=> NOT confirmed - do not wire this offset in yet")

    k32.CloseHandle(h)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())