"""Find real player height data on the pawn, live.

The overlay currently draws every box at a hardcoded 94.5 Source units, which is
an arithmetic guess from "1.8m / 1.905cm", not a value the game reported. This
probes two candidate sources so the guess can be replaced with evidence:

  1. m_vecViewOffset (pawn + 0xF60) - the EYE height above the feet. Cheap,
     always present, and it changes when a player crouches, so it doubles as a
     live crouch detector. It is NOT total body height though.

  2. The collision scene node's vecMins/vecMaxs - the actual capsule bounds.
     Reached through C_BaseEntity::m_pCollisionSceneNode, whose offset is not in
     our generated header, so this sweeps the neighbourhood of m_pGameSceneNode
     (0x330) looking for a pointer that behaves like a collision node.

For each candidate collision node the vec3 pair at +0xC8 is read, because
m_vecAbsOrigin lives there on the game scene node and vecMins/vecMaxs sit right
after it on the collision node. Height = maxs.z - mins.z.

Run:  python tools/cs2_player_height.py
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

# From the generated header (cs2_offsets.h, build 14188).
ENTITY_LIST = o.ENTITY_LIST   # was 0x2715828; cs2_header_offsets.py
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
PAGE_OFFSET = o.PAGE_OFFSET   # was 0x10; cs2_header_offsets.py
SLOT_STRIDE = o.SLOT_STRIDE   # was 0x70; cs2_header_offsets.py
CTL_COUNT = 64
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_VIEW_OFFSET = 0xF60

PRINTABLE = set(range(0x20, 0x7F))
# 1 Source unit is an inch (2.54cm), NOT 1.905cm. The old comment used the
# half-foot figure, which is why 94.5 was wrong. Kept here only to show the
# delta rather than silently replacing one magic number with another.
UNITS_PER_METRE = 1.0 / 0.0254


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

    def rf3(v):
        r = rd(v, 12)
        return struct.unpack("<3f", r) if r else None

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
    local_pawn = rq(base + LOCAL_PAWN)
    if not can(page):
        print("entity list not available - is a match running?"); return 1

    # Build the player list through the controller chain (see handoff 2).
    players = []
    for i in range(CTL_COUNT):
        ctl = rq(page + SLOT_STRIDE * i)
        if not can(ctl) or not mapped(ctl):
            continue
        nm = inline_name(ctl + OFF_NAME)
        if not nm:
            continue
        hd = ri(ctl + OFF_HANDLE)
        slot = hd & 0x1FF
        pawn = rq(page + SLOT_STRIDE * slot) if hd else 0
        if not can(pawn):
            continue
        hp = ri(pawn + OFF_HEALTH)
        if not (0 <= hp <= 100):
            continue
        players.append((nm, pawn, hp, pawn == local_pawn))

    if not players:
        print("no players found - start a match and retry")
        k32.CloseHandle(h)
        return 1

    print(f"pid={pid} client.dll 0x{base:X}   players={len(players)}")
    print(f"1 Source unit = 2.54cm, so {UNITS_PER_METRE:.1f} units per metre")
    print(f"the hardcoded 94.5 assumed 1.905cm/unit -> {94.5 / UNITS_PER_METRE:.2f} m"
          f"  (too tall)\n")

    # ---- 1. m_vecViewOffset: eye height, and a crouch signal ----
    print("== m_vecViewOffset (pawn + 0xF60) = eye height above feet ==")
    print(f"{'name':<16}{'hp':>4}{'loc':>5}{'viewOffset':>26}{'eye(m)':>9}")
    eyes = {}
    for nm, pawn, hp, is_loc in players:
        vo = rf3(pawn + OFF_VIEW_OFFSET)
        if not vo:
            print(f"{nm:<16}{hp:>4}{'Y' if is_loc else '':>5}{'(unreadable)':>26}")
            continue
        eyes[nm] = vo[2]
        print(f"{nm:<16}{hp:>4}{'Y' if is_loc else '':>5}"
              f"{f'({vo[0]:7.2f},{vo[1]:7.2f},{vo[2]:7.2f})':>26}"
              f"{vo[2] / UNITS_PER_METRE:>9.2f}")
    if eyes:
        vals = sorted(eyes.values())
        print(f"  eye heights seen: {vals}")
        print(f"  distinct: {sorted(set(round(v, 1) for v in vals))}"
              "   (two clusters = standing + crouched)")

    # ---- 2. hunt for the collision scene node ----
    # Sweep pointers near m_pGameSceneNode (0x330) and test each for a vec3 pair
    # at +0xC8 that looks like capsule bounds: mins.z near 0 or negative, maxs.z
    # positive and plausible, and the XY magnitudes much smaller than Z (a player
    # capsule is tall and narrow).
    print("\n== hunting m_pCollisionSceneNode ==")
    print("sweeping pointers in [0x300, 0x480) for capsule bounds at +0xC8\n")

    cand_offsets = {}
    for nm, pawn, hp, is_loc in players:
        for off in range(0x300, 0x480, 8):
            p = rq(pawn + off)
            if not can(p) or not mapped(p):
                continue
            mins = rf3(p + 0xC8)
            maxs = rf3(p + 0xD4)
            if not mins or not maxs:
                continue
            height = maxs[2] - mins[2]
            # A player capsule is 50-90 units tall, ~16 wide. Anything outside
            # that is some other vector that happens to live here.
            if not (40.0 < height < 120.0):
                continue
            if abs(maxs[0]) > 40.0 or abs(maxs[1]) > 40.0:
                continue
            if abs(mins[0]) > 40.0 or abs(mins[1]) > 40.0:
                continue
            key = (off, round(mins[0], 2), round(mins[1], 2), round(mins[2], 2),
                   round(maxs[0], 2), round(maxs[1], 2), round(maxs[2], 2))
            cand_offsets.setdefault(key, []).append(nm)

    if not cand_offsets:
        print("no capsule-shaped vec3 pair found in that range")
        print("-> the collision node is elsewhere, or bounds live at another offset")
    else:
        # Rank by how many distinct players agree. A real field is identical on
        # every standing player; a coincidence varies.
        ranked = sorted(cand_offsets.items(), key=lambda kv: -len(kv[1]))
        for key, names in ranked[:6]:
            off = key[0]
            height = key[6] - key[3]
            print(f"pawn+0x{off:X}: {len(names)}/{len(players)} players agree   "
                  f"mins=({key[1]},{key[2]},{key[3]}) maxs=({key[4]},{key[5]},{key[6]})"
                  f"  height={height:.1f}u = {height / UNITS_PER_METRE:.2f}m")
        best = ranked[0]
        off = best[0][0]
        agree = len(best[1])
        if agree >= max(2, len(players) // 2):
            print(f"\n=> m_pCollisionSceneNode is most likely pawn+0x{off:X}")
            print(f"   {agree}/{len(players)} players share identical bounds,")
            print(f"   height {best[0][6] - best[0][3]:.1f} units.")
            print("   Caveat: this sweep reads +0xC8 as mins and +0xD4 as maxs.")
            print("   Confirm the two differ by one cache line in a hex dump before")
            print("   trusting it - a single vec3 at 0xC8 would satisfy it too.")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())