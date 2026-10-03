"""Diagnose exactly which link of the weapon walk breaks.

## The situation

The dump tool reports "no live weapon with a sane clip1" while the game
clearly shows an AK-47 with 30 rounds in the magazine. So the failure is in
the resolution chain, not in the game state - and the tool's own message is
misleading, exactly the kind of plausible-but-wrong report this project keeps
producing.

Each link is printed with the value it actually returned, so the first one
that stops making sense is visible immediately. A link returning 0, 1 or a
non-address is the tell - the same signal as the degenerate dwEntityList
sentinel (SS7.3) and the non-pointer m_Item (SS3.1).

Read-only.
"""
import ctypes as C
import struct
import sys
import time

sys.path.insert(0, r"D:\game\MomoTrainerStudio\tools")
src = open(r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py", encoding="utf-8").read()
ns = {"__file__": r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py"}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
OFF_CLIP1 = 0x1928


def is_addr(v):
    return 0x10000 < v < (1 << 47)


pid = ns["find_pid"]("cs2.exe")
if not pid:
    print("cs2.exe not running")
    raise SystemExit(2)
h = k32.OpenProcess(0x0410, False, pid)
base = ns["module_base"](pid, "client.dll")
print(f"pid={pid}  client.dll=0x{base:X}\n")


def raw(va, n):
    b = C.create_string_buffer(n)
    g = C.c_size_t(0)
    if (not k32.ReadProcessMemory(h, C.c_void_p(va), b, n, C.byref(g))
            or g.value != n):
        return None
    return b.raw


def q(va):
    r = raw(va, 8)
    return struct.unpack("<Q", r)[0] if r else 0


def i32(va):
    r = raw(va, 4)
    return struct.unpack_from("<i", r, 0)[0] if r is None else 0


def step(n, val, ok, note=""):
    mark = "OK  " if ok else "FAIL"
    print(f"  [{mark}] {n:<34} = 0x{val:X}" if isinstance(val, int)
          else f"  [{mark}] {n:<34} = {val}")
    if note:
        print(f"         {note}")
    return ok


print("link 1: dwEntityList")
el = q(base + ns["ENTITY_LIST"])
step("*(clientBase + ENTITY_LIST)", el, is_addr(el),
     "a value of 1 means 'no match running' (uninitialised sentinel)")
if not is_addr(el):
    raise SystemExit("stop: entity list is not a pointer")

print("\nlink 2: the entity page")
page = q(el + ns["PAGE_OFFSET"])
step("*(entityList + 0x10)", page, is_addr(page))
if not is_addr(page):
    raise SystemExit("stop: no entity page")

print("\nlink 3: local pawn")
lp = q(base + ns["LOCAL_PAWN"])
step("*(clientBase + LOCAL_PAWN)", lp, is_addr(lp),
     "0 means dead/spectating or a round transition")
if not is_addr(lp):
    raise SystemExit("stop: no local pawn")

print("\nlink 4: weapon services")
ws = q(lp + 0x12F0)
step("*(pawn + 0x12F0)", ws, is_addr(ws))
if not is_addr(ws):
    raise SystemExit("stop: no weapon services")

print("\nlink 5: active weapon handle")
wsh = i32(ws + 0x60)
step("*(wpnSvc + 0x60)  m_hActiveWeapon", wsh & 0xFFFFFFFF, wsh != 0,
     "0xFFFFFFFF is 'invalid handle'")
if wsh in (0, -1):
    raise SystemExit("stop: no active weapon")

print("\nlink 6: handle -> slot -> entity")
slot = wsh & ns["HANDLE_MASK"]
print(f"         handle & 0x1FF = slot {slot}")
wpn = q(page + ns["SLOT_STRIDE"] * slot)
step("*(page + 0x70 * slot)", wpn, is_addr(wpn))
if not is_addr(wpn):
    raise SystemExit("stop: weapon entity did not resolve")

print("\nlink 7: the weapon IS the right entity (m_iClip1)")
clip = i32(wpn + OFF_CLIP1)
step(f"*(wpn + {OFF_CLIP1:#x})  m_iClip1", clip & 0xFFFFFFFF,
     1 <= clip <= 200,
     "must be 1..200 - this is the same gate the dump tool uses")
if not (1 <= clip <= 200):
    print("\n  This is where it fails: the entity at that slot is not your "
          "gun.")
    print(f"  clip1 = {clip}. Let me dump nearby slots to find the real one.")
    print(f"\n  scanning slots 0..511 for an entity with a sane clip1:")
    found = []
    for s in range(512):
        e = q(page + ns["SLOT_STRIDE"] * s)
        if not is_addr(e):
            continue
        c = i32(e + OFF_CLIP1)
        if 1 <= c <= 200:
            found.append((s, e, c))
    for s, e, c in found[:25]:
        print(f"    slot {s:<4} 0x{e:X}  clip1={c}")
    print(f"\n  {len(found)} slots have a sane clip1")
    if not found:
        print("  NONE - so no entity in the page has ammo data at 0x1928.")
        print("  Either the weapon offsets moved again, or this build's")
        print("  entity page layout differs. Print the raw slot values.")
    raise SystemExit(2)

print("\nALL LINKS OK - the weapon walk is sound")
print(f"  weapon 0x{wpn:X}  clip1={clip}")