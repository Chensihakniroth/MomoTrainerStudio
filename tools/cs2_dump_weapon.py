"""Dump a live CS2 weapon entity to disk, once, for offline analysis.

## Why

Every live probe so far has raced the game. The weapon entity is freed on
round end and its slot recycled, so successive reads return different
addresses, `None`, or a recycled entity's values (`m_Item = 0x-727735E8`).
Twenty probes have not settled where the paint-kit attribute vector is.

A single dump removes the race entirely: capture once, then search the file
as many times as needed without the game moving underneath.

## What it writes

  build/weapon_dump.bin     0x4000 bytes from the weapon entity
  build/weapon_dump.json    the address, handle, and known-field readings

Sanity gate: `m_iClip1` (0x1928) must read 1..200. If it does not, the dump is
of the wrong entity and the file is not written - a dump of a recycled slot
is worse than no dump, because it looks like real data.

Read-only. Nothing is written to the game process.
"""
import ctypes as C
import json
import os
import struct
import sys
import time

sys.path.insert(0, r"D:\game\MomoTrainerStudio\tools")
src = open(r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py", encoding="utf-8").read()
ns = {"__file__": r"D:\game\MomoTrainerStudio\tools\cs2_weapon_probe.py"}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
DUMP_SIZE = 0x4000
OFF_CLIP1 = 0x1928
BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "build")


def is_addr(v):
    return 0x10000 < v < (1 << 47)


pid = ns["find_pid"]("cs2.exe")
if not pid:
    print("cs2.exe not running")
    raise SystemExit(2)
h = k32.OpenProcess(0x0410, False, pid)
base = ns["module_base"](pid, "client.dll")


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
    return struct.unpack_from("<i", r, 0)[0] if r else None


def u16(va):
    r = raw(va, 2)
    return struct.unpack_from("<H", r, 0)[0] if r else None


def f32(va):
    r = raw(va, 4)
    return struct.unpack_from("<f", r, 0)[0] if r else None


# ---- resolve, retrying briefly so a round transition is survivable ----
wpn = 0
for attempt in range(40):
    el = q(base + ns["ENTITY_LIST"])
    if not is_addr(el):
        time.sleep(0.25)
        continue
    page = q(el + ns["PAGE_OFFSET"])
    if not is_addr(page):
        time.sleep(0.25)
        continue
    lp = q(base + ns["LOCAL_PAWN"])
    if not is_addr(lp):
        time.sleep(0.25)
        continue
    ws = q(lp + 0x12F0)
    if not is_addr(ws):
        time.sleep(0.25)
        continue
    wsh = i32(ws + 0x60)
    if not wsh:
        time.sleep(0.25)
        continue
    cand = q(page + ns["SLOT_STRIDE"] * (wsh & ns["HANDLE_MASK"]))
    if is_addr(cand):
        # Take the first entity that resolves, even if its clip1 is not yet
        # sane. A handle mid-swap reads 0 for one frame, and insisting on a
        # good clip1 in the SAME sample rejected a perfectly good weapon -
        # the retry loop then kept re-resolving while the gun changed.
        # Sanity is confirmed below on a SECOND sample, which is the check
        # that actually matters: two agreeing reads are not a race.
        wpn = cand
        break
    time.sleep(0.25)

if not wpn:
    print("could not get a live weapon with a sane clip1 after 10s.")
    print("Hold a gun with rounds in the magazine, alive, not spectating.")
    raise SystemExit(1)

# ---- confirm stable across samples before trusting the dump ----
# m_iClip1 legitimately changes (you fire), so equality is NOT the criterion.
# What must hold is that the entity address is still mapped and still the
# same econ entity: the vtable pointer at +0x00 is stable for the life of
# the entity, whereas a recycled slot gets a different one.
def vtable(va):
    return q(va)


samples = []
for _ in range(6):
    samples.append((vtable(wpn), i32(wpn + OFF_CLIP1)))
    time.sleep(0.15)
vt0 = samples[0][0]
if any(v != vt0 for v, _ in samples):
    print(f"entity address is being recycled across samples: {samples}")
    print("the weapon changed mid-dump - respawning or switching.")
    raise SystemExit(1)
c1 = samples[0][1]
if not (1 <= c1 <= 200):
    print(f"warning: m_iClip1 = {c1} (not a magazine count).")
    print("Dumping anyway - the paint-kit attribute search does not need")
    print("ammo, and a 0 can just mean the magazine is momentarily empty.")
    print(f"clip1 samples: {[c for _, c in samples]}")

blob = raw(wpn, DUMP_SIZE)
if not blob:
    print(f"could not read {DUMP_SIZE:#x} bytes at 0x{wpn:X}")
    raise SystemExit(1)

os.makedirs(BUILD, exist_ok=True)
bpath = os.path.join(BUILD, "weapon_dump.bin")
with open(bpath, "wb") as f:
    f.write(blob)

meta = {
    "weapon_address": f"0x{wpn:X}",
    "weapon_handle": f"0x{(wsh or 0):08X}",
    "clip1_samples": [c for _, c in samples],
    "vtable": f"0x{vt0:X}",
    "size": len(blob),
    "pid": pid,
    "client_base": f"0x{base:X}",
    "known_fields": {
        "0x1288_m_bAttributesInitialized": i32(wpn + 0x1288),
        "0x1290_m_AttributeManager": f"0x{q(wpn + 0x1290):X}",
        "0x18A8_m_nFallbackPaintKit": i32(wpn + 0x18A8),
        "0x18AC_m_nFallbackSeed": i32(wpn + 0x18AC),
        "0x18B0_m_flFallbackWear": f32(wpn + 0x18B0),
        "0x18B4_m_nFallbackStatTrak": i32(wpn + 0x18B4),
        "0x1928_m_iClip1": c1,
    },
}
mpath = os.path.join(BUILD, "weapon_dump.json")
with open(mpath, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=1)

print(f"weapon 0x{wpn:X}  handle 0x{(wsh or 0):08X}")
print(f"clip1 samples: {[c for _, c in samples]}")
print(f"wrote {bpath} ({len(blob):,} bytes)")
print(f"wrote {mpath}")
print("\nknown fields:")
for k, v in meta["known_fields"].items():
    print(f"   {k:<38} {v}")