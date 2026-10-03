"""Locate the paint-kit id field on a live CS2 weapon entity.

## Why measure instead of trusting a known offset

Public CS2 skin-changer offsets (`m_nFallbackPaintKitId` and friends) are
quoted for several builds with no version attached, and this project has
already been bitten by exactly that failure mode - two globals moved -0x10 on
2026-10-03 and every hardcoded probe read garbage with no error (handoff SS10,
SS14.11).

The same discipline applies here: find the field by its VALUE, then prove it
by changing what the game renders.

## How the field is identified

A paint-kit id is a small non-negative integer, 0..~534 for the real
catalogue (plus a 9000-series for workshop items). Almost every other int32 in
a weapon entity is a pointer, a bitfield or a float bit pattern. So:

  1. resolve several players' active weapon entities through the same handle
     walk the ammo probe already proved works
  2. sweep every 4-byte offset and collect int32 values
  3. score each offset by how many weapons hold a value inside the paint-kit
     id range there, AND how much those values VARY between weapons

Step 3's second half is what kills false positives. A field that is 0
everywhere, or the same value everywhere, is not a skin. A field holding
different plausible ids on different weapons is.

The values are then cross-referenced against build/paintkits.json so the
candidate can be read as a name: id 340 should print as "Jet Set".

Read-only. Nothing is written to the game process by this tool.
"""
import ctypes as C
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "cs2_weapon_probe.py"), encoding="utf-8").read()
ns = {"__file__": os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "cs2_weapon_probe.py")}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
PAGE_OFFSET = ns["PAGE_OFFSET"]
SLOT_STRIDE = ns["SLOT_STRIDE"]
HANDLE_MASK = ns["HANDLE_MASK"]
OFF_HANDLE = ns["OFF_HANDLE"]
OFF_NAME = ns["OFF_NAME"]
OFF_HEALTH = ns["OFF_HEALTH"]
OFF_WEAPON_SERVICES = ns["OFF_WEAPON_SERVICES"]
OFF_ACTIVE_WEAPON = ns["OFF_ACTIVE_WEAPON"]
OFF_CLIP1 = 0x1928
PRINTABLE = set(range(0x20, 0x7F))

BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "build")

# Real paint-kit ids from the catalogue.
KIT_MIN, KIT_MAX = 0, 11000
SWEEP_TO = 0x3000          # weapon entities are large; sweep well past 0x2000


def plausible(v):
    return 0x10000 < v < (1 << 47)


class Mem:
    def __init__(self, pid):
        self.h = k32.OpenProcess(0x0410, False, pid)
        self.base = ns["module_base"](pid, "client.dll")

    def raw(self, va, n):
        b = C.create_string_buffer(n)
        g = C.c_size_t(0)
        if (not k32.ReadProcessMemory(self.h, C.c_void_p(va), b, n, C.byref(g))
                or g.value != n):
            return None
        return b.raw

    def q(self, va):
        r = self.raw(va, 8)
        return struct.unpack("<Q", r)[0] if r else 0

    def i(self, va):
        r = self.raw(va, 4)
        return struct.unpack("<i", r)[0] if r else None

    def name(self, addr, cap=48):
        r = self.raw(addr, cap)
        if not r:
            return None
        s = r.split(b"\x00")[0]
        if not (2 <= len(s) <= 40):
            return None
        try:
            t = s.decode("ascii")
        except UnicodeDecodeError:
            return None
        return t if all(ord(c) in PRINTABLE for c in t) else None


def load_kits():
    p = os.path.join(BUILD, "paintkits.json")
    if not os.path.exists(p):
        return {}
    with open(p, encoding="utf-8") as f:
        return {str(v["paint_kit_id"]): v.get("display_name", "")
                for v in json.load(f).values()}


def main():
    pid = ns["find_pid"]("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    m = Mem(pid)
    kits = load_kits()
    el = m.q(m.base + ns["ENTITY_LIST"])
    page = m.q(el + PAGE_OFFSET) if plausible(el) else 0
    if not plausible(page):
        print("no entity page - start a match")
        return 1
    print(f"page 0x{page:X}   catalogue: {len(kits)} paint kits\n")

    # ---- collect weapon entities ----
    weapons = []
    for i in range(64):
        ctl = m.q(page + SLOT_STRIDE * i)
        if not plausible(ctl):
            continue
        nm = m.name(ctl + OFF_NAME)
        if not nm:
            continue
        hd = m.i(ctl + OFF_HANDLE)
        pawn = m.q(page + SLOT_STRIDE * (hd & HANDLE_MASK)) if hd else 0
        if not plausible(pawn):
            continue
        hp = m.i(pawn + OFF_HEALTH)
        if hp is None or not (0 <= hp <= 100):
            continue
        ws = m.q(pawn + OFF_WEAPON_SERVICES)
        wsh = m.i(ws + OFF_ACTIVE_WEAPON) if plausible(ws) else None
        if not wsh:
            continue
        wpn = m.q(page + SLOT_STRIDE * (wsh & HANDLE_MASK))
        if not plausible(wpn):
            continue
        clip = m.i(wpn + OFF_CLIP1)
        weapons.append((nm, pawn, wpn, clip))
    if len(weapons) < 2:
        print(f"only {len(weapons)} weapon entities - need >=2 to compare. "
              f"Start a match and wait for a full round.")
        return 1
    print(f"{len(weapons)} weapon entities:")
    for nm, pawn, wpn, clip in weapons:
        print(f"   {nm:<14} weapon 0x{wpn:X}  clip1={clip}")

    # ---- sweep every weapon, collect int32 per offset ----
    size = SWEEP_TO
    per_off = {}
    for nm, pawn, wpn, clip in weapons:
        blob = m.raw(wpn, size)
        if not blob:
            print(f"  ! cannot read {size} bytes at 0x{wpn:X} - entity may "
                  f"straddle an unmapped page")
            continue
        for off in range(0, size - 4, 4):
            v = struct.unpack_from("<i", blob, off)[0]
            per_off.setdefault(off, {})[nm] = v
    if not per_off:
        print("could not sweep any weapon entity")
        return 1

    # ---- score ----
    # A real paint-kit field: in range for most weapons, and the values
    # DIFFER between weapons (a skin is per-item, not a constant).
    scored = []
    for off, vals in per_off.items():
        v = list(vals.values())
        inrange = [x for x in v if KIT_MIN <= x <= KIT_MAX]
        if len(inrange) < max(2, len(v) // 2):
            continue
        distinct = len(set(inrange))
        if distinct < 2:
            continue                      # constant -> not a skin
        scored.append((len(inrange), distinct, off, vals))

    scored.sort(key=lambda t: (-t[0], -t[1]))
    print(f"\noffsets holding a plausible paint-kit id on >=half the weapons, "
          f"with at least 2 distinct values:")
    print(f"{'offset':<10}{'inrange':>9}{'distinct':>10}   values")
    shown = 0
    for n_in, n_dist, off, vals in scored:
        if shown >= 20:
            break
        sample = ", ".join(
            f"{k}={x}" + (f"({kits[str(x)]})" if str(x) in kits else "")
            for k, x in list(vals.items())[:5])
        print(f"  +0x{off:04X}   {n_in:>7}/{len(weapons)}   {n_dist:>8}   {sample}")
        shown += 1

    if not scored:
        print("\nno candidate. The paint kit is probably not a plain int32 on "
              "the entity - it may live in the attribute list "
              "(m_AttributeManager) which is reached through a pointer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())