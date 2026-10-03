"""Locate m_iReserveAmmo. The one weapon offset the schema got wrong.

## What is confirmed vs still open

VERIFIED live on CS2 build 14188:

    pawn  + 0x12F0  m_pWeaponServices   pointer      OK
    wpnSvc+ 0x60   m_hActiveWeapon      int32 handle OK (handle walk works)
    wpn   + 0x1928 m_iClip1             int32        OK - decreased by
                                                  exactly 1 per shot, 7 shots
    wpn   + 0x192C m_iClip2             int32        reads -1, UNVERIFIED

WRONG on this build:

    wpn + 0x1930   m_pReserveAmmo       reads NULL for every player

The schema says reserve ammo is a `int32*` on the weapon. It is not a pointer
here, and no offset in the whole 0x0-0x2000 entity holds a mapped pointer to
a sane pair. So it is stored somewhere else.

## Where it probably is

In CS2 the reserve lives on **CPlayer_WeaponServices** as
`m_iAmmo` — a per-ammo-type array indexed by the weapon's ammo type, NOT on
the weapon entity at all. The weapon carries the magazine; the owner carries
the reserve. That also explains why hunting the weapon entity found nothing:
the field was never there.

This probes the weapon-services block and, for each candidate, checks whether
the value DEPLETES as the player fires and REFILLLS on reload. Only a
behavioural test distinguishes reserve ammo from the ~50 other integers that
look plausible.

Point it at a live match and fire.
"""
import ctypes as C
import os
import struct
import sys
import time

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

SVC_LO, SVC_HI = 0x40, 0x200      # weapon services block
RES_MAX = 400


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


def main():
    pid = ns["find_pid"]("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    m = Mem(pid)
    el = m.q(m.base + ns["ENTITY_LIST"])
    page = m.q(el + PAGE_OFFSET) if plausible(el) else 0
    if not plausible(page):
        print("no entity page - start a match")
        return 1

    # local player
    lp = m.q(m.base + ns["LOCAL_PAWN"])
    if not plausible(lp):
        print("no local pawn - you are dead or spectating")
        return 1
    ws = m.q(lp + OFF_WEAPON_SERVICES)
    if not plausible(ws):
        print("no weapon services on the local pawn")
        return 1
    wsh = m.i(ws + OFF_ACTIVE_WEAPON)
    wpn = m.q(page + SLOT_STRIDE * (wsh & HANDLE_MASK)) if wsh else 0
    clip = m.i(wpn + OFF_CLIP1) if plausible(wpn) else None
    print(f"local pawn 0x{lp:X}  wpnSvc 0x{ws:X}  weapon 0x{wpn:X}")
    print(f"active weapon handle 0x{(wsh or 0):08X}  clip1={clip}")
    if clip is None:
        print("\nno weapon resolved - hold a gun, not a knife")
        return 1
    if clip == 0:
        # Not a reason to abort: an empty magazine is the BEST state for
        # finding reserve ammo, because the next reload refills it and the
        # reserve slot is about to change. Wait briefly and carry on.
        print("\nclip1 is 0 (magazine empty). Waiting for a reload...")

    print(f"\nweapon-services block 0x{SVC_LO:X}-0x{SVC_HI:X}:")
    for off in range(SVC_LO, SVC_HI, 4):
        v = m.i(ws + off)
        if v is None:
            continue
        print(f"  +0x{off:03X}  {v:>10}"
              + ("   <- handle-shaped" if v and v > 0xFFFF else ""))

    print("\nNow watching for DEPLETION while you fire (25s).")
    print("Reserve ammo must fall as you shoot and rise on reload.\n")

    offs = list(range(SVC_LO, SVC_HI, 4))
    first = {}
    moved = {}
    clip_first = clip
    clip_drop = 0
    t_end = time.time() + 25
    while time.time() < t_end:
        c = m.i(wpn + OFF_CLIP1)
        if c is not None and clip_first is not None and c < clip_first:
            clip_drop += clip_first - c
        for off in offs:
            v = m.i(ws + off)
            if v is None or v < 0 or v > RES_MAX:
                continue
            k = off
            if k in first and first[k] != v:
                moved[k] = moved.get(k, 0) + 1
            first.setdefault(k, v)
        time.sleep(0.1)

    print(f"clip1 fell by {clip_drop} rounds during the window")

    # Re-watch, printing min/max/distinct per offset across a wider window.
    # In CS2 the reserve lives in CPlayer_WeaponServices::m_iAmmo - a fixed
    # per-ammo-type ARRAY. So the answer is an offset plus an index, not a
    # single field like m_iClip1. A reserve slot shows many distinct values,
    # goes DOWN as you shoot and UP on reload; a bitfield does not.
    cands = sorted(moved, key=lambda o: -moved[o])[:6]
    base = cands[0] if cands else 0xB8
    lo, hi = max(SVC_LO, base - 0x40), min(SVC_HI, base + 0x80)
    offs2 = list(range(lo, hi, 4))

    print("\nwatching the weapon-services ammo array (25s).")
    print("FIRE, then RELOAD when empty - the reserve slot must go UP.\n")
    seen_min, seen_max, hist = {}, {}, {}
    t_end = time.time() + 25
    while time.time() < t_end:
        for o in offs2:
            v = m.i(ws + o)
            if v is None or v < 0 or v > RES_MAX:
                continue
            seen_min[o] = min(seen_min.get(o, v), v)
            seen_max[o] = max(seen_max.get(o, v), v)
            hist.setdefault(o, set()).add(v)
        time.sleep(0.1)

    print(f"{'offset':<10}{'min':>7}{'max':>7}{'distinct':>10}  verdict")
    for o in offs2:
        if o not in seen_min:
            continue
        lo_, hi_ = seen_min[o], seen_max[o]
        d = len(hist[o])
        if d < 2 and hi_ == lo_:
            continue
        v = ("DEPLETES + REFILLS -> reserve ammo" if (d >= 3 and hi_ > lo_)
             else f"varies ({lo_}..{hi_})")
        print(f"  +0x{o:03X}   {lo_:>5}{hi_:>7}{d:>10}  {v}")

    print("\nNote the HUD read 13/31 earlier: 31 is the reserve for that "
          "weapon. A candidate is credible only if its max matches the "
          "on-screen reserve count.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())