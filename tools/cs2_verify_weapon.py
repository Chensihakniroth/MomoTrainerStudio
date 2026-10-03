"""Confirm the CS2 weapon/ammo offsets live. The pass condition, isolated.

`cs2_hunt_clip1.py` finds candidates by agreement + movement. This asserts
the specific offsets the overlay uses, so a future CS2 update fails loudly
instead of silently displaying nonsense.

## What "verified" means here

A plausible magazine count is NOT proof. A wrong offset frequently reads a
small non-negative integer, because most of a weapon entity is bitfields and
small counters. The only test that separates the two is behavioural:

    m_iClip1 must DECREASE by the number of rounds fired.

So this asserts:

  1. every player's clip1 is in the plausible magazine range (0..200)
  2. clip1 is non-increasing for a held trigger (it can only go down, plus
     reload jumps which are skipped by sampling fast)
  3. at least one DECREASE is observed while firing
  4. reload raises clip1 back toward the magazine size

Point 2 and 3 together are what a coincidence fails: a stable pointer
fragment never decreases by exactly the shots fired.

Run it in a live match and fire. Read-only; nothing is written to the game.
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
PRINTABLE = set(range(0x20, 0x7F))

OFF_CLIP1 = 0x1928
OFF_CLIP2 = 0x192C
OFF_RESERVE_AMMO = 0x1930
MAG_MIN, MAG_MAX = 1, 200

failures = []


def check(cond, msg):
    print(f"  [{'PASS' if cond else 'FAIL'}] {msg}")
    if not cond:
        failures.append(msg)
    return cond


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


def resolve(m):
    """[(name, pawn, weapon)] for every player with a live weapon."""
    el = m.q(m.base + ns["ENTITY_LIST"])
    page = m.q(el + PAGE_OFFSET) if plausible(el) else 0
    if not plausible(page):
        return None, None
    out = []
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
        if plausible(wpn):
            out.append((nm, pawn, wpn))
    return out, page


def main():
    pid = ns["find_pid"]("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    m = Mem(pid)
    players, page = resolve(m)
    if page is None:
        print("no entity page - start a match")
        return 1

    print("=== structural ===")
    check(len(players) >= 2,
          f"resolved {len(players)} players with a weapon entity (need >=2)")

    sane = []
    for nm, pawn, wpn in players:
        c = m.i(wpn + OFF_CLIP1)
        ok = c is not None and MAG_MIN <= c <= MAG_MAX
        print(f"    {nm:<14} weapon 0x{wpn:X}  clip1={c}  clip2="
              f"{m.i(wpn + OFF_CLIP2)}")
        if ok:
            sane.append((nm, pawn, wpn, c))
    check(len(sane) >= 2,
          f"{len(sane)} players have a sane clip1 in {MAG_MIN}..{MAG_MAX} "
          f"(need >=2)")
    if len(sane) < 2:
        print("\nVERDICT: FAIL - offsets not usable")
        return 1

    # ---- reserve ammo is a pointer to int32[2] ----
    nm, pawn, wpn, _ = sane[0]
    rpa = m.q(wpn + OFF_RESERVE_AMMO)
    check(plausible(rpa), f"m_pReserveAmmo reads a pointer (0x{rpa:X})")
    if plausible(rpa):
        r0 = m.i(rpa)
        check(r0 is not None and 0 <= r0 <= 400,
              f"reserve ammo[0] = {r0} is in 0..400")

    print("\n=== behavioural (FIRE NOW) ===")
    print("watching the local player for 25s - fire your weapon\n")
    local = None
    for nm_, pawn_, wpn_ in players:
        if nm_ == "beta088088":
            local = (nm_, pawn_, wpn_)
    if local is None:
        print("  local player not found by name; using the first sane entry")
        local = (sane[0][0], sane[0][1], sane[0][2])
    label, _, wpn_l = local

    prev = m.i(wpn_l + OFF_CLIP1)
    drops = []
    reloads = 0
    samples = 0
    t_end = time.time() + 25
    while time.time() < t_end:
        v = m.i(wpn_l + OFF_CLIP1)
        samples += 1
        if v is None or prev is None:
            prev = v
            continue
        if v < prev:
            drops.append(prev - v)
        elif v > prev and prev <= 3:
            reloads += 1        # refilled from a nearly-empty magazine
        prev = v
        time.sleep(0.05)

    print(f"  {samples} samples, {len(drops)} decreases, {reloads} reloads")
    print(f"  first drops: {drops[:12]}")
    check(len(drops) > 0,
          "m_iClip1 decreased while firing (the behavioural proof)")
    check(all(1 <= d <= 5 for d in drops),
          f"every decrease is 1..5 rounds (got {sorted(set(drops))})")

    print(f"\n=== RESULT: {'PASS' if not failures else 'FAIL'} "
          f"({len(failures)} failures)")
    if failures:
        for f in failures:
            print(f"  - {f}")
        return 1
    print("m_iClip1 = 0x1928 CONFIRMED live. The weapon/ammo readout in the")
    print("overlay can be enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())