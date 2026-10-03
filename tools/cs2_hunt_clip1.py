"""Find m_iClip1 by watching the live weapon entity.

## The situation

The weapon handle walk is NOT the problem. For the local player:

    pawn   handle 0x005E012F -> slot 0x12F (303) -> pawn, health 100   OK
    weapon handle 0x01DB819B -> slot 0x19B (411) -> 0x4603A238000      reads
    but reading int32 at weapon+0x1928 gives -1

A plausible pointer with a nonsense field value is the signature of a **wrong
field offset**, not a wrong walk (handoff SS3.3: "a right RVA with the wrong
access mode looks exactly like a stale offset").

`m_iClip1 = 0x1928` came from the cs2-dumper schema and was never verified
against this build. This tool finds the real one the way SS8.5 found the
collision bounds: **rank candidates by how many players agree**, then confirm
with the only test a coincidence fails.

## Method

1. Resolve each player's active weapon through the same handle walk.
2. Sweep every 4-byte offset in the weapon entity for int32 values in the
   plausible ammo range. A magazine count is a small non-negative integer;
   most offsets are pointers, floats or bitfields and are not.
3. Sample those candidates over time. **m_iClip1 must MOVE when the player
   fires.** A wrong offset reads a stable value, which is precisely why a
   plausible-looking number is not sufficient evidence.

Candidates are ranked by agreement across players first, then confirmed by
movement. A candidate that only one player has is a coincidence until it
moves.

Read-only; no writes to the game process.
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

SWEEP_FROM = 0x1800
SWEEP_TO = 0x19C0          # brackets the schema value 0x1928
AMMO_MIN, AMMO_MAX = 1, 200
# Reserve ammo is a POINTER to int32[2], not a small int, so it needs its
# own pass: find offsets whose value looks like a mapped pointer AND whose
# first two int32s are in the reserve range.
PTR_LO, PTR_HI = 0x10000, 1 << 47
RESERVE_MIN, RESERVE_MAX = 0, 400


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
    print(f"page 0x{page:X}\n")

    # ---- resolve every player's active weapon ----
    players = []
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
        if wsh is None or not wsh:
            continue
        slot = wsh & HANDLE_MASK
        wpn = m.q(page + SLOT_STRIDE * slot)
        if not plausible(wpn):
            continue
        players.append((nm, pawn, wpn, slot))
    if not players:
        print("no player has a resolvable active weapon")
        return 1
    print(f"{len(players)} players with a resolved weapon entity:")
    for nm, pawn, wpn, slot in players:
        print(f"   {nm:<14} pawn 0x{pawn:X}  weapon 0x{wpn:X}  slot {slot}")

    # ---- sweep for ammo-shaped ints ----
    offs = list(range(SWEEP_FROM, SWEEP_TO, 4))
    tally = {}
    for nm, pawn, wpn, slot in players:
        for off in offs:
            v = m.i(wpn + off)
            if v is not None and AMMO_MIN <= v <= AMMO_MAX:
                tally.setdefault(off, []).append((nm, v))
    ranked = sorted(tally.items(), key=lambda kv: -len(kv[1]))
    print(f"\noffsets holding an ammo-shaped int in 0x{SWEEP_FROM:X}-"
          f"0x{SWEEP_TO:X}, ranked by how many players agree:")
    for off, hits in ranked[:14]:
        vals = ", ".join(f"{n}={v}" for n, v in hits[:4])
        print(f"   +0x{off:04X}  {len(hits)}/{len(players)} players   {vals}")

    if not ranked:
        print("\nno ammo-shaped value anywhere in the sweep range - "
              "the weapon entity or the walk is wrong, not the offset")
        return 1

    # ---- reserve ammo hunt ----
    # The schema says m_pReserveAmmo at 0x1930 is a POINTER to int32[2],
    # but it reads null on every player, and no offset in 0x1800-0x19C0 holds
    # a mapped pointer at all. So sweep the WHOLE entity for the reserve
    # pattern instead of assuming the pointer shape:
    #
    #   a) a mapped pointer to two sane ints          (the schema's claim)
    #   b) two adjacent sane ints, magazine-like      (inline array)
    #
    # Ranked by how many of the 10 players agree, which is what separates a
    # real field from a coincidence (SS8.5's method).
    print("\nreserve-ammo hunt over the whole weapon entity:")
    ENT_LO, ENT_HI = 0, 0x2000
    ptr_hits, inline_hits = {}, {}
    for nm, pawn, wpn, slot in players:
        for off in range(ENT_LO, ENT_HI, 4):
            v = m.q(wpn + off)
            if PTR_LO < v < PTR_HI:
                a = m.i(v)
                b = m.i(v + 4) if a is not None else None
                if a is None or b is None:
                    continue
                if RESERVE_MIN <= a <= RESERVE_MAX and 0 <= b <= 64:
                    ptr_hits.setdefault(off, []).append((nm, a, b))
            a = m.i(wpn + off)
            b = m.i(wpn + off + 4)
            if (a is not None and b is not None
                    and 0 < a <= RESERVE_MAX and 0 <= b <= 8):
                inline_hits.setdefault(off, []).append((nm, a, b))

    print("\n  (a) pointer to int32[2]:")
    if not ptr_hits:
        print("      none - m_pReserveAmmo is NOT a pointer on this build")
    for off, hits in sorted(ptr_hits.items(), key=lambda kv: -len(kv[1]))[:8]:
        print(f"      +0x{off:04X}  {len(hits)}/{len(players)} players  "
              f"{', '.join('%s=[%d,%d]' % h for h in hits[:3])}")

    print("\n  (b) inline pair (first>=second, both small):")
    for off, hits in sorted(inline_hits.items(), key=lambda kv: -len(kv[1]))[:8]:
        print(f"      +0x{off:04X}  {len(hits)}/{len(players)} players  "
              f"{', '.join('%s=[%d,%d]' % h for h in hits[:3])}")

    # schema value for comparison
    schema = 0x1928
    print(f"\nschema m_iClip1 = 0x{schema:04X} reads "
          f"{[m.i(p[2] + schema) for p in players]}")

    # ---- movement test: the only check a coincidence fails ----
    print("\nwatching candidates for MOVEMENT (this is the real test).")
    print("Fire your weapon during this window.\n")
    watch = [off for off, _ in ranked[:10]]
    first = {}
    changes = {off: 0 for off in watch}
    samples = 0
    t_end = time.time() + 25
    while time.time() < t_end:
        for nm, pawn, wpn, slot in players:
            for off in watch:
                v = m.i(wpn + off)
                if v is None:
                    continue
                key = (nm, off)
                if key in first and first[key] != v:
                    changes[off] += 1
                first.setdefault(key, v)
        samples += 1
        time.sleep(0.15)

    print(f"{samples} samples over 25s\n")
    print(f"{'offset':<10}{'changes':>9}  verdict")
    winners = []
    for off in watch:
        n = changes[off]
        if n:
            winners.append((off, n))
            print(f"  +0x{off:04X}  {n:>7}  MOVES - candidate m_iClip1")
        else:
            print(f"  +0x{off:04X}  {n:>7}  stable - not ammo")
    if not winners:
        print("\nNothing moved. Either nobody fired, or m_iClip1 is outside "
              "the sweep range. Re-run and fire during the window.")
        return 1
    best = max(winners, key=lambda t: t[1])
    print(f"\nbest candidate: +0x{best[0]:04X} ({best[1]} changes)")
    print("Confirm with cs2_verify_weapon.py before enabling the readout.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())