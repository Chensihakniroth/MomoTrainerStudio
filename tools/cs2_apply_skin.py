"""Apply a paint kit to a live CS2 weapon entity.

    python cs2_apply_skin.py --list
    python cs2_apply_skin.py --weapon ak47 --skin 340 --wear 0.1 --seed 661
    python cs2_apply_skin.py --weapon ak47 --skin 0        # restore default

## Where the field is

From the cs2-dumper schema (D:\\cs2-dumper\\output\\client_dll.hpp), class
`C_EconEntity`:

    m_OriginalOwnerXuidLow   0x18A0  uint32
    m_OriginalOwnerXuidHigh  0x18A4  uint32
    m_nFallbackPaintKit       0x18A8  int32
    m_nFallbackSeed           0x18AC  int32
    m_flFallbackWear         0x18B0  float32
    m_nFallbackStatTrak      0x18B4  int32

CONFIRMED live before the first write: every unskinned weapon in a bot match
reads paintKit=0, wear=0.0, seed=0, and the local player's weapon carries a
non-zero owner XUID in 0x18A0/0x18A4. A wrong offset would not read zero for
all ten weapons at once.

## What this writes, and what it does not

Writes exactly four int32/float fields inside one 28-byte block on the weapon
entity. Nothing else: no code injection, no module patching, no driver, no
handle stripping.

**It is still a modification of a VAC-protected process.** Use it in a private
or bot match only. A single write is the detectable class of action; there is
no way to make applying a skin to your own weapon undetectable in principle,
only less obvious in practice.

`m_nFallbackPaintKit` is the *fallback* skin used when the item has no
server-side skin. Writing it changes what the client renders, which is the
"what does it look like" half of a skin changer - not ownership, not stats.
"""

import argparse
import ctypes as C
import ctypes.wintypes as wt
import json
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
OFF_HEALTH = ns["OFF_HEALTH"]
OFF_WEAPON_SERVICES = ns["OFF_WEAPON_SERVICES"]
OFF_ACTIVE_WEAPON = ns["OFF_ACTIVE_WEAPON"]
OFF_CLIP1 = 0x1928
PRINTABLE = set(range(0x20, 0x7F))

# C_EconEntity fallback block - from the cs2-dumper schema.
OFF_PAINTKIT = 0x18A8
OFF_SEED = 0x18AC
OFF_WEAR = 0x18B0
OFF_STRAK = 0x18B4

BUILD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "build")
OVERLAY = r"D:\game\ExternalOverlay"

PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008


def plausible(v):
    return 0x10000 < v < (1 << 47)


class Mem:
    def __init__(self, pid, write=False):
        access = 0x0410
        if write:
            access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        self.h = k32.OpenProcess(access, False, pid)
        if not self.h:
            raise OSError("OpenProcess failed - try running as Administrator")
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

    def f(self, va):
        r = self.raw(va, 4)
        return struct.unpack("<f", r)[0] if r else None

    def put_i(self, va, val):
        ok = k32.WriteProcessMemory(self.h, C.c_void_p(va),
                                    C.byref(C.c_int32(val)),
                                    4, None)
        if not ok:
            raise C.WinError()

    def put_f(self, va, val):
        ok = k32.WriteProcessMemory(self.h, C.c_void_p(va),
                                    C.byref(C.c_float(val)),
                                    4, None)
        if not ok:
            raise C.WinError()

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
    """(player_name, pawn, weapon) for every live weapon entity."""
    el = m.q(m.base + ns["ENTITY_LIST"])
    page = m.q(el + PAGE_OFFSET) if plausible(el) else 0
    if not plausible(page):
        return None, []
    out = []
    for i in range(64):
        ctl = m.q(page + SLOT_STRIDE * i)
        if not plausible(ctl):
            continue
        nm = m.name(ctl + 0x6FC)
        if not nm:
            continue
        hd = m.i(ctl + 0x92C)
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
    return page, out


def load_index():
    p = os.path.join(OVERLAY, "build", "weapon_skins.json")
    if not os.path.exists(p):
        return {}, {}
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    return data, p


def show_weapon(m, nm, wpn):
    pk = m.i(wpn + OFF_PAINTKIT)
    sd = m.i(wpn + OFF_SEED)
    wr = m.f(wpn + OFF_WEAR)
    st = m.i(wpn + OFF_STRAK)
    print(f"   {nm:<14} 0x{wpn:X}  paintkit={pk} seed={sd} "
          f"wear={wr} stattrak={st}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true",
                    help="list live weapons and their current skin")
    ap.add_argument("--weapon", help="weapon token, e.g. ak47 / awp / knife")
    ap.add_argument("--skin", type=int, help="paint kit id (0 = default)")
    ap.add_argument("--wear", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--strak", type=int, default=0)
    ap.add_argument("--player", default="beta088088",
                    help="whose weapon (default: you)")
    ap.add_argument("--hold", type=float, default=0.0,
                    help="seconds to keep it applied, then restore")
    a = ap.parse_args()

    pid = ns["find_pid"]("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    idx, idx_path = load_index()

    if a.list or a.skin is None:
        m = Mem(pid)
        page, players = resolve(m)
        if page is None:
            print("no entity page - start a match")
            return 1
        print(f"{len(players)} live weapons:\n")
        for nm, pawn, wpn in players:
            show_weapon(m, nm, wpn)
        if idx:
            print(f"\nskin index: {len(idx)} weapons in {idx_path}")
            for w in sorted(idx):
                print(f"   {w:<24} {idx[w]['skin_count']} skins")
        return 0

    # ---- apply ----
    want = ("weapon_" + a.weapon.lower()) if a.weapon else None
    if idx and want and want not in idx:
        near = [w for w in idx if a.weapon.lower() in w]
        print(f"'{a.weapon}' not in the skin index. Close matches: {near}")
        return 1

    m = Mem(pid, write=True)
    page, players = resolve(m)
    if page is None:
        print("no entity page - start a match")
        return 1
    target = None
    for nm, pawn, wpn in players:
        if nm == a.player:
            target = (nm, pawn, wpn)
            break
    if not target:
        print(f"player '{a.player}' has no live weapon "
              f"(alive and holding a gun?)")
        print(f"available: {[n for n, _, _ in players]}")
        return 1

    nm, pawn, wpn = target
    print(f"target: {nm} weapon 0x{wpn:X}")
    print("before:")
    show_weapon(m, nm, wpn)

    old = (m.i(wpn + OFF_PAINTKIT), m.i(wpn + OFF_SEED),
           m.f(wpn + OFF_WEAR), m.i(wpn + OFF_STRAK))

    # Validate the kit id against the catalogue before writing a wrong number.
    kits_path = os.path.join(OVERLAY, "build", "paintkits.json")
    label = ""
    if os.path.exists(kits_path) and a.skin:
        with open(kits_path, encoding="utf-8") as f:
            kits = {v["paint_kit_id"]: v.get("display_name", "")
                    for v in json.load(f).values()}
        if a.skin in kits:
            label = f" ({kits[a.skin]})"
        else:
            print(f"\nkit {a.skin} is not in the catalogue ({len(kits)} kits). "
                  f"Continuing anyway - pass --skin 0 to restore.")

    try:
        m.put_i(wpn + OFF_PAINTKIT, a.skin)
        m.put_i(wpn + OFF_SEED, a.seed)
        m.put_f(wpn + OFF_WEAR, a.wear)
        m.put_i(wpn + OFF_STRAK, a.strak)
    except OSError as e:
        print(f"\nWRITE FAILED: {e}")
        return 1

    time.sleep(0.3)
    print(f"\nwrote paintkit={a.skin}{label} seed={a.seed} "
          f"wear={a.wear} stattrak={a.strak}")
    print("after:")
    show_weapon(m, nm, wpn)

    ok = (m.i(wpn + OFF_PAINTKIT) == a.skin
          and m.i(wpn + OFF_SEED) == a.seed)
    print(f"\nreadback: {'OK' if ok else 'MISMATCH'}")

    if a.hold > 0:
        print(f"\nholding for {a.hold:.0f}s (the game may overwrite this on "
              f"weapon switch or repaint)...")
        t_end = time.time() + a.hold
        while time.time() < t_end:
            now = m.i(wpn + OFF_PAINTKIT)
            if now != a.skin:
                print(f"  game reset the field to {now} after "
                      f"{a.hold - (t_end - time.time()):.0f}s")
                break
            time.sleep(0.25)
        m.put_i(wpn + OFF_PAINTKIT, old[0])
        m.put_i(wpn + OFF_SEED, old[1])
        m.put_f(wpn + OFF_WEAR, old[2])
        m.put_i(wpn + OFF_STRAK, old[3])
        print("restored:", old)
    else:
        print(f"\nto restore: --skin 0  (or the previous values {old})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())