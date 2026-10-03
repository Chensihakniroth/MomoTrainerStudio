"""Diagnose the weapon handle -> entity slot walk.

The weapon probe resolves pawns correctly (10 players, sane health) but the
weapon comes back unresolved for everyone. This isolates which step is wrong:

    pawn handle  m_hPlayerPawn   0x92C   known to work
    weapon handle m_hActiveWeapon 0x60    never verified

`m_hActiveWeapon` is read from CPlayer_WeaponServices, and its low bits are
assumed to index the entity page the same way the pawn handle does. That
assumption is what is under test.

Prints the same handles under several plausible index rules so the correct
one is visible rather than guessed at.
"""
import ctypes as C
import ctypes.wintypes as wt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "cs2_weapon_probe.py"), encoding="utf-8").read()
ns = {"__file__": os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "cs2_weapon_probe.py")}
exec(compile(src.split("def main")[0], "wp", "exec"), ns)

k32 = ns["k32"]
NS = {}
PAGE_OFFSET = ns["PAGE_OFFSET"]
SLOT_STRIDE = ns["SLOT_STRIDE"]
HANDLE_MASK = ns["HANDLE_MASK"]
OFF_HANDLE = ns["OFF_HANDLE"]
OFF_NAME = ns["OFF_NAME"]
OFF_HEALTH = ns["OFF_HEALTH"]
OFF_WEAPON_SERVICES = ns["OFF_WEAPON_SERVICES"]
OFF_ACTIVE_WEAPON = ns["OFF_ACTIVE_WEAPON"]
# inline_name() and read_ascii() are nested inside main() in the source
# script, so they are NOT in the pre-main namespace. Re-implement them here
# rather than editing the other tool's structure just to borrow two helpers.
PRINTABLE = set(range(0x20, 0x7F))


def inline_name(addr):
    b = C.create_string_buffer(64)
    g = C.c_size_t(0)
    if not k32.ReadProcessMemory(NS["h"], C.c_void_p(addr), b, 64,
                                 C.byref(g)):
        return None
    raw = b.raw.split(b"\x00")[0]
    if not (2 <= len(raw) <= 40):
        return None
    try:
        t = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(ord(c) in PRINTABLE for c in t) else None


def read_ascii(addr, n=48):
    b = C.create_string_buffer(n)
    g = C.c_size_t(0)
    if not k32.ReadProcessMemory(NS["h"], C.c_void_p(addr), b, n, C.byref(g)):
        return None
    raw = b.raw.split(b"\x00")[0]
    try:
        t = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return t if all(ord(c) in PRINTABLE for c in t) and t else None


def make(pid):
    h = k32.OpenProcess(0x0410, False, pid)
    base = ns["module_base"](pid, "client.dll")

    def rq(va):
        b = C.create_string_buffer(8)
        g = C.c_size_t(0)
        if (not k32.ReadProcessMemory(h, C.c_void_p(va), b, 8, C.byref(g))
                or g.value != 8):
            return 0
        return int.from_bytes(b.raw[:8], "little")

    def ri(va):
        b = C.create_string_buffer(4)
        g = C.c_size_t(0)
        if (not k32.ReadProcessMemory(h, C.c_void_p(va), b, 4, C.byref(g))
                or g.value != 4):
            return None
        return int.from_bytes(b.raw[:4], "little", signed=True)
    return h, base, rq, ri


def plausible(p):
    return 0x10000 < p < 0x7FFFFFFFFFFF


def main():
    pid = ns["find_pid"]("cs2.exe")
    if not pid:
        print("cs2.exe not running")
        return 2
    h, base, rq, ri = make(pid)
    NS["h"] = h
    el = rq(base + ns["ENTITY_LIST"])
    page = rq(el + PAGE_OFFSET) if plausible(el) else 0
    if not plausible(page):
        print("no entity page - start a match")
        return 1
    print(f"page 0x{page:X}\n")

    # Candidate index rules for a handle -> slot mapping.
    rules = [
        ("h & 0x1FF", 0x1FF),
        ("h & 0xFFF", 0xFFF),
        ("h & 0x7FFF", 0x7FFF),
        ("h >> 8", None),
        ("(h >> 1) & 0x1FF", None),
    ]

    ctl = None
    for i in range(64):
        c = rq(page + SLOT_STRIDE * i)
        if c and inline_name(c + OFF_NAME) == "beta088088":
            ctl = c
            print(f"local controller at slot {i}, ptr 0x{c:X}")
            break
    if not ctl:
        print("local controller not found")
        return 1

    hd = ri(ctl + OFF_HANDLE)
    pawn = rq(page + SLOT_STRIDE * (hd & HANDLE_MASK))
    print(f"pawn handle 0x{hd:08X} -> pawn 0x{pawn:X} health "
          f"{ri(pawn + OFF_HEALTH)}\n")

    ws = rq(pawn + OFF_WEAPON_SERVICES)
    wsh = ri(ws + OFF_ACTIVE_WEAPON) if plausible(ws) else None
    print(f"wpnSvc 0x{ws:X}   m_hActiveWeapon="
          f"{'0x%08X' % wsh if wsh is not None else 'None'}\n")

    print("weapon handle under each index rule:")
    for label, mask in rules:
        if mask is None:
            if label == "h >> 8":
                slot = (wsh >> 8) if wsh is not None else -1
            else:
                slot = ((wsh >> 1) & 0x1FF) if wsh is not None else -1
        else:
            slot = (wsh & mask) if wsh is not None else -1
        wpn = rq(page + SLOT_STRIDE * slot) if slot >= 0 else 0
        clip = ri(wpn + ns["OFF_CLIP1"]) if plausible(wpn) else None
        des = read_ascii(wpn + 0x20, 48) if plausible(wpn) else None
        ok = "READS" if plausible(wpn) else "-"
        print(f"  {label:<18} slot={slot:<6} wpn=0x{wpn:<14X} {ok:6}"
              f" clip1={clip} name={des}")

    print("\nraw weapon-services block (0x50..0x90):")
    for off in range(0x50, 0x90, 4):
        v = ri(ws + off)
        print(f"  +0x{off:02X}  {('0x%08X' % v) if v is not None else '-':>12}"
              f"   int={v}")
    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())