"""Resolve and verify the CS2 weapon / ammo chain, live.

Source: the cs2-dumper client dump in D:\\cs2-dumper\\output. Offsets are
taken verbatim from client_dll.hpp, where each appears exactly once:

    pawn    + 0x12F0   m_pWeaponServices  (CPlayer_WeaponServices*, POINTER)
    wpnSvc  + 0x60     m_hActiveWeapon    (int32 handle, NOT a pointer)
    wpnSvc  + 0x68     m_iAmmo            (uint16[32] reserve, per ammo type)
    weapon  + 0x1928   m_iClip1           (int32, magazine)
    weapon  + 0x192C   m_iClip2           (int32, spare chamber)
    weapon  + 0x1930   m_pReserveAmmo     (POINTER to int32[2])

The handle uses the SAME page walk as every other entity, so this cost no new
machinery.

The ammo fields can be verified immediately: clip1 must be >= 0 and sane, and
it must MOVE when the local player fires. That last check is the one that
distinguishes the right offset from a plausible-looking one.

WEAPON NAME: CBaseEntity embeds CEntityIdentity at offset 0, so the weapon
entity carries
    + 0x14   m_nameStringTableIndex   int32
    + 0x18   m_name                   CUtlSymbolLarge
    + 0x20   m_designerName           CUtlSymbolLarge
and engine2.dll exports Source2EngineToClientStringTable001 = 0x620050, the
table that index refers to. That is the SOLVED path, but the bucket layout of
CNetworkStringTable is not in the dump, so it is not walked here yet. What this
probe does instead is read those fields raw and report them, plus scan for any
plain ASCII name - which is what would show if this build stores one inline.

Run:  python tools/cs2_weapon_probe.py
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
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.restype = wt.BOOL
k32.Module32FirstW.restype = wt.BOOL
k32.Module32NextW.restype = wt.BOOL

ENTITY_LIST = o.ENTITY_LIST   # was 0x2715828; cs2_header_offsets.py
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
PAGE_OFFSET = o.PAGE_OFFSET   # was 0x10; cs2_header_offsets.py
SLOT_STRIDE = o.SLOT_STRIDE   # was 0x70; cs2_header_offsets.py
HANDLE_MASK = o.HANDLE_MASK   # was 0x1FF; cs2_header_offsets.py
CTL_COUNT = 64
OFF_HANDLE = 0x92C
OFF_NAME = 0x6FC
OFF_HEALTH = 0x34C
OFF_VIEW_OFFSET = 0xF60

OFF_WEAPON_SERVICES = 0x12F0
OFF_ACTIVE_WEAPON = 0x60
OFF_OWNER_AMMO = 0x68
OFF_CLIP1 = 0x1928
OFF_CLIP2 = 0x192C
OFF_RESERVE_AMMO = 0x1930

# CEntityIdentity is embedded at offset 0 of every entity.
OFF_NAME_TABLE_INDEX = 0x14
OFF_NAME_SYMBOL = 0x18
OFF_DESIGNER_NAME = 0x20

PRINTABLE = set(range(0x20, 0x7F))


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
        return struct.unpack("<i", r)[0] if r else None

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
        print(f"no entity page (dwEntityList=0x{el:X}) - start a match")
        k32.CloseHandle(h); return 1

    print(f"pid={pid} client.dll 0x{base:X}  page 0x{page:X}")
    print(f"local pawn 0x{local_pawn:X}\n")

    print(f"{'name':<22}{'wpnSvc':>10}{'handle':>10}{'slot':>5}{'weapon':>18}"
          f"{'clip1':>7}{'clip2':>7}{'res0':>6}{'res1':>6}")
    print("-" * 105)

    rows = []
    for i in range(CTL_COUNT):
        ctl = rq(page + SLOT_STRIDE * i)
        if not can(ctl):
            continue
        nm = inline_name(ctl + OFF_NAME)
        if not nm:
            continue
        hd = ri(ctl + OFF_HANDLE)
        pawn = rq(page + SLOT_STRIDE * (hd & HANDLE_MASK)) if hd else 0
        if not can(pawn):
            continue
        hp = ri(pawn + OFF_HEALTH)
        if not (hp is not None and 0 <= hp <= 100):
            continue

        ws = rq(pawn + OFF_WEAPON_SERVICES)
        wsh = ri(ws + OFF_ACTIVE_WEAPON) if can(ws) else None
        slot = (wsh & HANDLE_MASK) if wsh else -1
        wpn = rq(page + SLOT_STRIDE * slot) if can(slot) and slot >= 0 else 0

        clip1 = clip2 = res0 = res1 = None
        if can(wpn):
            clip1 = ri(wpn + OFF_CLIP1)
            clip2 = ri(wpn + OFF_CLIP2)
            rpa = rq(wpn + OFF_RESERVE_AMMO)
            if can(rpa):
                res0 = ri(rpa)
                res1 = ri(rpa + 4)
        rows.append((nm, pawn, wpn, clip1, clip2, res0, res1))
        print(f"{nm:<22}{f'0x{ws:X}' if can(ws) else '-':>10}"
              f"{f'0x{wsh:X}' if wsh else '-':>10}{slot:>5}"
              f"{f'0x{wpn:X}' if can(wpn) else '-':>18}"
              f"{clip1 if clip1 is not None else '-':>7}"
              f"{clip2 if clip2 is not None else '-':>7}"
              f"{res0 if res0 is not None else '-':>6}"
              f"{res1 if res1 is not None else '-':>6}")

    print()
    good = [r for r in rows if r[2] and r[3] is not None and r[3] >= 0
            and r[3] < 200]
    print(f"players with a sane clip1: {len(good)}/{len(rows)}")

    # The discriminator: a wrong offset reads a stable nonsense number, the
    # right one changes when the player fires.
    if good:
        nm, pawn, wpn, clip1, clip2, res0, res1 = good[0]
        print(f"\nwatching {nm}'s clip1 for 25s - FIRE to confirm it moves.")
        print(f"  weapon 0x{wpn:X}  clip1={clip1} clip2={clip2} "
              f"reserve={res0}/{res1}")
        seen = []
        try:
            import time
            for _ in range(50):
                time.sleep(0.5)
                c = ri(wpn + OFF_CLIP1)
                if c is not None and (not seen or seen[-1] != c):
                    seen.append(c)
                    if len(seen) <= 12:
                        print(f"  clip1 -> {c}")
        except KeyboardInterrupt:
            pass
        print(f"\n  distinct clip1 values seen: {seen}")
        if len(set(seen)) > 1:
            print("  PASS clip1 MOVES -> 0x1928 is the real magazine field")
        else:
            print("  INCONCLUSIVE: clip1 never moved. Fire a few rounds in the")
            print("  game and re-run to confirm.")

    # Where is the name? Report the raw identity fields, then dump the weapon
    # entity looking for a plain ASCII name.
    live = [r for r in rows if r[2]]
    if live:
        nm, pawn, wpn = live[0][0], live[0][1], live[0][2]
        print(f"\nidentity fields on {nm}'s weapon entity 0x{wpn:X}:")
        idx = ri(wpn + OFF_NAME_TABLE_INDEX)
        nm_sym = rq(wpn + OFF_NAME_SYMBOL)
        dz_sym = rq(wpn + OFF_DESIGNER_NAME)
        print(f"  +0x14 m_nameStringTableIndex = {idx}")
        print(f"  +0x18 m_name         (CUtlSymbolLarge) = 0x{nm_sym:X}")
        print(f"  +0x20 m_designerName (CUtlSymbolLarge) = 0x{dz_sym:X}")
        if can(nm_sym):
            raw = rd(nm_sym, 32)
            if raw:
                txt = raw.split(b"\x00")[0]
                try:
                    print("       m_name as char*: %r" % txt.decode("ascii"))
                except UnicodeDecodeError:
                    print("       m_name as char*: not ASCII (interned handle)")
        print("  engine2.dll Source2EngineToClientStringTable001 = 0x620050")
        print("  -> resolve m_nameStringTableIndex through that table for the name")

        print(f"\nstring scan of the weapon entity (first 4 KiB):")
        raw = rd(wpn, 0x1000)
        if raw:
            i = 0
            found = 0
            while i < len(raw) and found < 20:
                if raw[i] in PRINTABLE:
                    j = i
                    while j < len(raw) and raw[j] in PRINTABLE:
                        j += 1
                    if j - i >= 4:
                        try:
                            s = raw[i:j].decode("ascii")
                            print(f"  +0x{i:04X}  {s!r}")
                            found += 1
                        except UnicodeDecodeError:
                            pass
                    i = j
                else:
                    i += 1
            if found == 0:
                print("  no printable run of 4+ chars - the name is genuinely")
                print("  interned, so the string table above is the only route.")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())