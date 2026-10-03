"""Find the CEntityIdentity for the local pawn, then walk the class list.

No schema output contains CEntityList/CGameEntitySystem (checked all 20 module
dumps), so the entity list cannot be indexed from the dumped offsets. But
CEntityIdentity DOES expose m_pNextByClass at 0x68 - a per-class linked list of
every identity of that class. Finding the local pawn's identity node therefore
gives a complete player enumeration without the entity system at all.

Identification is empirical, not assumed:
  * a CEntityIdentity candidate has m_name (0x18) and m_designerName (0x20) as
    canonical pointers to short printable ASCII
  * the identity -> C_BaseEntity link is DISCOVERED by requiring that some
    offset reproduces the local pawn's known address
  * the class list is only accepted if it yields several nodes, and the local
    pawn appears among them
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import re
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

LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_ARMOR = 0x1ECC

IDX_NAME = 0x18
IDX_DESIGNER = 0x20
IDX_STRIDX = 0x14
ID_PREV = 0x50
ID_NEXT = 0x58
ID_PREV_CLASS = 0x60
ID_NEXT_CLASS = 0x68


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wt.DWORD), ("Protect", wt.DWORD), ("Type", wt.DWORD)]


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


def module_base(pid, module):
    snap = k32.CreateToolhelp32Snapshot(0x18, pid)
    me = ME32(); me.dwSize = ctypes.sizeof(ME32)
    base = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == module:
                base = me.modBaseAddr or 0; break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base


def canonical(v):
    return 0x10000 < v < (1 << 47)


PRINTABLE = re.compile(rb"[\x20-\x7e]{3,40}\x00")


def main():
    pid = find_pid("cs2.exe")
    if not pid:
        print("cs2.exe not running"); return 2
    h = k32.OpenProcess(0x0010 | 0x0400, False, pid)
    base = module_base(pid, "client.dll")

    def rd(va, n):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return buf.raw

    def rq(va):
        raw = rd(va, 8)
        return struct.unpack("<Q", raw)[0] if raw else 0

    def ri(va):
        raw = rd(va, 4)
        return struct.unpack("<i", raw)[0] if raw else 0

    def mapped(va):
        m = MBI()
        if k32.VirtualQueryEx(h, ctypes.c_void_p(va), ctypes.byref(m),
                              ctypes.sizeof(MBI)) == 0:
            return False
        return m.State == 0x1000 and (int(m.Protect) & 0x02)

    pawn = rq(base + LOCAL_PAWN)
    print(f"pid={pid} client.dll 0x{base:X}")
    print(f"local pawn 0x{pawn:X}")
    if not pawn:
        print("be alive in a round"); return 1
    onode = rq(pawn + OFF_SCENE_NODE)
    oorigin = struct.unpack("<3f", rd(onode + OFF_ABS_ORIGIN, 12)) if onode else None
    print(f"local origin {oorigin}")

    mbi = MBI()
    k32.VirtualQueryEx(h, ctypes.c_void_p(pawn), ctypes.byref(mbi),
                       ctypes.sizeof(MBI))
    start, size = mbi.BaseAddress or 0, int(mbi.RegionSize)
    print(f"region 0x{start:X} .. 0x{start+size:X} ({size/2**20:.1f} MiB)")

    # String pool cache: identity name pointers resolve into it.
    strcache = {}

    def as_str(p):
        if p in strcache:
            return strcache[p]
        if not canonical(p) or not mapped(p):
            strcache[p] = None
            return None
        raw = rd(p, 48)
        if not raw:
            strcache[p] = None
            return None
        m = PRINTABLE.match(raw)
        s = m.group(0)[:-1].decode("ascii") if m else None
        strcache[p] = s
        return s

    # ---- find CEntityIdentity candidates in the region ----
    print("\n-- scanning the region for CEntityIdentity shapes --")
    STEP = 1 << 22
    cands = []
    pos = 0
    while pos < size:
        want = min(STEP, size - pos)
        blob = rd(start + pos, want)
        pos += want
        if not blob:
            continue
        for i in range(0, len(blob) - 0x70, 8):
            name = struct.unpack_from("<Q", blob, i + IDX_NAME)[0]
            des = struct.unpack_from("<Q", blob, i + IDX_DESIGNER)[0]
            if not (canonical(name) and canonical(des)):
                continue
            s1, s2 = as_str(name), as_str(des)
            if not s1 or not s2:
                continue
            if len(s1) < 3 or len(s2) < 3:
                continue
            stridx = struct.unpack_from("<i", blob, i + IDX_STRIDX)[0]
            if not (0 <= stridx < 1000000):
                continue
            nxt = struct.unpack_from("<Q", blob, i + ID_NEXT)[0]
            if nxt and not (canonical(nxt) and mapped(nxt)):
                continue
            cands.append((start + pos - want + i, s1, s2, stridx))
        if len(cands) > 4000:
            break

    print(f"   {len(cands)} identity-shaped candidates")
    if not cands:
        print("   none found")
        k32.CloseHandle(h)
        return 1
    for a, s1, s2, si in cands[:8]:
        print(f"     0x{a:X}  name={s1!r} designer={s2!r} strIdx={si}")

    # ---- discover the identity -> entity link using the known pawn ----
    print("\n-- learning identity -> C_BaseEntity (the pawn must appear) --")
    link = None
    for a, s1, s2, si in cands:
        for off in range(0, 0x60, 8):
            v = rq(a + off)
            if v == pawn:
                link = (a, off, s1, s2)
                break
        if link:
            break
    if not link:
        print("   no identity holds the pawn pointer in 0x00-0x60")
        print("   the identity may live in a different region; widen the sweep")
        k32.CloseHandle(h)
        return 1
    ident, linkoff, lname, ldes = link
    print(f"   identity 0x{ident:X} name={lname!r} designer={ldes!r}")
    print(f"   +0x{linkoff:X} == local pawn   <== LINK OFFSET")

    # ---- walk the per-class list ----
    print("\n-- walking m_pNextByClass (0x68) --")
    for rel_name, field in (("m_pNextByClass", ID_NEXT_CLASS),
                            ("m_pNext", ID_NEXT)):
        nodes, seen, cur = [], set(), ident
        while canonical(cur) and cur not in seen and len(nodes) < 500:
            seen.add(cur)
            nodes.append(cur)
            cur = rq(cur + field)
        print(f"   {rel_name}: {len(nodes)} nodes")
        if len(nodes) < 3:
            continue
        rows = []
        for nd in nodes:
            ent = rq(nd + linkoff)
            if not canonical(ent):
                continue
            hp = ri(ent + OFF_HEALTH)
            team = ri(ent + OFF_TEAM) & 0xFF
            node = rq(ent + OFF_SCENE_NODE)
            org = None
            if node and mapped(node):
                raw = rd(node + OFF_ABS_ORIGIN, 12)
                if raw:
                    org = struct.unpack("<3f", raw)
            nm = as_str(rq(nd + IDX_DESIGNER)) or "?"
            rows.append((nd, ent, hp, team, ri(ent + OFF_ARMOR), org, nm))
        print(f"     {'identity':<18} {'entity':<18} {'hp':>4} {'tm':>3} {'arm':>4}  origin")
        for nd, ent, hp, team, arm, org, nm in rows:
            tag = "  <== LOCAL" if ent == pawn else ""
            o = f"({org[0]:8.1f},{org[1]:9.1f},{org[2]:7.1f})" if org else "-"
            print(f"     0x{nd:016X} 0x{ent:016X} {hp:4d} {team:3d} {arm:4d}  {o} {nm}{tag}")
        if any(r[1] == pawn for r in rows):
            print(f"   ==> {rel_name} WORKS: {len(rows)} entities, local pawn included")
            break

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())