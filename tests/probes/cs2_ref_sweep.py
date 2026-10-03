"""Find every place in CS2 that references the local pawn, by sweeping memory.

A BFS through canonical pointers explodes (89 -> 5186 nodes after two levels)
because a 4 KB page yields ~100 pointers, and the interesting array is never
reached before the cap. Sweeping instead is bounded and decisive: search every
committed readable region for the pawn's 8-byte value, then classify each hit by
its surroundings.

A hit whose neighbours are also pointers to objects with a plausible entity
layout IS the entity list. A lone hit is just some back-reference.
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
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.Process32FirstW.restype = wt.BOOL
k32.Process32NextW.restype = wt.BOOL
k32.Module32FirstW.restype = wt.BOOL
k32.Module32NextW.restype = wt.BOOL

GAME_ENTITY_SYSTEM = 0x2715828
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_PENTITY = 0x10

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
PROT_READ = 0x02


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),          # Win10+ field; omitting shifts everything
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


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

    pawn = rq(base + LOCAL_PAWN)
    entsys = rq(base + GAME_ENTITY_SYSTEM)
    print(f"pid={pid}  client.dll 0x{base:X}")
    print(f"local pawn   0x{pawn:X}")
    print(f"entitySystem 0x{entsys:X}")
    if not pawn:
        print("no local pawn right now (dead / not spawned) - run during a round")
        return 1
    print(f"MBI size {ctypes.sizeof(MBI)} (expect 48)")

    target = struct.pack("<Q", pawn)
    hits = []
    regions = scanned = skipped = 0
    addr = 0x10000
    LIMIT = 1 << 47
    mbi = MBI()
    gaps = 0
    while addr < LIMIT:
        n = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                               ctypes.sizeof(MBI))
        if n == 0:
            # Do NOT break. An unmapped hole returns 0, and breaking there
            # truncated the walk at 0.23 GiB of a 4 GB process - which is why the
            # first sweep reported "0 references to the local pawn" and sent us
            # looking in entirely the wrong place. Step over the hole instead.
            gaps += 1
            addr += 0x10000
            continue
        base_addr = mbi.BaseAddress or addr
        size = int(mbi.RegionSize)
        prot = int(mbi.Protect)
        # Readable = not NOACCESS and not GUARD. This used to be
        # `prot & 0x02`, i.e. the PAGE_READONLY bit, which skipped every
        # PAGE_READWRITE region - so the sweep covered 0.23 GiB of a 4 GB
        # process and its "0 references" result was meaningless.
        readable = (mbi.State == MEM_COMMIT
                    and not (prot & PAGE_NOACCESS)
                    and not (prot & PAGE_GUARD))
        if readable:
            regions += 1
            off = 0
            STEP = 1 << 20
            while off < size:
                want = min(STEP, size - off)
                blob = rd(base_addr + off, want)
                if blob is not None:
                    scanned += want
                    pos = 0
                    while True:
                        i = blob.find(target, pos)
                        if i < 0:
                            break
                        hit = base_addr + off + i
                        hits.append(hit)
                        pos = i + 8
                else:
                    skipped += 1
                off += want
        nxt = base_addr + size
        if nxt <= addr:
            break
        addr = nxt

    print(f"\nreadable regions: {regions}   (holes stepped over: {gaps})")
    print(f"bytes scanned  : {scanned/2**30:.2f} GiB  (unreadable chunks: {skipped})")
    print(f"references to the local pawn: {len(hits)}")

    print("\n=== each reference, with context ===")
    for hit in hits:
        # index within a hypothetical pointer array
        idx = (hit - 0) // 8
        print(f"\n  0x{hit:016X}")
        lo = max(0, (hit - 64))
        row = []
        for d in range(-4, 5):
            v = rq(hit + d * 8)
            mark = "*" if d == 0 else " "
            row.append(f"{mark}0x{v:X}")
        print("     slots: " + "  ".join(row))
        # is the slot itself a CEntityInstance whose m_pEntity is the pawn?
        inst = rq(hit)
        ent = rq(hit + OFF_PENTITY) if inst else 0
        print(f"     value 0x{inst:X}  -> m_pEntity(+0x10) = 0x{ent:X}"
              f"  {'== PAWN' if ent == pawn else ''}")
        if inst and canonicalish(inst):
            hp = ri(inst + OFF_HEALTH)
            ep = rq(inst + OFF_PENTITY)
            print(f"     at value+0x34C (m_iHealth) = {hp}"
                  f"   value+0x10 = 0x{ep:X}")

    k32.CloseHandle(h)
    return 0


def canonicalish(v):
    return 0x10000 < v < (1 << 47)


if __name__ == "__main__":
    raise SystemExit(main())