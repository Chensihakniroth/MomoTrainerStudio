"""Project the live local player with the live view matrix.

Mirrors ov::WorldToScreen exactly. Prints where the feet and head land, so a
missing ESP is attributable to the matrix convention rather than guessed at.
"""
from cs2_header_offsets import offsets

o = offsets()
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys
from pathlib import Path

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

sys.path.insert(0, str(Path(r"D:\game\ExternalOverlay\src")))

VIEW_MATRIX = o.VIEW_MATRIX   # was 0x2566910; cs2_header_offsets.py
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
OFF_HEALTH = 0x34C
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
VIEW_ANGLES = o.VIEW_ANGLES   # was 0x25767E8; cs2_header_offsets.py


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
    print(f"pid={pid} client.dll 0x{base:X}")

    def rd(va, n, fmt=None):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                     ctypes.byref(got)) or got.value != n:
            return None
        return struct.unpack(fmt, buf.raw) if fmt else buf.raw

    m = rd(base + VIEW_MATRIX, 64, "<16f")
    if m is None:
        print("matrix read failed"); return 2
    M = [m[0:4], m[4:8], m[8:12], m[12:16]]     # row-major
    print("\nmatrix (row-major):")
    for r in M:
        print("   " + "  ".join(f"{v:11.5f}" for v in r))

    angles = rd(base + VIEW_ANGLES, 12, "<3f")
    print(f"\nview angles pitch/yaw/roll = {angles}")

    pawn = rd(base + LOCAL_PAWN, 8, "<Q")
    if not pawn or not pawn[0]:
        print("\ndwLocalPlayerPawn is NULL (dead / not spawned this frame)")
        return 1
    pawn = pawn[0]
    health = rd(pawn + OFF_HEALTH, 4, "<i")
    node = rd(pawn + OFF_SCENE_NODE, 8, "<Q")
    print(f"pawn 0x{pawn:X}  health {health}  node 0x{node[0]:X}" if node else "no node")
    origin = rd(node[0] + OFF_ABS_ORIGIN, 12, "<3f")
    print(f"origin = {origin}")
    feet = origin

    def transform(M, v):
        x, y, z = v
        out = []
        for r in M:
            out.append(r[0] * x + r[1] * y + r[2] * z + r[3])
        return out

    # CS2/Source uses Z-up. The generic overlay mock uses Y-up, but CS2 head
    # height must be added to Z or the projected box is rotated sideways.
    HEIGHT = 94.5
    points = [("feet", feet), ("head", (feet[0], feet[1], feet[2] + HEIGHT))]
    for label, point in points:
        c = transform(M, point)
        print(f"\n{label}: world {tuple(round(v, 1) for v in point)}")
        print(f"   clip = [{c[0]:11.4f} {c[1]:11.4f} {c[2]:11.4f} {c[3]:11.4f}]")
        if c[3] <= 1e-4:
            print("   REJECTED by the c.w <= 1e-4 near-plane test  <== why nothing draws")
            continue
        inv = 1.0 / c[3]
        nx, ny, nz = c[0] * inv, c[1] * inv, c[2] * inv
        sx = (nx * 0.5 + 0.5) * 1920.0
        sy = (1.0 - (ny * 0.5 + 0.5)) * 1080.0
        print(f"   ndc = [{nx:8.4f} {ny:8.4f} {nz:8.4f}]")
        print(f"   screen = ({sx:8.1f}, {sy:8.1f})  in 1920x1080")

    # Also try the transposed matrix, in case the game stores it column-major.
    Mt = [[M[c][r] for c in range(4)] for r in range(4)]
    print("\n-- with the matrix transposed (column-major storage?) --")
    for label, point in points:
        c = transform(Mt, point)
        if c[3] > 1e-4:
            sx = (c[0] / c[3] * 0.5 + 0.5) * 1920.0
            sy = (1.0 - (c[1] / c[3] * 0.5 + 0.5)) * 1080.0
            print(f"   {label:4s} clip w = {c[3]:11.4f}   screen = ({sx:.1f}, {sy:.1f})")
        else:
            print(f"   {label:4s} clip w = {c[3]:11.4f}  (rejected)")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())