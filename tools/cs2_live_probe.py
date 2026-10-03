"""Live-read every CS2 offset individually and report which ones fail.

The overlay's CS2 bridge reports only a failed-read COUNT, which cannot tell you
whether the view matrix, the player name, or the pawn chain is at fault. This
probes each one in isolation against the live process and prints the actual
bytes/error, so a failure is attributable.

Usage:  python tools/cs2_live_probe.py
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
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.GetCurrentProcess.restype = wt.HANDLE

# from the generated header
VIEW_MATRIX = o.VIEW_MATRIX   # was 0x2566910; cs2_header_offsets.py
LOCAL_CONTROLLER = o.LOCAL_CONTROLLER   # was 0x2538008; cs2_header_offsets.py
LOCAL_PAWN = o.LOCAL_PAWN   # was 0x2560698; cs2_header_offsets.py
VIEW_ANGLES = o.VIEW_ANGLES   # was 0x25767E8; cs2_header_offsets.py
GLOBAL_VARS = o.GLOBAL_VARS   # was 0x222BE98; cs2_header_offsets.py
GAME_ENTITY_SYSTEM = 0x2715828

OFF_HEALTH = 0x34C
OFF_TEAM = 0x3E7
OFF_SCENE_NODE = 0x330
OFF_ABS_ORIGIN = 0xC8
OFF_NAME = 0x6FC
OFF_IS_LOCAL = 0x790
OFF_ARMOR = 0x1ECC


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


def enable_debug():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.restype = wt.BOOL
    advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD,
                                        ctypes.POINTER(wt.HANDLE)]
    advapi.LookupPrivilegeValueW.restype = wt.BOOL
    advapi.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR,
                                             ctypes.POINTER(LUID)]
    advapi.AdjustTokenPrivileges.restype = wt.BOOL
    advapi.AdjustTokenPrivileges.argtypes = [wt.HANDLE,
                                             ctypes.POINTER(LUID_AND_ATTRIBUTES),
                                             wt.LPBOOL]

    k32.GetCurrentProcess.restype = wt.HANDLE
    tok = wt.HANDLE()
    if not advapi.OpenProcessToken(k32.GetCurrentProcess(), 0x28,
                                   ctypes.byref(tok)):
        return False
    luid = LUID()
    if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                        ctypes.byref(luid)):
        return False
    la = LUID_AND_ATTRIBUTES(luid, 0x2)          # SE_PRIVILEGE_ENABLED
    ok = advapi.AdjustTokenPrivileges(tok, ctypes.byref(la), None)
    ctypes.set_last_error(0)
    return bool(ok)


def find_pid(name="cs2.exe"):
    TH32CS_SNAPPROCESS = 0x2
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Process32FirstW.restype = wt.BOOL
    k32.Process32NextW.restype = wt.BOOL

    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD), ("szExeFile", wt.WCHAR * 260)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PE32()
    pe.dwSize = ctypes.sizeof(PE32)
    if k32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                pid = 0
                break
    else:
        pid = 0
    k32.CloseHandle(snap)
    return pid


def module_base(pid, module="client.dll"):
    TH32CS_SNAPMODULE = 0x8
    TH32CS_SNAPMODULE32 = 0x10
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Module32FirstW.restype = wt.BOOL
    k32.Module32NextW.restype = wt.BOOL

    class ME32(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                    ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                    ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
                    ("modBaseSize", wt.DWORD), ("hModule", wt.HANDLE),
                    ("szModule", wt.WCHAR * 256), ("szExePath", wt.WCHAR * 260)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1 or snap == 0xFFFFFFFFFFFFFFFF:
        return 0, 0
    me = ME32()
    me.dwSize = ctypes.sizeof(ME32)
    base = size = 0
    if k32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.lower() == module.lower():
                base, size = me.modBaseAddr or 0, me.modBaseSize
                break
            if not k32.Module32NextW(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


def main():
    print("SeDebugPrivilege:", "enabled" if enable_debug() else "NOT enabled")
    pid = find_pid()
    if not pid:
        print("cs2.exe is not running")
        return 2
    h = k32.OpenProcess(0x0010 | 0x0400 | 0x1000 | 0x0001, False, pid)  # VM_READ|VM_OP|VM_QUERY|QUERY_INFO
    if not h:
        print(f"OpenProcess failed, error {ctypes.get_last_error()} - run as Administrator")
        return 2
    base, size = module_base(pid)
    if not base:
        print("client.dll not mapped yet")
        k32.CloseHandle(h)
        return 2
    print(f"pid={pid}  client.dll base=0x{base:X} size={size:,} ({size//1024} KB)")

    def rd(addr, n, label):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
        mbi = MBI()
        k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                           ctypes.sizeof(MBI))
        prot = mbi.Protect
        state = mbi.State
        desc = f"protect=0x{prot:X} state=0x{state:X}" if mbi.RegionSize else "UNMAPPED"
        if not ok or got.value != n:
            err = ctypes.get_last_error()
            print(f"  [FAIL] {label:<34} 0x{addr:X}  err={err}  {desc}")
            return None
        return buf.raw

    def rd_ptr(addr, label):
        raw = rd(addr, 8, label)
        if raw is None:
            return 0
        val = struct.unpack("<Q", raw)[0]
        print(f"  [ ok ] {label:<34} -> 0x{val:X}")
        return val

    print("\n-- globals in client.dll --")
    matrix_ptr = rd_ptr(base + VIEW_MATRIX, "dwViewMatrix")
    controller = rd_ptr(base + LOCAL_CONTROLLER, "dwLocalPlayerController")
    pawn = rd_ptr(base + LOCAL_PAWN, "dwLocalPlayerPawn")
    angles_ptr = rd_ptr(base + VIEW_ANGLES, "dwViewAngles")
    gvars = rd_ptr(base + GLOBAL_VARS, "dwGlobalVars")
    entsys = rd_ptr(base + GAME_ENTITY_SYSTEM, "dwGameEntitySystem")

    print("\n-- view matrix payload (64 bytes @ dwViewMatrix) --")
    if matrix_ptr:
        m = rd(matrix_ptr, 64, "viewMatrix payload")
        if m:
            f = struct.unpack("<16f", m)
            for r in range(4):
                print("   " + "  ".join(f"{f[r*4+c]:12.5f}" for c in range(4)))
            finite = all(abs(v) < 1e6 for v in f) and all(v == v for v in f)
            print(f"   all finite / sane: {finite}")

    print("\n-- local controller fields --")
    if controller:
        raw = rd(controller + OFF_IS_LOCAL, 1, "m_bIsLocalPlayerController")
        if raw:
            print(f"   m_bIsLocalPlayerController = {raw[0]}")
        raw = rd(controller + OFF_NAME, 32, "m_iszPlayerName (32B chunk)")
        if raw:
            txt = raw.split(b"\x00")[0].decode("utf-8", "replace")
            print(f"   m_iszPlayerName            = {txt!r}  (raw {raw.hex()})")
        raw = rd(controller + OFF_NAME + 32, 32, "m_iszPlayerName (+32)")
        if raw:
            print(f"   m_iszPlayerName +32        = {raw.hex()}")

    print("\n-- local pawn fields --")
    if pawn:
        raw = rd(pawn + OFF_HEALTH, 4, "m_iHealth")
        if raw:
            print(f"   m_iHealth = {struct.unpack('<i', raw)[0]}")
        raw = rd(pawn + OFF_TEAM, 1, "m_iTeamNum")
        if raw:
            print(f"   m_iTeamNum = {raw[0]}")
        raw = rd(pawn + OFF_ARMOR, 4, "m_ArmorValue")
        if raw:
            print(f"   m_ArmorValue = {struct.unpack('<i', raw)[0]}")
        node = rd_ptr(pawn + OFF_SCENE_NODE, "m_pGameSceneNode")
        if node:
            raw = rd(node + OFF_ABS_ORIGIN, 12, "m_vecAbsOrigin")
            if raw:
                v = struct.unpack("<3f", raw)
                print(f"   m_vecAbsOrigin = {v[0]:.1f}, {v[1]:.1f}, {v[2]:.1f}")

    print("\n-- view angles payload --")
    if angles_ptr:
        raw = rd(angles_ptr, 12, "viewAngles payload")
        if raw:
            v = struct.unpack("<3f", raw)
            print(f"   pitch/yaw/roll = {v[0]:.2f}, {v[1]:.2f}, {v[2]:.2f}")

    k32.CloseHandle(h)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())