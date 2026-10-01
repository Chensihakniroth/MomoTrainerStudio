"""
find_callers.py — Find all CALL sites in JX2Royal.exe that target
the HP write (0x515890) and HP read (0x4223A0) functions.

A CALL instruction is E8 <rel32> (5 bytes).
Target = (CALL_addr + 5) + rel32
So:  rel32 = target - (CALL_addr + 5)
"""
import ctypes, ctypes.wintypes as w, struct, os, subprocess

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
RPM = k32.ReadProcessMemory
RPM.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
RPM.restype = w.BOOL
OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE


def rblock(h, addr, n):
    buf = (ctypes.c_uint8 * n)()
    g = ctypes.c_size_t(0)
    if not RPM(h, addr, buf, n, ctypes.byref(g)) or g.value != n:
        return None
    return bytes(buf)


def find_pid():
    r = subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         "Get-Process JX2Royal -ErrorAction SilentlyContinue | "
         "Where-Object { $_.MainWindowTitle -ne 'JX2 Royal Launcher' } | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True)
    for line in r.stdout.strip().splitlines():
        if line.strip().isdigit():
            return int(line.strip())
    return None


def find_callers(h, exe_base, exe_size, target, module_name='JX2Royal.exe'):
    """Scan exe for E8 <rel32> instructions where target == target_addr."""
    # Read whole .text section at once (or whole exe if .text lookup fails)
    # We'll just read the whole executable image — it's ~13MB, fine.
    code = rblock(h, exe_base, exe_size)
    if code is None:
        print(f"Failed to read {exe_size} bytes from {exe_base:#x}")
        return []

    callers = []
    for off in range(len(code) - 5):
        if code[off] != 0xE8:  # not CALL
            continue
        rel = struct.unpack('<i', code[off+1:off+5])[0]
        dest = exe_base + off + 5 + rel
        if dest == target:
            call_addr = exe_base + off
            # Read bytes around the call for context
            ctx = code[max(0,off-4):off+15]
            callers.append((call_addr, ctx))
    return callers


def show_context(callers, target_name, target, max_show=20):
    print(f"\n=== Callers of {target_name} = {target:#x} ===")
    print(f"Found {len(callers)} CALL sites")
    for i, (addr, ctx) in enumerate(callers[:max_show]):
        print(f"\n  [{i+1}] CALL at {addr:#x} (offset +{addr-0x400000:#x})")
        before = ctx[:4]
        call = ctx[4:9]  # 5 bytes
        after = ctx[9:15]
        print(f"      before: {before.hex(' ')}")
        print(f"      CALL   {call.hex(' ')}  (target = {target:#x})")
        print(f"      after : {after.hex(' ')}")


def main():
    pid = find_pid()
    if not pid:
        print("JX2Royal not running"); return
    print(f"PID: {pid}")

    h = OpenProcess(0x0010, False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}"); return

    # From the module list:
    EXE_BASE = 0x400000
    EXE_SIZE = 0xD0E000 - 0x400000  # 0x90E000 = 9.5 MB
    HP_WRITE = 0x515890  # function containing HP write at 0x515945
    HP_READ  = 0x4223A0  # function containing HP read at 0x4223CD

    print(f"Scanning {EXE_SIZE} bytes ({EXE_SIZE/1024/1024:.1f} MB) of JX2Royal.exe")
    print(f"  WRITE func: {HP_WRITE:#x}")
    print(f"  READ  func: {HP_READ:#x}")

    write_callers = find_callers(h, EXE_BASE, EXE_SIZE, HP_WRITE)
    read_callers  = find_callers(h, EXE_BASE, EXE_SIZE, HP_READ)

    show_context(write_callers, 'HP_WRITE_FUNC', HP_WRITE)
    show_context(read_callers,  'HP_READ_FUNC',  HP_READ)

    print(f"\n\n=== Summary ===")
    print(f"  HP_WRITE called from {len(write_callers)} sites")
    print(f"  HP_READ  called from {len(read_callers)} sites")


if __name__ == '__main__':
    main()
