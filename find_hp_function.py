"""
find_hp_function.py — identify the function at 0x00515945 (HP write)
and 0x004223CD (HP read) in JX2Royal.exe.
"""
import ctypes, ctypes.wintypes as w, struct, os, subprocess

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

OpenProcess = k32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = w.BOOL

CloseHandle = k32.CloseHandle

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def rblock(h, addr, n):
    buf = (ctypes.c_uint8 * n)()
    got = ctypes.c_size_t(0)
    if not ReadProcessMemory(h, addr, buf, n, ctypes.byref(got)):
        return None
    return bytes(buf)


def r32(h, addr):
    b = rblock(h, addr, 4)
    return None if b is None else struct.unpack('<I', b)[0]


def find_pid():
    r = subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         "Get-Process JX2Royal -ErrorAction SilentlyContinue | "
         "Where-Object { $_.MainWindowTitle -ne 'JX2 Royal Launcher' } | "
         "Select-Object -ExpandProperty Id"],
        capture_output=True, text=True)
    for line in r.stdout.strip().splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return None


def find_module_for_addr(h, target_addr, pid):
    """Return (base, name, size) for module containing target_addr."""
    # PowerShell module enumeration
    ps = f'''
$h = ([System.Diagnostics.Process]::GetProcessById({pid})).Handle
$mods = New-Object IntPtr[] 4096
$need = 0
[psapi]::EnumProcessModulesEx($h, $mods, 4096*8, [ref]$need, 3) | Out-Null
$count = [int]($need / 8)
for ($i=0; $i -lt $count; $i++) {{
  $mi = New-Object PSAPI+MODULEINFO
  [psapi]::GetModuleInformation($h, $mods[$i], [ref]$mi, [System.Runtime.InteropServices.Marshal]::SizeOf([type]'PSAPI+MODULEINFO')) | Out-Null
  $n = New-Object System.Text.StringBuilder 256
  [psapi]::GetModuleBaseNameW($h, $mods[$i], $n, 256) | Out-Null
  $lo = $mi.lpBaseOfDll.ToInt64()
  $hi = $lo + $mi.SizeOfImage
  if ({target_addr} -ge $lo -and {target_addr} -lt $hi) {{
    Write-Host ("BASE=0x{{0:X}} SIZE=0x{{1:X}} NAME={{2}}" -f $lo, $mi.SizeOfImage, $n.ToString())
    break
  }}
}}
'''
    r = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if 'BASE=' in line:
            # Parse: BASE=0x... SIZE=0x... NAME=...
            parts = line.strip().split()
            base = int(parts[0].split('=')[1], 16)
            size = int(parts[1].split('=')[1], 16)
            name = parts[2].split('=', 1)[1] if '=' in parts[2] else parts[2]
            return base, size, name
    return None


def find_function_bounds(h, module_base, code_addr):
    """
    Find the function that contains code_addr by walking backwards
    looking for common function prologues: push ebp; mov ebp, esp (0x55 0x8B 0xEC).
    Or CC/INT3 padding / ret boundaries.
    """
    # Search up to 0x2000 bytes back for a function prologue
    SEARCH_BACK = 0x2000
    page_start = module_base
    # Read in chunks
    page = rblock(h, code_addr - SEARCH_BACK, SEARCH_BACK)
    if page is None:
        return None
    rel = code_addr - (code_addr - SEARCH_BACK)
    # Common x86 prologues:
    #   55 8B EC           push ebp; mov ebp, esp
    #   55 8B EC 83 ...    push ebp; mov ebp, esp; sub esp, N
    #   55 57              push ebp; push edi
    #   8B FF              mov edi, edi (MSVC hot-patch)
    #   53                 push ebx
    #   56                 push esi
    #   83 EC              sub esp, N (one-byte prefix varies)
    #   90                 nop padding
    #   CC                 int3 padding
    for off in range(rel - 1, max(0, rel - 0x800), -1):
        if off + 2 < len(page):
            # 55 8B EC = push ebp; mov ebp, esp — strong signal
            if page[off] == 0x55 and page[off+1] == 0x8B and page[off+2] == 0xEC:
                func_start = code_addr - SEARCH_BACK + off
                return func_start
        if off + 1 < len(page):
            # CC CC ... = int3 padding boundary
            if page[off] == 0xCC:
                # walk past CCs and check if next is a prologue
                continue
    # Fallback: no prologue found, return code_addr itself
    return code_addr


def disassemble_near(h, addr, before=32, after=32):
    """Return hex bytes around addr for manual disassembly."""
    b = rblock(h, addr - before, before + after)
    if b is None:
        return None
    return b[:before].hex(' '), b[before:before+after].hex(' '), b


def scan_calls_to(h, func_start, func_end, target_addr):
    """
    Scan from func_start to func_end looking for CALL target_addr.
    Returns the relative call positions.
    """
    page = rblock(h, func_start, func_end - func_start)
    if page is None:
        return []
    hits = []
    for off in range(len(page) - 5):
        if page[off] == 0xE8:  # CALL rel32
            rel = struct.unpack('<i', page[off+1:off+5])[0]
            dest = func_start + off + 5 + rel
            if dest == target_addr:
                hits.append(func_start + off)
    return hits


def main():
    pid = find_pid()
    if not pid:
        print("JX2Royal not running")
        return
    print(f"PID: {pid}")

    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return

    HP_WRITE_ADDR = 0x00515945
    HP_READ_ADDR  = 0x004223CD

    for label, addr in [('HP_WRITE', HP_WRITE_ADDR), ('HP_READ', HP_READ_ADDR)]:
        print(f"\n{'='*60}\n{label} = {addr:#x}\n{'='*60}")
        info = find_module_for_addr(h, addr, pid)
        if not info:
            print("  Module not found")
            continue
        base, size, name = info
        offset = addr - base
        print(f"  Module: {name}, base={base:#x}, size={size:#x}, offset={offset:#x}")

        # Bytes around the address
        before_hex, after_hex, raw = disassemble_near(h, addr)
        print(f"  Bytes at: {after_hex[:24]}")
        print(f"  Before  : {before_hex[-24:]}")

        # Find function bounds
        func_start = find_function_bounds(h, base, addr)
        if func_start:
            func_size = addr - func_start
            print(f"  Probable function start: {func_start:#x} (current addr - start = {func_size} bytes back)")

            # Read function bytes — first 32 bytes (prologue)
            prologue = rblock(h, func_start, 32)
            if prologue:
                print(f"  Prologue: {prologue.hex(' ')}")

            # If we have a clear function, scan for calls to the other function
            other = HP_READ_ADDR if label == 'HP_WRITE' else HP_WRITE_ADDR
            calls = scan_calls_to(h, func_start, addr, other)
            if calls:
                print(f"  -> calls to {other:#x} from within: {[hex(c) for c in calls]}")
            else:
                print(f"  -> no direct calls to {other:#x} from prologue region")

    CloseHandle(h)


if __name__ == '__main__':
    main()
