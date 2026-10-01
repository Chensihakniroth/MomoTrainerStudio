import os, sys, time, ctypes, struct
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# Ensure C pointer ctypes declarations
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]

# EnumProcessModules prototype (MSVC-only); kernel32 handles 64-bit values through common prototypes
psapi = ctypes.windll.psapi
psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
psapi.EnumProcessModules.restype = ctypes.c_bool
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
psapi.GetModuleBaseNameW.restype = ctypes.c_ulong

# Find RobloxPlayerBeta system process
pid = None
import psutil
for p in psutil.process_iter(['pid', 'name']):
    try:
        if 'roblox' in p.info['name'].lower() and 'player' in p.info['name'].lower():
            pid = p.info['pid']
            break
    except:
        pass

if not pid:
    raise SystemExit('RobloxPlayerBeta not found')

h = k32.OpenProcess(0x1F0FFF, False, pid)
if not h:
    raise SystemExit('OpenProcess failed')

# List modules and DLL base for msvcrt / kernelbase / kernel32 / ntdll / user32
arr = (ctypes.c_void_p * 2048)()
cb = ctypes.c_ulong(0)
if not psapi.EnumProcessModules(h, arr, ctypes.sizeof(arr), ctypes.byref(cb)):
    raise SystemExit('EnumProcessModules failed')
count = cb.value // ctypes.sizeof(ctypes.c_void_p)
targets = ['kernel32.dll', 'kernelbase.dll', 'msvcrt.dll', 'ntdll.dll', 'user32.dll']
found = {}
for i in range(count):
    name = (ctypes.c_wchar * 260)()
    if psapi.GetModuleBaseNameW(h, ctypes.c_void_p(arr[i]), name, 260):
        n = name.value.lower()
        for target in targets:
            if n == target and target not in found:
                found[target] = arr[i]

print('=== Target process module bases ===')
for n in targets:
    print(f'{n}: 0x{found[n]:X}' if n in found else f'{n}: NOT LOADED')

# Confirm remote function addresses that DLL expects to locate in imported DLLs
k32base = found.get('kernel32.dll', 0)
kbbase = found.get('kernelbase.dll', 0)
if not k32base or not kbbase:
    raise SystemExit('Required modules not present in target')

# Required exports from these modules
required = [
    ('kernel32.dll', k32base, ['LoadLibraryA','GetModuleHandleA','GetProcAddress','FreeLibrary','CreateRemoteThread','WaitForSingleObject','CloseHandle']),
    ('kernelbase.dll', kbbase, ['CreateNamedPipeW','ConnectNamedPipe','CreateThread','GetLastError','Sleep','VirtualProtect','VirtualQuery','RtlMoveMemory','RtlZeroMemory']),
    ('ntdll.dll', found.get('ntdll.dll', 0), ['RtlMoveMemory','RtlZeroMemory','RtlNtStatusToDosError','RtlGetLastWin32Error']),
    ('user32.dll', found.get('user32.dll', 0), ['ExitProcess','MessageBoxA']),
]
missing = []
for mod, base, funcs in required:
    for fn in funcs:
        addr = k32.GetProcAddress(ctypes.c_void_p(base), fn.encode())
        if not addr:
            missing.append(f'{mod}!{fn}')

if missing:
    raise SystemExit(f'Required remote exports missing: {missing[:20]}')

# Confirm that local processes matching DLL bases use the same export values (not just names)
print('=== Verify required addresses are valid system exports in current process ===')
for mod, base, funcs in required:
    for fn in funcs:
        local_mod = k32.LoadLibraryA(mod.encode())
        local_addr = k32.GetProcAddress(ctypes.c_void_p(local_mod), fn.encode())
        remote_addr = k32.GetProcAddress(ctypes.c_void_p(base), fn.encode())
        print(f'{mod}!{fn}: local=0x{local_addr:X} remote=0x{remote_addr:X} {"OK" if local_addr or remote_addr else "UNRESOLVED"}')

# Load executor DLL and inspect DLL name/data directory with exported DLL base
from manual_mapper import PEImage
dll_path = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
pe = PEImage(open(dll_path, 'rb').read())
# Parser currently does not expose export data; use local module handle as pointer validation only
print(f'DLL={dll_path}; imports={len(pe.get_imports())}')

# Inject using map operation and validate pipe appears after DllMain exit
from manual_mapper import ManualMapper
print('Injecting...')
if not ManualMapper(pid, h).map(dll_path):
    raise SystemExit('Map operation failed')
time.sleep(5)
pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(pid)
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
if h_pipe and h_pipe != ctypes.c_void_p(-1).value:
    print('PIPE EXISTS')
    buf = ctypes.create_string_buffer(4096)
    written = ctypes.c_ulong(0)
    # Write/read confirms caller side pipe operation only (no DLL-specific logic)
    k32.WriteFile(h_pipe, b'ping', 4, ctypes.byref(written), None)
    print(f'Ping written={written.value}')
    k32.CloseHandle(h_pipe)
else:
    print(f'PIPE absent; CreateFileW error={k32.GetLastError()}')

k32.CloseHandle(h)
