import os, sys, time, ctypes, struct
sys.path.insert(0, '.')

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

# 1) Get actual kernel32 base in target process
import psutil
pid = None
for proc in psutil.process_iter(['pid', 'name']):
    try:
        info = proc.info
        if info['name'] and 'roblox' in info['name'].lower() and 'player' in info['name'].lower():
            pid = info['pid']
            break
    except Exception:
        continue

if not pid:
    raise SystemExit('Roblox not running')

h = k32.OpenProcess(0x1F0FFF, False, pid)

# Get module bases from target process
hmods = (ctypes.c_void_p * 2048)()
cb = ctypes.c_ulong(0)
psapi.EnumProcessModules.restype = ctypes.c_bool
psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
psapi.GetModuleBaseNameW.restype = ctypes.c_ulong
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong]
if not psapi.EnumProcessModules(h, hmods, ctypes.sizeof(hmods), ctypes.byref(cb)):
    raise SystemExit('EnumProcessModules failed')
nmods = cb.value // ctypes.sizeof(ctypes.c_void_p)
targets = ['kernel32.dll', 'msvcrt.dll', 'ntdll.dll', 'kernelbase.dll']
bases = {}
for i in range(nmods):
    name = (ctypes.c_wchar * 260)()
    if psapi.GetModuleBaseNameW(h, ctypes.c_void_p(hmods[i]), name, 260):
        low = name.value.lower()
        for t in targets:
            if low == t and t not in bases:
                bases[t] = hmods[i]

print('Target process module bases:')
for t in targets:
    print('  %s: 0x%X' % (t, bases[t]) if t in bases else '  %s: MISSING' % t)

# 2) Verify function addresses in target process kernel32
print('\nLocal function addresses from own process:')
for fn in [b'GetProcAddress', b'LoadLibraryA', b'CreateNamedPipeW', b'CloseHandle']:
    addr = k32.GetProcAddress(k32.LoadLibraryA(b'kernel32.dll'), fn)
    print('  kernel32!%s local: 0x%X' % (fn.decode(), addr))

print('\nRemote function offsets check for target kernel32:')
for fn, expected_offset in [
    (b'GetProcAddress', None),
    (b'LoadLibraryA', None),
    (b'CloseHandle', None),
    (b'FreeLibrary', None),
]:
    addr_local = k32.GetProcAddress(k32.LoadLibraryA(b'kernel32.dll'), fn)
    addr_remote = k32.GetProcAddress(ctypes.c_void_p(bases['kernel32.dll']), fn)
    if addr_local and addr_remote:
        delta = addr_remote - bases['kernel32.dll']
        print('  %s: remote=0x%X offset=0x%X' % (fn.decode(), addr_remote, delta))

# 3) Test if mapped sections actually contain a valid IAT RVA structure for our DLL
from manual_mapper import PEImage
dll = PEImage(open(r'Downloads\RobloxExecutorCRT.dll', 'rb').read())
print('\nPE Import directory: RVA=0x%X size=%d' % (dll.import_rva, dll.import_size))
imports = dll.get_imports()
print('Import count: %d' % len(imports))
for imp in imports:
    print('  %s: functions=%d' % (imp['dll'], len(imp['functions'])))
    for f in imp['functions'][:3]:
        print('    - %s' % (f.get('name') or ('#%d' % f.get('ordinal', 0))))

k32.CloseHandle(h)
print('\nDiagnostics complete.')
