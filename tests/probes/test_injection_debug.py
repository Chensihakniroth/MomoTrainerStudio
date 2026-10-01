import os, sys, time, ctypes, struct, shutil
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# Set ctypes
for func, restype, argtypes in [
    ('LoadLibraryA', ctypes.c_void_p, [ctypes.c_char_p]),
    ('GetModuleHandleA', ctypes.c_void_p, [ctypes.c_char_p]),
    ('GetProcAddress', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p]),
    ('CreateRemoteThread', ctypes.c_void_p, None),
    ('OpenProcess', ctypes.c_void_p, None),
    ('VirtualAllocEx', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]),
    ('WriteProcessMemory', ctypes.c_bool, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
    ('WaitForSingleObject', ctypes.c_ulong, [ctypes.c_void_p, ctypes.c_ulong]),
    ('GetExitCodeThread', ctypes.c_bool, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong)]),
    ('CloseHandle', ctypes.c_bool, [ctypes.c_void_p]),
    ('GetLastError', ctypes.c_ulong, []),
]:
    fn = getattr(k32, func)
    if restype: fn.restype = restype
    if argtypes: fn.argtypes = argtypes

# Find Roblox
import psutil
pid = None
for proc in psutil.process_iter(['pid', 'name']):
    try:
        if proc.info['name'] and 'roblox' in proc.info['name'].lower():
            pid = proc.info['pid']
            break
    except:
        pass

if not pid:
    raise SystemExit('Roblox not running')

h = k32.OpenProcess(0x1F0FFF, False, pid)

# Test 1: Load a system DLL that's already loaded (should succeed)
kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
print(f'Local kernel32: 0x{kernel32:X}')

# Write path to remote
test_dll = b'C:\\Windows\\System32\\kernel32.dll'
name_addr = k32.VirtualAllocEx(h, None, len(test_dll) + 1,
    ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), test_dll,
    ctypes.c_size_t(len(test_dll) + 1), ctypes.byref(ctypes.c_size_t(0)))

load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

# Test with system DLL
thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

print(f'System DLL thread: handle={h_thread}, tid={thread_id.value}')
k32.WaitForSingleObject(h_thread, 10000)
exit_code = ctypes.c_ulonglong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'System DLL LoadLibraryA: 0x{exit_code.value:X}')
k32.CloseHandle(h_thread)

# Test 2: Try LoadLibraryExA with DONT_RESOLVE_DLL_REFERENCES
load_library_ex_a = k32.GetProcAddress(kernel32, b'LoadLibraryExA')
if load_library_ex_a:
    name_addr2 = k32.VirtualAllocEx(h, None, len(test_dll) + 1,
        ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
    k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr2), test_dll,
        ctypes.c_size_t(len(test_dll) + 1), ctypes.byref(ctypes.c_size_t(0)))
    
    # LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES=0x00000001)
    param = ctypes.c_void_p(name_addr2)
    h_thread2 = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_ex_a),
        param, 0, ctypes.byref(thread_id))
    print(f'LoadLibraryExA thread: handle={h_thread2}')
    k32.WaitForSingleObject(h_thread2, 10000)
    exit_code2 = ctypes.c_ulonglong(0)
    k32.GetExitCodeThread(h_thread2, ctypes.byref(exit_code2))
    print(f'LoadLibraryExA: 0x{exit_code2.value:X}')
    k32.CloseHandle(h_thread2)

# Test 3: Try our DLL with full path
print('\n--- Testing our DLL ---')
roblox_dir = None
for proc in psutil.process_iter(['pid', 'exe']):
    try:
        if proc.info['pid'] == pid:
            roblox_dir = os.path.dirname(proc.info['exe'])
            break
    except:
        pass

if roblox_dir:
    our_dll = os.path.join(roblox_dir, 'RobloxExecutorCRT.dll').encode('ascii')
    name_addr3 = k32.VirtualAllocEx(h, None, len(our_dll) + 1,
        ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
    k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr3), our_dll,
        ctypes.c_size_t(len(our_dll) + 1), ctypes.byref(ctypes.c_size_t(0)))
    
    h_thread3 = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
        ctypes.c_void_p(name_addr3), 0, ctypes.byref(thread_id))
    print(f'Our DLL thread: handle={h_thread3}, tid={thread_id.value}')
    k32.WaitForSingleObject(h_thread3, 10000)
    exit_code3 = ctypes.c_ulonglong(0)
    k32.GetExitCodeThread(h_thread3, ctypes.byref(exit_code3))
    print(f'Our DLL LoadLibraryA: 0x{exit_code3.value:X}')
    k32.CloseHandle(h_thread3)
    
    # Check error
    if exit_code3.value == 0:
        print(f'LoadLibraryA failed in target! Error would be in target process context')
    elif exit_code3.value == 0xC000071C:
        print('STATUS_INVALID_IMAGE_HASH - anti-cheat blocking!')

k32.CloseHandle(h)
print('\nDone.')
