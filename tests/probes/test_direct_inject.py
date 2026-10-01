import os, sys, time, ctypes, struct, shutil
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# CRITICAL: Set ALL ctypes argtypes/restype for 64-bit addresses
for func, restype, argtypes in [
    ('LoadLibraryA', ctypes.c_void_p, [ctypes.c_char_p]),
    ('LoadLibraryW', ctypes.c_void_p, [ctypes.c_wchar_p]),
    ('GetModuleHandleA', ctypes.c_void_p, [ctypes.c_char_p]),
    ('GetProcAddress', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p]),
    ('CreateRemoteThread', ctypes.c_void_p, None),
    ('OpenProcess', ctypes.c_void_p, None),
    ('VirtualAllocEx', ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]),
    ('WriteProcessMemory', ctypes.c_bool, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]),
    ('WaitForSingleObject', ctypes.c_ulong, [ctypes.c_void_p, ctypes.c_ulong]),
    ('GetExitCodeThread', ctypes.c_bool, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong)]),
    ('CloseHandle', ctypes.c_bool, [ctypes.c_void_p]),
    ('VirtualFreeEx', ctypes.c_bool, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]),
]:
    fn = getattr(k32, func)
    if restype: fn.restype = restype
    if argtypes: fn.argtypes = argtypes

# Find Roblox
import psutil
pid = None
exe_path = None
for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        info = proc.info
        if info['name'] and 'roblox' in info['name'].lower() and 'player' in info['name'].lower():
            pid = info['pid']
            exe_path = info['exe']
            break
    except:
        pass

if not pid:
    raise SystemExit('Roblox not running')

print(f'Roblox PID: {pid}')

# Copy executor DLL to Roblox directory
roblox_dir = os.path.dirname(exe_path)
executor_src = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
executor_dst = os.path.join(roblox_dir, 'RobloxExecutorCRT.dll')
shutil.copy2(executor_src, executor_dst)

h = k32.OpenProcess(0x1F0FFF, False, pid)

# Method 1: Direct LoadLibraryA injection of the executor DLL
executor_path = executor_dst.encode('ascii')
name_addr = k32.VirtualAllocEx(h, None, len(executor_path) + 1,
    ctypes.c_ulong(0x00001000 | 0x00002000), ctypes.c_ulong(0x04))
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), executor_path,
    ctypes.c_size_t(len(executor_path) + 1), ctypes.byref(ctypes.c_size_t(0)))

kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

print(f'Thread: handle={h_thread}, tid={thread_id.value}')
k32.WaitForSingleObject(h_thread, 10000)

exit_code = ctypes.c_ulonglong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'LoadLibraryA returned: 0x{exit_code.value:X}')
k32.CloseHandle(h_thread)

# Wait for pipe
print('\nWaiting 5 seconds...')
time.sleep(5)

# Check pipe
pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(pid)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
invalid = ctypes.c_void_p(-1).value

if h_pipe and h_pipe != invalid:
    print('[PIPE EXISTS!]')
    k32.CloseHandle(h_pipe)
else:
    print(f'Pipe NOT found (error={k32.GetLastError()})')

# Check debug log
debug_path = r'C:\Temp\momo_debug.txt'
if os.path.exists(debug_path):
    with open(debug_path, 'r') as f:
        print(f'\n[Debug Log]\n{f.read()}')
else:
    print('\n[No debug log]')

k32.CloseHandle(h)
print('\nDone.')
