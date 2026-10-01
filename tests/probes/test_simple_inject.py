import os, sys, time, ctypes, subprocess, shutil
sys.path.insert(0, '.')
import win32pipe, win32file

k32 = ctypes.windll.kernel32
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
k32.WaitForSingleObject.restype = ctypes.c_ulong

# Find Roblox
import psutil
pid = None
exe_path = None
for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        if proc.info['name'] and 'roblox' in proc.info['name'].lower() and 'player' in proc.info['name'].lower():
            pid = proc.info['pid']
            exe_path = proc.info['exe']
            break
    except:
        pass

if not pid:
    raise SystemExit('Roblox not running')

print(f'Roblox PID: {pid}')

# Copy SimpleTest.dll to Roblox directory
roblox_dir = os.path.dirname(exe_path)
simple_src = r'D:\game\MomoTrainerStudio\downloads\SimpleTest.dll'
simple_dst = os.path.join(roblox_dir, 'SimpleTest.dll')
shutil.copy2(simple_src, simple_dst)

# Inject SimpleTest.dll directly (no loader needed)
h = k32.OpenProcess(0x1F0FFF, False, pid)
simple_path = simple_dst.encode('ascii')
name_addr = k32.VirtualAllocEx(h, None, len(simple_path) + 1,
    ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), simple_path,
    ctypes.c_size_t(len(simple_path) + 1), ctypes.byref(ctypes.c_size_t(0)))

kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

print(f'Injection thread: handle={h_thread}, tid={thread_id.value}')
k32.WaitForSingleObject(h_thread, 10000)
exit_code = ctypes.c_ulong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'SimpleTest.dll LoadLibraryA: 0x{exit_code.value:X}')
k32.CloseHandle(h_thread)

# Wait for pipe
print('Waiting 3 seconds for pipe...')
time.sleep(3)

# Check pipe using win32pipe
pipe_name = fr'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{pid}'
print(f'Checking pipe: {pipe_name}')

try:
    h_pipe = win32file.CreateFile(
        pipe_name,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None,
        win32file.OPEN_EXISTING,
        0, None
    )
    print('[PIPE EXISTS!]')
    win32file.CloseHandle(h_pipe)
except Exception as e:
    print(f'Pipe error: {e}')

# Check debug log
debug_path = r'C:\Temp\simple_debug.txt'
if os.path.exists(debug_path):
    with open(debug_path, 'r') as f:
        print(f'\n[Debug Log]\n{f.read()}')
else:
    print('\n[No debug log]')

k32.CloseHandle(h)
print('\nDone.')
