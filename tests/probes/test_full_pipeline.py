import os, sys, time, ctypes, struct, shutil
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# Set ctypes
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.OpenProcess.restype = ctypes.c_void_p
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
k32.WaitForSingleObject.restype = ctypes.c_ulong
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong)]
k32.GetExitCodeThread.restype = ctypes.c_bool
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.CloseHandle.restype = ctypes.c_bool

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

h = k32.OpenProcess(0x1F0FFF, False, pid)

# Copy DLL with unique name
roblox_dir = os.path.dirname(exe_path)
executor_src = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
unique_name = f'RbxExec_{int(time.time())}.dll'
executor_dst = os.path.join(roblox_dir, unique_name)
shutil.copy2(executor_src, executor_dst)

# Inject
executor_path = executor_dst.encode('ascii')
name_addr = k32.VirtualAllocEx(h, None, len(executor_path) + 1,
    ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), executor_path,
    ctypes.c_size_t(len(executor_path) + 1), ctypes.byref(ctypes.c_size_t(0)))

kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

print(f'Injection thread: handle={h_thread}, tid={thread_id.value}')
k32.WaitForSingleObject(h_thread, 10000)
exit_code = ctypes.c_ulonglong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'LoadLibraryA returned: 0x{exit_code.value:X}')
k32.CloseHandle(h_thread)

# Wait for pipe
print('\nWaiting 8 seconds for pipe creation...')
time.sleep(8)

# Check pipe
pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(pid)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
invalid = ctypes.c_void_p(-1).value

if h_pipe and h_pipe != invalid:
    print('\n[PIPE EXISTS!]')
    k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    k32.WriteFile(h_pipe, b'test lua', 9, ctypes.byref(ctypes.c_ulong(0)), None)
    time.sleep(1)
    buf = ctypes.create_string_buffer(512)
    read = ctypes.c_ulong(0)
    k32.ReadFile(h_pipe, buf, 512, ctypes.byref(read), None)
    print(f'Response: {read.value} bytes')
    if read.value > 0:
        print(f'Data: {buf.value[:read.value]}')
    k32.CloseHandle(h_pipe)
    print('\n[SUCCESS!]')
else:
    print(f'\n[Pipe NOT found] (error={k32.GetLastError()})')

# Check debug log
debug_path = r'C:\Temp\momo_debug.txt'
if os.path.exists(debug_path):
    with open(debug_path, 'r') as f:
        print(f'\n[Debug Log]\n{f.read()}')
else:
    print('\n[No debug log]')

k32.CloseHandle(h)
print('\nDone.')
