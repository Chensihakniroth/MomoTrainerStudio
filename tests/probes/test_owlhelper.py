import os, sys, time, ctypes, struct, shutil
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# CRITICAL: Set ALL ctypes argtypes/restype for 64-bit addresses
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
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
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
k32.GetExitCodeThread.restype = ctypes.c_bool
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.CloseHandle.restype = ctypes.c_bool
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]

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

print(f'Roblox PID: {pid}, exe: {exe_path}')

# Get Roblox working directory
roblox_dir = os.path.dirname(exe_path)
print(f'Roblox dir: {roblox_dir}')

# Copy DLLs to Roblox directory so LoadLibrary can find them
loader_src = r'D:\game\MomoTrainerStudio\downloads\Loader.dll'
executor_src = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
loader_dst = os.path.join(roblox_dir, 'Loader.dll')
executor_dst = os.path.join(roblox_dir, 'RobloxExecutorCRT.dll')

shutil.copy2(loader_src, loader_dst)
shutil.copy2(executor_src, executor_dst)
print(f'Copied DLLs to {roblox_dir}')

# Inject using simple CreateRemoteThread + LoadLibraryA
h = k32.OpenProcess(0x1F0FFF, False, pid)
if not h:
    raise SystemExit(f'OpenProcess failed: {k32.GetLastError()}')

# Write loader DLL path to remote process memory
loader_path = loader_dst.encode('ascii')
name_addr = k32.VirtualAllocEx(h, None, len(loader_path) + 1,
    ctypes.c_ulong(0x00001000 | 0x00002000),  # MEM_COMMIT | MEM_RESERVE
    ctypes.c_ulong(0x04))  # PAGE_READWRITE

if not name_addr:
    raise SystemExit(f'VirtualAllocEx failed: {k32.GetLastError()}')

written = ctypes.c_size_t(0)
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), loader_path, ctypes.c_size_t(len(loader_path) + 1), ctypes.byref(written))

# Get LoadLibraryA address
kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
if not kernel32:
    raise SystemExit(f'GetModuleHandleA(kernel32) failed')
load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')
if not load_library_a:
    raise SystemExit(f'GetProcAddress(LoadLibraryA) failed')
print(f'LoadLibraryA: 0x{load_library_a:X}')

# Create remote thread
thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

if not h_thread:
    raise SystemExit(f'CreateRemoteThread failed: {k32.GetLastError()}')

print(f'Thread created: handle={h_thread}, tid={thread_id.value}')

# Wait for thread to complete
result = k32.WaitForSingleObject(h_thread, 10000)
print(f'WaitForSingleObject: {result}')

# Get return value (module handle of loaded DLL)
exit_code = ctypes.c_ulong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'LoadLibraryA returned: 0x{exit_code.value:X} (non-zero = success)')
k32.CloseHandle(h_thread)

# Wait for pipe to be created
print('\nWaiting 5 seconds for pipe...')
time.sleep(5)

# Check for pipe
pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(pid)
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
invalid = ctypes.c_void_p(-1).value

if h_pipe and h_pipe != invalid:
    print('\n[PIPE EXISTS!]')
    k32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    k32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    k32.WriteFile(h_pipe, b'ping', 4, ctypes.byref(ctypes.c_ulong(0)), None)
    buf = ctypes.create_string_buffer(512)
    read = ctypes.c_ulong(0)
    k32.ReadFile(h_pipe, buf, 512, ctypes.byref(read), None)
    print(f'Read {read.value} bytes: {buf.value[:read.value]}')
    k32.CloseHandle(h_pipe)
    print('\n[SUCCESS] Full pipeline working!')
else:
    print(f'\n[Pipe NOT found] (error={k32.GetLastError()})')

# Check debug log
debug_path = r'C:\Temp\momo_debug.txt'
if os.path.exists(debug_path):
    with open(debug_path, 'r') as f:
        print(f'\n[DLL Debug Log]\n{f.read()}')
else:
    print('\n[No debug log]')

k32.CloseHandle(h)
print('\n=== Done ===')
