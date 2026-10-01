import os, sys, time, ctypes, psutil, shutil
sys.path.insert(0, '.')

k32 = ctypes.windll.kernel32
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
k32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
k32.GetExitCodeThread.restype = ctypes.c_bool
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.CloseHandle.restype = ctypes.c_bool

# Find Roblox
pid = None
for proc in psutil.process_iter(['pid', 'exe']):
    try:
        if proc.info['exe'] and 'roblox' in proc.info['exe'].lower():
            pid = proc.info['pid']
            break
    except:
        pass

if not pid:
    raise SystemExit('Roblox not running')

print(f'Roblox PID: {pid}')

# Copy to TEMP directory (accessible to all processes)
dll_dst = os.path.join(os.environ['TEMP'], 'InjectTest.dll')
shutil.copy2(r'D:\game\MomoTrainerStudio\downloads\InjectTest.dll', dll_dst)

h = k32.OpenProcess(0x1F0FFF, False, pid)

# Inject from TEMP
dll_path = dll_dst.encode('ascii')
name_addr = k32.VirtualAllocEx(h, None, len(dll_path) + 1,
    ctypes.c_ulong(0x3000), ctypes.c_ulong(0x04))
k32.WriteProcessMemory(h, ctypes.c_void_p(name_addr), dll_path,
    ctypes.c_size_t(len(dll_path) + 1), ctypes.byref(ctypes.c_size_t(0)))

kernel32 = k32.GetModuleHandleA(b'kernel32.dll')
load_library_a = k32.GetProcAddress(kernel32, b'LoadLibraryA')

thread_id = ctypes.c_ulong(0)
h_thread = k32.CreateRemoteThread(h, None, 0, ctypes.c_void_p(load_library_a),
    ctypes.c_void_p(name_addr), 0, ctypes.byref(thread_id))

print(f'Thread: handle={h_thread}, tid={thread_id.value}')
k32.WaitForSingleObject(h_thread, 10000)

exit_code = ctypes.c_ulong(0)
k32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
print(f'Exit code: 0x{exit_code.value:X}')
k32.CloseHandle(h_thread)
k32.CloseHandle(h)

# Check if file was created
time.sleep(2)
debug_file = f'C:\\Temp\\injection_test_{pid}.txt'
if os.path.exists(debug_file):
    with open(debug_file, 'r') as f:
        print(f'\n[Debug Output]\n{f.read()}')
else:
    print(f'\n[No file created] from TEMP path')
