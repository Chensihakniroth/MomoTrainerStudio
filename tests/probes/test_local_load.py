import os, sys, time, ctypes, struct, shutil, tempfile
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]

# Load DLL locally and check if it creates a pipe
dll_path = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
handle = k32.LoadLibraryA(dll_path.encode('ascii'))
print(f'Loaded locally: 0x{handle:X}')

# Wait for pipe
time.sleep(3)

# Check pipe (using current process PID)
pid = os.getpid()
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

k32.FreeLibrary(handle)
print('\nDone.')
