import os, sys, time, ctypes
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32

# Set proper ctypes
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.FlushInstructionCache.restype = ctypes.c_bool

import psutil
roblox_pid = None
for proc in psutil.process_iter(['pid', 'name']):
    try:
        if 'roblox' in proc.info['name'].lower() and 'player' in proc.info['name'].lower():
            roblox_pid = proc.info['pid']
            break
    except:
        pass

if not roblox_pid:
    print('ERROR: Roblox not running.')
    sys.exit(1)

print(f'Roblox PID: {roblox_pid}')

h_process = k32.OpenProcess(0x1F0FFF, False, roblox_pid)
if not h_process:
    sys.exit(1)

dll_path = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
from manual_mapper import ManualMapper
injector = ManualMapper(roblox_pid, h_process)
ok = injector.map(dll_path)
print(f'Injection: {"OK" if ok else "FAILED"}')
if not ok:
    sys.exit(1)

time.sleep(5)

print('\n=== DLL Debug Log ===')
try:
    with open(r'C:\Temp\momo_debug.txt', 'r') as f:
        log = f.read()
        print(log if log else '(empty)')
except Exception as e:
    print(f'(no log: {e})')

pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(roblox_pid)
k32.CreateFileW.restype = ctypes.c_void_p
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
invalid = ctypes.c_void_p(-1).value

if h_pipe and h_pipe != invalid:
    print('\nPIPE EXISTS!')
    test = b'test lua'
    written = ctypes.c_ulong(0)
    k32.WriteFile(h_pipe, test, len(test), ctypes.byref(written), None)
    print(f'Wrote: {written.value}/{len(test)} bytes')
    time.sleep(1)
    read_buf = ctypes.create_string_buffer(512)
    bytes_read = ctypes.c_ulong(0)
    k32.ReadFile(h_pipe, read_buf, 512, ctypes.byref(bytes_read), None)
    print(f'Read: {bytes_read.value} bytes')
    if bytes_read.value > 0:
        print(f'Response: {read_buf.value[:bytes_read.value]}')
        print('\n=== PASSED ===')
    k32.CloseHandle(h_pipe)
else:
    print(f'\nPipe NOT found (error={k32.GetLastError()})')

k32.CloseHandle(h_process)
print('=== Done ===')
