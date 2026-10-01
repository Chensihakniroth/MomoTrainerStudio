import os, sys, time, ctypes, struct
sys.path.insert(0, '.')
k32 = ctypes.windll.kernel32
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]

# Check C:\Temp exists
print(f'C:\\Temp exists: {os.path.exists("C:/Temp")}')
if not os.path.exists('C:/Temp'):
    os.makedirs('C:/Temp', exist_ok=True)
    print('Created C:\\Temp')

# Find Roblox
import psutil
pid = None
for proc in psutil.process_iter(['pid', 'name']):
    try:
        if proc.info['name'] and 'roblox' in proc.info['name'].lower() and 'player' in proc.info['name'].lower():
            pid = proc.info['pid']
            break
    except:
        pass

if not pid:
    raise SystemExit('Roblox not running')

print(f'Roblox PID: {pid}')

# Inject DLL
from manual_mapper import ManualMapper
h = k32.OpenProcess(0x1F0FFF, False, pid)
dll_path = r'D:\game\MomoTrainerStudio\downloads\RobloxExecutorCRT.dll'
if not ManualMapper(pid, h).map(dll_path):
    raise SystemExit('Map failed')

# Wait and check for pipe
print('Waiting 5 seconds for pipe...')
time.sleep(5)

# Check if debug file was written
debug_path = r'C:\Temp\momo_debug.txt'
if os.path.exists(debug_path):
    with open(debug_path, 'r') as f:
        print(f'Debug log:\n{f.read()}')
else:
    print('No debug log written - pipe thread never started')

# Check pipe exists
pipe_name = r'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_' + str(pid)
k32.CreateFileW.restype = ctypes.c_void_p
h_pipe = k32.CreateFileW(pipe_name, 0xC0000000, 0, None, 3, 0x40000000, None)
invalid = ctypes.c_void_p(-1).value

if h_pipe and h_pipe != invalid:
    print('PIPE EXISTS!')
    k32.WriteFile(h_pipe, b'ping', 4, ctypes.byref(ctypes.c_ulong(0)), None)
    buf = ctypes.create_string_buffer(512)
    read = ctypes.c_ulong(0)
    k32.ReadFile(h_pipe, buf, 512, ctypes.byref(read), None)
    print(f'Read {read.value} bytes: {buf.value[:read.value]}')
    k32.CloseHandle(h_pipe)
else:
    print(f'Pipe NOT found (error={k32.GetLastError()})')

# List threads in target process using CreateToolhelp32Snapshot
print('\n=== Target process threads ===')
TH32CS_SNAPTHREAD = 0x00000004
snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
if snap == -1:
    print(f'Snapshot failed: {k32.GetLastError()}')
else:
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ('dwSize', ctypes.c_ulong),
            ('cntUsage', ctypes.c_ulong),
            ('th32ThreadID', ctypes.c_ulong),
            ('th32OwnerProcessID', ctypes.c_ulong),
            ('tpBasePri', ctypes.c_long),
            ('tpDeltaPri', ctypes.c_long),
            ('dwFlags', ctypes.c_ulong),
        ]
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(THREADENTRY32)
    if k32.Thread32First(snap, ctypes.byref(te)):
        count = 0
        while True:
            if te.th32OwnerProcessID == pid:
                count += 1
                if count <= 5:
                    print(f'  Thread ID: {te.th32ThreadID}')
            if not k32.Thread32Next(snap, ctypes.byref(te)):
                break
        print(f'  Total threads: {count}')
    k32.CloseHandle(snap)

k32.CloseHandle(h)
print('\nDone.')
