import os, sys, time, ctypes, psutil
sys.path.insert(0, '.')
from manual_mapper import ManualMapper
import win32event

pid = None
for proc in psutil.process_iter(['pid', 'exe']):
    try:
        if proc.info['exe'] and 'roblox' in proc.info['exe'].lower():
            pid = proc.info['pid']
            break
    except:
        pass

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
h = k32.OpenProcess(0x1F0FFF, False, pid)

# Use a DLL that's known to work with manual mapping
# The key is that the entry point must be DllMain directly
dll_path = r'D:\game\MomoTrainerStudio\downloads\PipeTestCRTFree.dll'
injector = ManualMapper(pid, h)
ok = injector.map(dll_path)
print(f'Map: {"OK" if ok else "FAIL"}')
k32.CloseHandle(h)

time.sleep(3)

# Check events
for name in ['DllMainRanEvent', 'ThreadCreatedEvent']:
    try:
        hEvent = win32event.OpenEvent(win32event.EVENT_ALL_ACCESS, False, name)
        state = win32event.WaitForSingleObject(hEvent, 0)
        print(f'{name}: {"SIGNALED" if state == win32event.WAIT_OBJECT_0 else "NOT_SIGNALED"}')
        win32event.CloseHandle(hEvent)
    except:
        print(f'{name}: NOT_FOUND')

# Also check pipe
import win32file
pipe_name = fr'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{pid}'
try:
    h_pipe = win32file.CreateFile(pipe_name, 0xC0000000, 0, None, 3, 0, None)
    print('PIPE EXISTS!')
    win32file.CloseHandle(h_pipe)
except:
    print('Pipe not found')
