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

if not pid:
    print('Roblox not running')
    exit(1)

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
h = k32.OpenProcess(0x1F0FFF, False, pid)

dll_path = r'D:\game\MomoTrainerStudio\downloads\PipeTestCRTFree.dll'
injector = ManualMapper(pid, h)
ok = injector.map(dll_path)
print(f'Map: {"OK" if ok else "FAIL"}')
k32.CloseHandle(h)

time.sleep(3)

for name in ['DllMainRanEvent', 'ThreadCreatedEvent']:
    try:
        hEvent = win32event.OpenEvent(win32event.EVENT_ALL_ACCESS, False, name)
        state = win32event.WaitForSingleObject(hEvent, 0)
        status = 'SIGNALED' if state == win32event.WAIT_OBJECT_0 else 'NOT_SIGNALED'
        print(f'{name}: {status}')
        win32event.CloseHandle(hEvent)
    except:
        print(f'{name}: NOT_FOUND')
