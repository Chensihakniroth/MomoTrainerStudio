import win32pipe, win32file, os

pid = os.getpid()
name = fr'\\.\pipe\uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh_{pid}'
print(f'Creating: {name}')

try:
    handle = win32pipe.CreateNamedPipe(
        name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        255, 4096, 4096, 0, None
    )
    print(f'SUCCESS: handle={handle}')
    
    # Try to open it
    h2 = win32file.CreateFile(
        name,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None,
        win32file.OPEN_EXISTING,
        0, None
    )
    print('Can open pipe!')
    win32file.CloseHandle(h2)
    win32file.CloseHandle(handle)
except Exception as e:
    print(f'Error: {e}')
