import win32pipe, win32file

# Try to connect to an existing pipe (lsass)
name = r'\\.\pipe\lsass'
print(f'Trying to open: {name}')

try:
    handle = win32file.CreateFile(
        name,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None,
        win32file.OPEN_EXISTING,
        0, None
    )
    print(f'SUCCESS: handle={handle}')
    win32file.CloseHandle(handle)
except Exception as e:
    print(f'Error: {e}')

# Try to create a pipe with a very simple name
print('\nTrying to create pipe...')
for name in [r'\\.\pipe\test1', r'\\.\pipe\mytest', r'\\.\pipe\abc']:
    try:
        handle = win32pipe.CreateNamedPipe(
            name,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 64, 64, 0, None
        )
        print(f'{name}: SUCCESS handle={handle}')
        win32file.CloseHandle(handle)
        break
    except Exception as e:
        print(f'{name}: {e}')
