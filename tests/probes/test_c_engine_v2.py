"""Smoke test for scan_engine v2: verify all scan types work."""
import ctypes, struct, time
import memory_scanner as ms
import scan_engine as se

k32 = ctypes.windll.kernel32
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
mypid = k32.GetCurrentProcessId()
h = k32.OpenProcess(0x1F0FFF, False, mypid)
pages = list(ms.list_pages(h))

print('=== C engine v2 smoke test ===')
print(f'available: {se.is_available()}')

tests = [
    ('uint32 fast', 'uint32', 12345, True,  4),
    ('uint8 fast',  'uint8',  50,    True,  4),
    ('uint8 full',  'uint8',  50,    False, 4),
    ('uint16 fast', 'uint16', 1000,  True,  4),
    ('uint16 full', 'uint16', 1000,  False, 4),
    ('uint32 full', 'uint32', 12345, False, 4),
    ('uint64 fast', 'uint64', 0x123456789ABCDEF0, True, 4),
    ('float fast',  'float',  99.5,  True,  4),
    ('float full',  'float',  99.5,  False, 4),
    ('double fast', 'double', 1.5,   True, 4),
]

for label, vtype, value, fast, nt in tests:
    t0 = time.time()
    hits = se.c_engine_scan(h, vtype, value, pages, nt, fast)
    t = time.time() - t0
    print(f'  {label:18s} {len(hits):6d} hits in {t:.3f}s')

# Controlled correctness test: write 12345 to a known address
import numpy as np
arr = np.zeros(1024, dtype='<u4')
arr[17] = 12345
addr = arr.ctypes.data
verify = (ctypes.c_uint8 * 4)()
rb = ctypes.c_size_t(0)
k32.ReadProcessMemory(h, ctypes.c_void_p(addr + 17*4), verify, 4, ctypes.byref(rb))
val = struct.unpack('<I', bytes(verify))[0]
print(f'\nControlled uint32: arr[17]=12345, read={val}, match={val==12345}')
c_hits = se.c_engine_scan(h, 'uint32', 12345, [(addr, 4096, 0x04)], 1, True)
print(f'C found: {c_hits}')
expected = addr + 17*4
print(f'Expected addr: 0x{expected:X}')
print(f'Match: {len(c_hits) >= 1 and c_hits[0][0] == expected}')

k32.CloseHandle(h)
print('\n=== DONE ===')
