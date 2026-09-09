#!/usr/bin/env python3
"""
Debug: Check the scan output format and narrow method
"""
import ctypes, ctypes.wintypes as w, struct, os
import memory_scanner as ms

h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

# Create simple pointer chain: base1[0x100] = base2, base2[0x200] = 0xDEADBEEF
ptr1_addr = base1 + 0x100
wb = lambda addr, data: ctypes.windll.kernel32.WriteProcessMemory(h, addr, (ctypes.c_uint8 * len(data))(*data), len(data), ctypes.byref(ctypes.c_size_t()))
wb(ptr1_addr, struct.pack('<Q', base2))
wb(base2 + 0x200, struct.pack('<I', 0xDEADBEEF))

print(f"base1=0x{base1:X}, ptr1_addr=0x{ptr1_addr:X}, base2=0x{base2:X}")
print(f"ptr1_addr stores: 0x{base2:X}")
print(f"base2+0x200 stores: 0x{struct.unpack('<I', wb(base2+0x200, bytes([0,0,0,0])))[0]:X}")

# Run scan for pointers to base2
ctrl = ms.PointerScanController(h, max_depth=1, max_offset=0x10000)
results = ctrl.scan([base2], depth=0)
count = results.count()
print(f"\nScan for pointers to base2 (0x{base2:X}): found {count} results")

if count > 0:
    # Show first few
    for i, (addr, blob) in enumerate(results.all_hits()):
        print(f"  Result {i}: 0x{addr:X} -> blob {blob.hex()}")
        try:
            # Try to decode blob
            step = ctypes.sizeof(ctypes.c_void_p)
            ptr_pack = '<I' if step == 4 else '<Q'
            n, = struct.unpack('<I', blob[:4])[0]
            print(f"    n_offsets={n}, blob len={len(blob)}")
            if n > 0:
                offsets = tuple(struct.unpack('<I', blob[4 + i*4:8 + i*4])[0] for i in range(n))
                print(f"    offsets={offsets}")
        except Exception as e:
            print(f"    Decode error: {e}")

ctrl.close()
ctypes.windll.kernel32.CloseHandle(h)
print("\nDone")