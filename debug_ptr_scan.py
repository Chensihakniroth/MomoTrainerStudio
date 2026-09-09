"""Debug: test what the pointer scan actually finds"""
import ctypes, ctypes.wintypes as w, struct, os
import memory_scanner as ms

h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

target_val = 0xDEADBEEF
target_addr = base3 + 0x300
ptr2_addr = base2 + 0x200
ptr1_addr = base1 + 0x100

def wb(addr, data):
    buf = (ctypes.c_uint8 * len(data))(*data)
    g = ctypes.c_size_t(0)
    ctypes.windll.kernel32.WriteProcessMemory(h, addr, buf, len(data), ctypes.byref(g))

# Create simple 1-level chain: ptr1_addr -> target_addr
# At ptr1_addr we store the address of target_addr
wb(ptr1_addr, struct.pack('<Q', target_addr))
wb(target_addr, struct.pack('<I', target_val))

print(f"base1=0x{base1:X}, ptr1_addr=0x{ptr1_addr:X}, target_addr=0x{target_addr:X}, target_val=0x{target_val:X}")
print(f"ptr1_addr contains: 0x{target_addr:X}")
print(f"target_addr contains: 0x{target_val:X}")

# Now scan for pointers to target_addr (depth 1)
ctrl = ms.PointerScanController(h, max_depth=1, max_offset=0x1000)
print(f"\nScanning for pointers to 0x{target_addr:X}...")
results = ctrl.scan([target_addr], depth=0)
count = results.count()
print(f"Found {count} pointers")
if count > 0:
    for addr, blob in results.all_hits()[:3]:
        val = struct.unpack('<Q', blob)[0]
        print(f"  Slot 0x{addr:X} -> ptr 0x{val:X}")

# Now scan for pointers to target_val (depth 1, looking for what points to the VALUE)
ctrl2 = ms.PointerScanController(h, max_depth=1, max_offset=0x1000)
print(f"\nScanning for pointers to 0x{target_val:X} (the VALUE, not the address)...")
results2 = ctrl2.scan([target_val], depth=0)
count2 = results2.count()
print(f"Found {count2} pointers")
if count2 > 0:
    for addr, blob in results2.all_hits()[:3]:
        val = struct.unpack('<Q', blob)[0]
        print(f"  Slot 0x{addr:X} -> ptr 0x{val:X}")

ctrl.close()
ctypes.windll.kernel32.CloseHandle(h)
print("\nDebug done")
