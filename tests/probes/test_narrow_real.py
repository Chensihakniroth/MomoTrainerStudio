#!/usr/bin/env python3
"""
Test narrow() with a real process (DummyGame.exe)
Uses a simple pointer chain for testing.
"""
import ctypes
import ctypes.wintypes as w
import struct
import os
import sys
import time
import memory_scanner as ms

def main():
    # Open the current process (DummyGame)
    h = ctypes.windll.kernel32.OpenProcess(0x001F, False, os.getpid())
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        sys.exit(1)

    def rb(addr, n):
        buf = (ctypes.c_uint8 * n)()
        g = ctypes.c_size_t(0)
        if not ctypes.windll.kernel32.ReadProcessMemory(h, addr, buf, n, ctypes.byref(g)) or g.value != n:
            return None
        return bytes(buf)

    def wb(addr, data):
        buf = (ctypes.c_uint8 * len(data))(*data)
        g = ctypes.c_size_t(0)
        return ctypes.windll.kernel32.WriteProcessMemory(h, addr, buf, len(data), ctypes.byref(g))

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04

    # Allocate 3 chunks
    base1 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base2 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    base3 = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

    print(f"Allocated: 0x{base1:X}, 0x{base2:X}, 0x{base3:X}")

    ptr1_addr = base1 + 0x100
    ptr2_addr = base2 + 0x200
    target_addr = base3 + 0x300

    # Create chain: base1[0x100] -> base2, base2[0x200] -> target, target[0x300] = 0xDEADBEEF
    wb(ptr1_addr, struct.pack('<Q', base2))
    wb(ptr2_addr, struct.pack('<Q', target_addr))
    wb(target_addr + 0x300, struct.pack('<I', 0xDEADBEEF))

    print(f"Chain: 0x{base1:X}+0x100 -> 0x{base2:X} -> 0x{base2:X}+0x200 -> 0x{target_addr:X} -> 0x{target_addr:X}+0x300 = 0xDEADBEEF")

    # Scan for pointers to base2 (which contains 0xDEADBEEF)
    print("\n=== Scanning for pointers to base2 (0x{base2:X}) ===")
    ctrl = ms.PointerScanController(h, max_depth=1, max_offset=0x10000)
    results = ctrl.scan([base2], depth=0)
    count = results.count()
    print(f"Found {count} pointers to base2")

    if count > 0:
        print("First 3 results:")
        for i, (addr, blob) in enumerate(results.all_hits()[:3]):
            print(f"  [{i}] 0x{addr:X} -> {blob.hex()}")

        # Test narrow - simulate base2 moving to base2'
        print("\n=== Simulating heap change (base2 moves) ===")
        base2_new = ctypes.windll.kernel32.VirtualAlloc(None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        print(f"Old base2: 0x{base2:X}, New base2: 0x{base2_new:X}")

        # Narrow to chains that still point to base2_new
        narrowed = ctrl.narrow([base2_new])
        narrowed_count = narrowed.count()
        print(f"After narrow to 0x{base2_new:X}: {narrowed_count} results")

        # Now narrow to chains pointing to base2 (the original target)
        narrowed2 = ctrl.narrow([base2])
        narrowed2_count = narrowed2.count()
        print(f"After narrow to original 0x{base2:X}: {narrowed2_count} results")

    ctrl.close()
    ctypes.windll.kernel32.CloseHandle(h)
    print("\nTest complete!")

if __name__ == '__main__':
    main()