"""
test_target.py - Simple test target for MomoTrainer Studio's Stealth Debugger
Run this, then attach MomoTrainer Studio to it.

It allocates a value (starting at 1000) and increments it every second.
The address is printed so you can scan for it or add it directly.
"""
import ctypes
import ctypes.wintypes as w
import os
import time
import sys

os.environ.setdefault('PYTHONIOENCODING', 'utf-8')

def main():
    print("=" * 60)
    print("  [TARGET] Stealth Debugger Test Target")
    print("=" * 60)
    print(f"  PID: {os.getpid()}")
    print()

    # Allocate a 4-byte int on the heap via ctypes so we get a stable address
    value = ctypes.c_int32(1000)
    addr = ctypes.addressof(value)

    print(f"  Address: 0x{addr:X}")
    print(f"  Initial Value: {value.value}")
    print()
    print("  How to test:")
    print("  1. Open MomoTrainer Studio")
    print(f"  2. Attach to this process (PID {os.getpid()})")
    print(f"  3. Scan for value 1000 (int32)")
    print(f"     Or add address 0x{addr:X} to the cheat table manually")
    print("  4. Right-click -> Find out what accesses this address")
    print("     Or right-click -> Find out what writes to this address")
    print("  5. Watch the stealth debugger catch the reads/writes!")
    print()
    print("  Press Ctrl+C to exit")
    print("=" * 60)

    tick = 0
    try:
        while True:
            # READ the value (triggers access detection)
            current = value.value

            # WRITE a new value (triggers write detection)
            value.value = 1000 + tick

            if tick % 5 == 0:
                print(f"  [tick {tick:>4}]  addr=0x{addr:X}  value={value.value}")

            tick += 1
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n  Target stopped. Bye!")

if __name__ == '__main__':
    main()
