"""
check_jx2.py — Verify the JX2 process is accessible and read HP.
"""
import psutil, ctypes, ctypes.wintypes as w, sys

def main():
    proc = next((p for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == 'JX2Royal.exe'), None)
    if not proc:
        print("JX2Royal.exe not found!")
        return
    pid = proc.info['pid']
    print(f"JX2Royal PID: {pid}")

    h = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
    if not h:
        print(f"OpenProcess failed: {ctypes.get_last_error()}")
        return
    print("Opened JX2 process successfully")

    hp_addr = 0x07B4C320
    buf = (ctypes.c_uint8 * 8)()
    g = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(h, hp_addr, buf, 8, ctypes.byref(g))
    if ok and g.value == 8:
        hp_val = int.from_bytes(bytes(buf), 'little')
        print(f"HP @ 0x{hp_addr:x} = 0x{hp_val:x} ({hp_val})")
    else:
        print(f"ReadProcessMemory failed: {ctypes.get_last_error()}")

    # Read the instruction at 0x515945 (HP write)
    instr_buf = (ctypes.c_uint8 * 8)()
    g2 = ctypes.c_size_t(0)
    ok2 = ctypes.windll.kernel32.ReadProcessMemory(h, 0x00515945, instr_buf, 8, ctypes.byref(g2))
    if ok2 and g2.value == 8:
        bytes_hex = ' '.join(f'{b:02x}' for b in bytes(instr_buf))
        print(f"Instr @ 0x00515945: {bytes_hex}")
    else:
        print(f"Can't read 0x00515945: {ctypes.get_last_error()}")

    # Read the instruction at 0x004223CD (HP read)
    instr_buf2 = (ctypes.c_uint8 * 8)()
    g3 = ctypes.c_size_t(0)
    ok3 = ctypes.windll.kernel32.ReadProcessMemory(h, 0x004223CD, instr_buf2, 8, ctypes.byref(g3))
    if ok3 and g3.value == 8:
        bytes_hex2 = ' '.join(f'{b:02x}' for b in bytes(instr_buf2))
        print(f"Instr @ 0x004223CD: {bytes_hex2}")
    else:
        print(f"Can't read 0x004223CD: {ctypes.get_last_error()}")

    print("\nDone")

if __name__ == '__main__':
    main()
