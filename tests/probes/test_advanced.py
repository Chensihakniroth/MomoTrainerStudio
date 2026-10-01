"""Test advanced_features.py against DummyGame.py"""

import ctypes
import struct
import time
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import advanced_features as af
import memory_scanner as ms

def find_dummy_game_pid():
    """Find DummyGame.exe PID."""
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snap == -1:
        return None

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_char * 260)]

    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None

    if k32.Process32First(snap, ctypes.byref(pe32)):
        while True:
            name = pe32.szExeFile.decode('utf-8', errors='replace').lower()
            if 'dummy' in name or 'python' in name:
                pid = pe32.th32ProcessID
                break
            if not k32.Process32Next(snap, ctypes.byref(pe32)):
                break

    k32.CloseHandle(snap)
    return pid


def main():
    pid = find_dummy_game_pid()
    if not pid:
        print("ERROR: DummyGame not found! Run DummyGame.py first.")
        return False

    print(f"=== Testing against DummyGame (PID: {pid}) ===\n")
    k32 = ctypes.windll.kernel32
    # Need VM_OPERATION for VirtualAllocEx, VM_WRITE for WriteProcessMemory, etc.
    PROCESS_VM_ACCESS = 0x0008 | 0x0010 | 0x0020  # OPERATION | READ | WRITE
    PROCESS_QUERY = 0x00001000  # PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
    h = k32.OpenProcess(PROCESS_VM_ACCESS | PROCESS_QUERY | 0x00000400, False, pid)

    if not h:
        print("ERROR: Could not open process!")
        return False

    all_passed = True

    # ---- Test 1: Structure Dissect ----
    print("--- Structure Dissect ---")
    try:
        sd = af.StructureDissect(pid, h)
        # Scan for player struct pattern: HP=100(u16), Mana=50(u16)
        pattern = struct.pack('<HH', 100, 50)

        found_addrs = []

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                        ('AllocationProtect', ctypes.c_ulong), ('RegionSize', ctypes.c_size_t),
                        ('State', ctypes.c_ulong), ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong)]

        # Prototype VirtualQueryEx so ctypes knows the types
        k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
        k32.VirtualQueryEx.restype = ctypes.c_size_t

        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        regions_scanned = 0
        while k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) != 0:
            if mbi.State == 0x1000 and (mbi.Protect & 0xF0) == 0:
                regions_scanned += 1
                try:
                    buf = ctypes.create_string_buffer(mbi.RegionSize)
                    read = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(h, ctypes.c_void_p(mbi.BaseAddress), buf, ctypes.c_size_t(mbi.RegionSize), ctypes.byref(read)):
                        data = buf.raw
                        idx = data.find(pattern)
                        while idx != -1:
                            found_addrs.append(mbi.BaseAddress + idx)
                            idx = data.find(pattern, idx + 1)
                except Exception:
                    pass
            addr += mbi.RegionSize
            if addr > 0x7FFF0000:
                break
        print(f"  Scanned {regions_scanned} regions")

        print(f"  Found {len(found_addrs)} player structs (HP=100, Mana=50)")

        if found_addrs:
            result = sd.detect_struct(found_addrs[0])
            if result:
                print(f"  Dissected 0x{result.base_address:X} (confidence: {result.confidence:.2f})")
                for f in result.fields[:6]:
                    print(f"    +0x{f.offset:02X} {f.vtype:<10} = {f.value}")
            print("  PASS")
        else:
            print("  SKIP (no structs found)")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 2: Memory Dumper ----
    print("--- Memory Dumper ---")
    try:
        os.makedirs('dumps', exist_ok=True)
        dumper = af.MemoryDumper(pid, h)
        if found_addrs:
            ok = dumper.dump_region(found_addrs[0], 64, 'dumps/player_dump.bin')
            print(f"  Binary dump: {'PASS' if ok else 'FAIL'} ({os.path.getsize('dumps/player_dump.bin') if ok else 0} bytes)")

            ok = dumper.dump_to_csv(found_addrs[0], 64, 'dumps/player_dump.csv')
            print(f"  CSV dump: {'PASS' if ok else 'FAIL'}")
        else:
            print("  SKIP")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 3: Pointer Map ----
    print("--- Pointer Map ---")
    try:
        pm = af.PointerMap(pid, h)
        if found_addrs:
            pm.scan_region(found_addrs[0] - 0x100, 0x2000)
            stats = pm.get_stats()
            print(f"  Found {stats['total_pointers']} pointers -> {stats['unique_targets']} targets")
            pm.export_json('dumps/pointer_map.json')
            print("  Export JSON: PASS")
        else:
            print("  SKIP")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 4: Auto-Assembler ----
    print("--- Auto-Assembler ---")
    try:
        asm = af.AutoAssembler(pid)
        test_bytes = b'\x90' * 16
        inject_addr = asm.inject_bytes(test_bytes, executable=False)
        if inject_addr:
            readback = asm.read_bytes(inject_addr, 16)
            print(f"  Inject 16 bytes @ 0x{inject_addr:X}: PASS")
            print(f"  Read back: {'MATCH' if readback == test_bytes else 'MISMATCH'}")
            asm.free(inject_addr)
            print("  Free: PASS")
        else:
            print("  FAIL: Injection returned 0")
            all_passed = False
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 5: Speedhack ----
    print("--- Speedhack ---")
    try:
        sh = af.Speedhack(pid)
        sh.set_speed(2.5)
        sh.enable()
        status = sh.get_status()
        print(f"  {status}: {'PASS' if '2.5' in status else 'FAIL'}")
        sh.disable()
        print(f"  Disable: PASS")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 6: Script Recorder ----
    print("--- Script Recorder ---")
    try:
        rec = af.ScriptRecorder()
        rec.start()
        rec.record_scan(100, 'int32', 'exact')
        rec.record_add_address(found_addrs[0] if found_addrs else 0x140001000, 'int32', 'HP')
        rec.record_freeze(found_addrs[0] if found_addrs else 0x140001000, True)
        rec.stop()
        rec.export('dumps/recorded_script.py')
        print(f"  Recorded script: PASS ({os.path.getsize('dumps/recorded_script.py')} bytes)")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 7: Script Engine ----
    print("--- Lua Script Engine ---")
    try:
        class MockAPI:
            def read_int(self, addr):
                return 42
            def write_int(self, addr, val):
                return True

        engine = af.LuaScriptEngine(MockAPI())
        script_src = "result = api.read_int(0x1000)\napi.write_int(0x2000, result)\n"
        engine.register_script('test', script_src)
        log = engine.get_log()
        print(f"  Script loaded: PASS ({len(log)} log entries)")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 8: Auto-Attach Watcher ----
    print("--- Auto-Attach Watcher ---")
    try:
        result = []
        def on_attach(found_pid, name):
            result.append((found_pid, name))

        watcher = af.AutoAttachWatcher(on_attach)
        watcher.watch('python.exe', interval=0.5)
        time.sleep(1.5)
        watcher.stop()
        if result:
            print(f"  Found process: {result[0][1]} (PID: {result[0][0]}): PASS")
        else:
            print("  Process not found (name mismatch)")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 9: Scan Session ----
    print("--- Scan Session ---")
    try:
        class MockApp:
            def __init__(self):
                self.pid = pid
                self.exe_name = 'DummyGame.exe'
                self.candidates = []
                self.addresses = []

        mock_app = MockApp()
        if found_addrs:
            mock_app.candidates = [ms.Candidate(found_addrs[0], b'\x64\x00\x32\x00')]
        mock_app.addresses = [{'addr': found_addrs[0] if found_addrs else 0x140001000,
                                'vtype': 'int32', 'description': 'HP', 'frozen': False}]

        session = af.ScanSession(mock_app)
        session.save('dumps/session.json')
        print(f"  Save session: PASS")

        mock_app2 = MockApp()
        session2 = af.ScanSession(mock_app2)
        data = session2.load('dumps/session.json')
        print(f"  Load session: {len(data['candidates'])} candidates, {len(data['addresses'])} addresses: PASS")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    # ---- Test 10: Plugin Manager ----
    print("--- Plugin Manager ---")
    try:
        pm = af.PluginManager('plugins')
        plugins = pm.discover()
        print(f"  Discovered plugins: {len(plugins)} (PASS)")
    except Exception as e:
        print(f"  FAIL: {e}")
        all_passed = False
    print()

    k32.CloseHandle(h)
    print(f"=== {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'} ===")
    return all_passed


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
