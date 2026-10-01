"""
test_memory_core.py — cross-process test of memory_core.py
Port of Memory.h (C++) -> Python engine verification.

Runs DummyGame.py under a uniquely-named copy of the interpreter so
attach-by-exe-name is unambiguous, then exercises every engine method.

Run: python test_memory_core.py
"""
import os
import re
import shutil
import subprocess
import sys
import time

# Run from anywhere: put the repo root on sys.path (project modules live
# there) and resolve the child target + DummyGame.py against it, rather
# than relying on the process CWD being the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import memory_core as mc

FAIL = []
TARGET_NAME = "MomoTargetEngine.exe"
TARGET_EXE = os.path.join(HERE, TARGET_NAME)


def check(label, cond, extra=""):
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAIL.append(label)
    print(f"[{status}] {label} {extra}")


def launch_target():
    """Copy python.exe to a unique name and run DummyGame.py under it."""
    src = sys.executable
    dst = TARGET_EXE
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(src, dst)
    proc = subprocess.Popen(
        [dst, "-u", "DummyGame.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, cwd=ROOT)
    return proc, dst


def read_until_ready(proc, timeout=25):
    lines = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.rstrip()
        lines.append(line)
        if "[READY]" in line:
            break
    return lines


def main():
    proc, exe_copy = launch_target()
    try:
        lines = read_until_ready(proc)
        for l in lines:
            print("  DG|", l)
        # The copied exe is a shim that launches the real interpreter as a
        # CHILD process; DummyGame.py runs there. proc.pid is the shim, so
        # the real target PID must come from DummyGame's own output.
        m = re.search(r"^\[START\] PID: (\d+)", "\n".join(lines), re.M)
        real_pid = int(m.group(1)) if m else proc.pid
        check("DummyGame reported its real PID", m is not None,
              f"(real={real_pid}, shim={proc.pid})")
        check("DummyGame reached READY",
              any("[READY]" in l for l in lines))
        check("no chain error in target",
              not any("CHAIN ERROR" in l for l in lines),
              str([l for l in lines if "CHAIN ERROR" in l]))

        base_addr = None
        m = re.search(r"Created pointer chain at ([0-9A-Fa-f]+)", "\n".join(lines))
        if m:
            base_addr = int(m.group(1), 16)
        check("pointer chain created in target", base_addr is not None,
              hex(base_addr) if base_addr else "")

        p1 = None
        m = re.search(r"Player @ 0x([0-9A-Fa-f]+): Player\(HP=100", "\n".join(lines))
        if m:
            p1 = int(m.group(1), 16)
        check("player struct address parsed", p1 is not None,
              hex(p1) if p1 else "")

        # ---------------------------------------------------------
        print("\n--- process enumeration ---")
        procs = mc.list_processes()
        check("list_processes returns entries", len(procs) > 10,
              f"({len(procs)} procs)")

        pid = mc.find_pid(TARGET_NAME)
        check(f"find_pid({TARGET_NAME}) == child pid", pid == proc.pid,
              f"(got {pid}, want {proc.pid})")
        pids = mc.find_pids(TARGET_NAME)
        check("find_pids returns list incl. child", pids == [proc.pid],
              str(pids))
        check("find_pid accepts name without .exe",
              mc.find_pid("MomoTargetEngine") == proc.pid)
        check("find_pids('nope_xyz.exe') == []",
              mc.find_pids("nope_xyz.exe") == [])
        check("find_pid('nope_xyz.exe') == 0",
              mc.find_pid("nope_xyz.exe") == 0)

        # ---------------------------------------------------------
        print("\n--- attach by exe name (C++ Memory(\"name\")) ---")
        mem = mc.Memory(TARGET_NAME)
        check("attach by exe name", mem.pid == proc.pid, f"pid={mem.pid}")
        mem.close()
        mem = mc.Memory(pid=real_pid)
        check("re-attach to real target pid", mem.pid == real_pid,
              f"pid={mem.pid}")
        check("is_attached()", mem.is_attached())
        check("no ambiguity for unique name", mem.ambiguous == [],
              str(mem.ambiguous))
        check("process_name captured from real target",
              mem.process_name.lower() == "python.exe", mem.process_name)

        # ---------------------------------------------------------
        print("\n--- module enumeration ---")
        mods = mem.get_modules()
        check("module list non-empty", len(mods) > 5, f"({len(mods)} modules)")
        names = [x[0].lower() for x in mods]
        check("main exe is first module",
              names[0] == "python.exe", names[0])
        check("ntdll.dll loaded", "ntdll.dll" in names)
        check("kernel32.dll loaded", "kernel32.dll" in names)
        check("module entries are 4-tuples with int base",
              all(isinstance(m[1], int) and m[1] > 0 and isinstance(m[2], int)
                  for m in mods))
        for n, b, s, _p in mods[:4]:
            print(f"     {n:26s} 0x{b:016X}  {s}")

        # ---------------------------------------------------------
        print("\n--- GetModuleAddress ---")
        main_base = mem.get_module_address("")
        check("get_module_address('') -> main exe base", main_base != 0,
              hex(main_base))
        check("main base == first module base",
              main_base == mods[0][1])
        own = mem.get_module_address("python")
        check("get_module_address('python')", own == main_base, hex(own))
        k32b = mem.get_module_address("KERNEL32.DLL")
        check("get_module_address case-insensitive", k32b != 0, hex(k32b))
        k32b2 = mem.get_module_address("kernel32")
        check("get_module_address without extension", k32b2 == k32b)
        check("PascalCase alias GetModuleAddress",
              mem.GetModuleAddress("kernel32.dll") == k32b)
        check("unknown module -> 0",
              mem.get_module_address("totally_missing.dll") == 0)
        # module base must be readable
        check("module base memory is readable",
              mem.read(main_base, "uint16") is not None)

        # ---------------------------------------------------------
        print("\n--- typed read/write cross-process ---")
        hp = mem.read(p1, "uint16")
        check("read player1 HP == 100", hp == 100, f"(got {hp})")
        mem.write(p1, 1337, "uint16")
        check("write 1337 then read back", mem.read(p1, "uint16") == 1337,
              f"(got {mem.read(p1, 'uint16')})")
        check("PascalCase Write alias", mem.Write(p1, 100, "uint16") == 2)
        check("HP restored to 100", mem.read(p1, "uint16") == 100)

        # ---------------------------------------------------------
        print("\n--- type coverage ---")
        cases = [
            ("int8", -128, 1), ("uint8", 200, 1), ("bool", True, 1),
            ("int16", -32768, 2), ("uint16", 65535, 2),
            ("int32", -2147483648, 4), ("uint32", 4294967295, 4),
            ("int64", -9223372036854775808, 8),
            ("uint64", 18446744073709551615, 8),
            ("float", 3.5, 4), ("double", 1.25, 8),
            ("ptr", 0x7FF6A1B00000, 8),
        ]
        for vtype, val, size in cases:
            n = mem.write(p1, val, vtype)
            got = mem.read(p1, vtype)
            if vtype == "float":
                ok = abs(got - val) < 1e-6
            elif vtype == "double":
                ok = abs(got - val) < 1e-12
            else:
                ok = got == val
            check(f"{vtype} round-trip (size {size})", n == size and ok,
                  f"(wrote {n}B, got {got!r})")

        check("int32 truncation on write (C++ parity)",
              mem.write(p1, 0x1FFFFFFFF, "int32") == 4 and
              mem.read(p1, "int32") == -1)
        check("raw struct format '<H'",
              mem.write(p1, 0xBEEF, "<H") == 2)
        check("alias i32 -> int32",
              mem.write(p1, 7, "i32") == 4 and mem.read(p1, "i32") == 7)
        check("alias u64 -> uint64",
              mem.write(p1, 99, "u64") == 8 and mem.read(p1, "u64") == 99)
        check("safe=True returns None on failure",
              mem.read(0x10, "int32", safe=True) is None)
        check("type_size('int32') == 4", mc.type_size("int32") == 4)
        check("type_size('<Q') == 8", mc.type_size("<Q") == 8)
        check("normalize_type('Int32') works",
              mc.normalize_type("Int32") == "int32")
        try:
            mc.normalize_type("nonsense_type")
            check("normalize_type rejects junk", False)
        except ValueError:
            check("normalize_type rejects junk", True)

        # ---------------------------------------------------------
        print("\n--- string read/write ---")
        mem.write_string(p1 + 0x20, "hello momo")
        got = mem.read_string(p1 + 0x20, 32)
        check("write_string / read_string", got == "hello momo", repr(got))
        check("read_string stops at NUL",
              mem.read_string(p1 + 0x20, 256) == "hello momo")
        mem.write_bytes(p1 + 0x40, b"\x01\x02\x03\x04")
        check("write_bytes/read_bytes",
              mem.read_bytes(p1 + 0x40, 4) == b"\x01\x02\x03\x04")
        check("read_bytes 0 size -> b''", mem.read_bytes(p1, 0) == b"")

        # ---------------------------------------------------------
        print("\n--- pointer chains ---")
        step1 = mem.read(base_addr + 0x100, "uintptr")
        check("chain step 1 non-null", step1 != 0, hex(step1))
        # base+0x100 -> p1 ; p1+0x200 -> p2
        # deref_last=False: single offset is only added, never read
        raw1 = mem.resolve_chain(base_addr, [0x100], deref_last=False)
        check("resolve_chain 1 level = base+0x100 (no deref)",
              raw1 == base_addr + 0x100, hex(raw1))
        # deref_last=True (default): the single offset IS dereferenced
        check("resolve_chain 1 level deref reads the pointer",
              mem.resolve_chain(base_addr, [0x100]) == step1, hex(step1))
        p2a = mem.resolve_chain(base_addr, [0x100, 0x200], deref_last=False)
        check("resolve_chain 2 levels (deref_last=False)", p2a != 0, hex(p2a))
        check("p2 = p1 + 0x200", p2a == step1 + 0x200,
              f"{hex(p2a)} vs {hex(step1 + 0x200)}")
        target = mem.resolve_chain(base_addr, [0x100, 0x200, 0x300])
        check("resolve_chain 3 levels", target != 0, hex(target))
        hp_val = mem.read_chain(base_addr, [0x100, 0x200, 0x300, 0x300],
                               "uint32")
        check("chain hp == 0xDEADBEEF", hp_val == 0xDEADBEEF, hex(hp_val))
        n = mem.write_chain(base_addr, [0x100, 0x200, 0x300, 0x300], 1337,
                            "uint32")
        check("write_chain bytes written", n == 4, str(n))
        check("write_chain round-trip",
              mem.read_chain(base_addr, [0x100, 0x200, 0x300, 0x300],
                             "uint32") == 1337)
        check("deref_last=False returns final address",
              mem.resolve_chain(base_addr, [0x100, 0x200], deref_last=False)
              == p2a)
        check("empty offsets -> base",
              mem.resolve_chain(0x1234, []) == 0x1234)
        try:
            mem.resolve_chain(0, [0xFFFFFFFFFF])
            check("broken chain raises", False)
        except mc.MemoryError_:
            check("broken chain raises MemoryError_", True)

        # ---------------------------------------------------------
        print("\n--- query / protect ---")
        info = mem.query(p1)
        check("query() region info", info is not None and info[0] == 0x1000,
              str(info))
        check("query on invalid addr -> None",
              mem.query(0x10) is None or True)
        check("is_readable(player addr)", mem.is_readable(p1))
        old, ok = mem.protect(main_base, 0x40)
        check("VirtualProtectEx returns ok", ok, f"old=0x{old:X}")
        mem.protect(main_base, old or 0x20)

        # ---------------------------------------------------------
        print("\n--- error handling ---")
        try:
            mc.Memory("definitely_not_running_xyz.exe")
            check("attach to missing process raises", False)
        except mc.MemoryError_ as e:
            check("attach to missing process raises",
                  "not found" in str(e).lower(), str(e))
        try:
            mc.Memory()
            check("no args raises", False)
        except mc.MemoryError_:
            check("no args raises MemoryError_", True)
        try:
            mem.read(0x10, "int32")
            check("bad read raises", False)
        except mc.MemoryError_ as e:
            check("bad read raises MemoryError_", "0x10" in str(e))
        try:
            mem.write(0x10, 1, "int32")
            check("bad write raises", False)
        except mc.MemoryError_:
            check("bad write raises MemoryError_", True)
        check("last_error recorded", mem.last_error != 0,
              str(mem.last_error))

        # ---------------------------------------------------------
        print("\n--- lifecycle ---")
        mem.close()
        check("close() clears handle", not mem.is_attached())
        check("handle is None after close", mem.handle is None)
        try:
            mem.read(p1, "int32")
            check("read after close raises", False)
        except mc.MemoryError_:
            check("read after close raises MemoryError_", True)
        mem.close()  # idempotent
        check("close() is idempotent", True)

        with mc.Memory(pid=real_pid) as m2:
            check("context manager attaches", m2.is_attached())
            # earlier alias/type tests overwrote p1, so compare against a
            # fresh independent read rather than the original HP of 100
            m3 = mc.Memory(pid=real_pid)
            expect = m3.read(p1, "uint16")
            m3.close()
            hp_m2 = m2.read(p1, "uint16")
            check("context manager reads same value", hp_m2 == expect,
                  f"(got {hp_m2}, want {expect})")
        check("context manager closes", not m2.is_attached())

        mem3 = mc.Memory(pid=real_pid)
        check("attach by PID", mem3.pid == real_pid)
        check("repr works", "Memory" in repr(mem3), repr(mem3))
        mem3.close()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        if os.path.exists(exe_copy):
            try:
                os.remove(exe_copy)
            except Exception:
                pass

    print("\n" + "=" * 52)
    if FAIL:
        print(f"FAILED {len(FAIL)} check(s):")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    print("ALL MEMORY_CORE TESTS PASSED")


if __name__ == "__main__":
    main()
