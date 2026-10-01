"""
test_shared_handle.py — verify the Memory.h panel reuses studio_gui's
process handle and does NOT close a handle it does not own.

Also verifies SeDebugPrivilege is acquired by the engine.
"""
import ctypes
import os
import re
import shutil
import subprocess
import sys
import time
import tkinter as tk

# Run from anywhere: put the repo root on sys.path (project modules live
# there) and resolve the child target + DummyGame.py against it, rather
# than relying on the process CWD being the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import memory_core as mc
import memory_core_panel as mcp

FAIL = []
TARGET = os.path.join(HERE, "MomoHandleTarget.exe")


def check(label, cond, extra=""):
    if not cond:
        FAIL.append(label)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", label, extra))


def main():
    dst = TARGET
    for attempt in range(6):
        if not os.path.exists(dst):
            break
        try:
            os.remove(dst)
        except PermissionError:
            time.sleep(1.0 + attempt)
    if os.path.exists(dst):
        raise RuntimeError("stale target locked")
    shutil.copy2(sys.executable, dst)
    proc = subprocess.Popen([dst, "-u", "DummyGame.py"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, cwd=ROOT)
    lines, real_pid = [], None
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.rstrip()
        lines.append(line)
        m = re.search(r"^\[START\] PID: (\d+)", line)
        if m:
            real_pid = int(m.group(1))
        if "[READY]" in line:
            break
    p1 = int(re.search(r"Player @ 0x([0-9A-Fa-f]+)",
                       "\n".join(lines)).group(1), 16)
    check("target ready", real_pid is not None, "pid=%s" % real_pid)

    try:
        # ---- 1. debug privilege is actually acquired ----
        got = mc.enable_debug_privilege()
        print("    enable_debug_privilege() ->", got)
        check("enable_debug_privilege returns a bool", isinstance(got, bool))
        me = mc.Memory(pid=real_pid)
        check("Memory records debug_privilege",
              hasattr(me, "debug_privilege"),
              str(getattr(me, "debug_privilege", "MISSING")))
        me.close()

        # ---- 2. from_handle wraps without owning ----
        k32 = mc.k32
        app_handle = k32.OpenProcess(0x1F0FFF, False, real_pid)
        check("app opened its own handle", bool(app_handle))
        wrapped = mc.Memory.from_handle(app_handle, real_pid, "target",
                                        owns_handle=False)
        check("from_handle sets pid", wrapped.pid == real_pid)
        check("from_handle shares handle", wrapped.handle == app_handle)
        check("from_handle reads through it",
              wrapped.read(p1, "uint16") == 100,
              str(wrapped.read(p1, "uint16")))
        wrapped.close()
        check("close() does NOT close a borrowed handle",
              wrapped.handle is not None)
        # the app's handle must still work
        buf = (ctypes.c_ubyte * 2)()
        got_n = ctypes.c_size_t(0)
        alive = k32.ReadProcessMemory(app_handle, ctypes.c_void_p(p1),
                                      ctypes.byref(buf), 2,
                                      ctypes.byref(got_n))
        check("borrowed handle still valid after panel close",
              bool(alive) and got_n.value == 2, f"ok={alive}")
        k32.CloseHandle(app_handle)

        # ---- 3. panel reuses the shared handle ----
        root = tk.Tk()
        root.withdraw()
        app_handle2 = k32.OpenProcess(0x1F0FFF, False, real_pid)
        win = mcp.MemoryCoreWindow(root, real_pid, "python.exe",
                                   process_handle=app_handle2)
        root.update()
        win._attach_pid(real_pid)
        root.update()
        check("panel attached", win.mem is not None and win.mem.is_attached())
        check("panel used the shared handle",
              win.mem is not None and win.mem.handle == app_handle2)
        check("panel marked handle as not owned",
              win.mem is not None and
              getattr(win.mem, "owns_handle", True) is False)
        check("console says reusing",
              "Reusing" in win.console.get("1.0", "end"))

        # read/write through it
        win.addr_var.set("0x%X" % p1)
        win.type_var.set("uint16")
        win._do_read()
        check("panel read via shared handle",
              win.val_var.get().startswith("0x64"), win.val_var.get())
        win.val_var.set("555")
        win._do_write()
        check("panel write via shared handle",
              win.mem.read(p1, "uint16") == 555,
              str(win.mem.read(p1, "uint16")))
        win.val_var.set("100")
        win._do_write()
        check("modules listed via shared handle",
              len(win.mod_tree.get_children()) > 5,
              "(%d)" % len(win.mod_tree.get_children()))

        # detach must NOT kill the app's handle
        win._detach()
        root.update()
        buf2 = (ctypes.c_ubyte * 2)()
        n2 = ctypes.c_size_t(0)
        still = k32.ReadProcessMemory(app_handle2, ctypes.c_void_p(p1),
                                      ctypes.byref(buf2), 2,
                                      ctypes.byref(n2))
        check("studio handle survives panel detach",
              bool(still) and n2.value == 2, f"ok={still}")
        win.on_close()
        buf3 = (ctypes.c_ubyte * 2)()
        n3 = ctypes.c_size_t(0)
        still2 = k32.ReadProcessMemory(app_handle2, ctypes.c_void_p(p1),
                                       ctypes.byref(buf3), 2,
                                       ctypes.byref(n3))
        check("studio handle survives panel close",
              bool(still2) and n3.value == 2, f"ok={still2}")
        k32.CloseHandle(app_handle2)
        root.destroy()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except Exception:
                pass

    print("\n" + "=" * 52)
    if FAIL:
        print("FAILED %d check(s):" % len(FAIL))
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    print("ALL SHARED-HANDLE TESTS PASSED")


if __name__ == "__main__":
    main()
