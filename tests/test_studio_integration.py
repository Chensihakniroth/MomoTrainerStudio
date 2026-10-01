"""
test_studio_integration.py — verify the Memory.h engine is wired into the
real studio_gui app: menu entry present, launcher opens a live window, and
the window reuses an already-open instance.
"""
import os
import re
import shutil
import subprocess
import sys
import time
import tkinter as tk

FAIL = []
# Run from anywhere: put the repo root on sys.path (project modules live
# there) and resolve the child target + DummyGame.py against it, rather
# than relying on the process CWD being the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TARGET_NAME = "MomoIntegrationTarget.exe"
TARGET_EXE = os.path.join(HERE, TARGET_NAME)


def check(label, cond, extra=""):
    if not cond:
        FAIL.append(label)
    print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")


def main():
    import studio_gui as g

    # --- live target ---
    dst = TARGET_EXE
    for attempt in range(6):
        if not os.path.exists(dst):
            break
        try:
            os.remove(dst)
        except PermissionError:
            # previous run's target is still shutting down
            time.sleep(1.0 + attempt)
    if os.path.exists(dst):
        raise RuntimeError("stale target copy still locked: " + dst)
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
    check("target ready", real_pid is not None, f"pid={real_pid}")

    root0 = tk.Tk()
    root0.withdraw()
    app = g.StudioGUI(root0)
    app.root.withdraw()
    app.root.update()
    check("real StudioGUI constructed", True)

    # --- Tools menu contains the entry ---
    try:
        menubar = app.root.nametowidget(app.root.cget("menu"))
        tools_idx = None
        labels = []
        for i in range(menubar.index("end") + 1):
            if menubar.type(i) == "cascade":
                labels.append(menubar.entrycget(i, "label"))
                if str(menubar.entrycget(i, "label")).startswith("Tools"):
                    tools_idx = i
        check("Tools menu exists", tools_idx is not None, str(labels))
        if tools_idx is not None:
            sub = menubar.nametowidget(menubar.entrycget(tools_idx, "menu"))
            items = [sub.entrycget(i, "label")
                     for i in range(sub.index("end") + 1)
                     if sub.type(i) == "command"]
            check("Memory.h Engine menu item present",
                  any("Memory.h Engine" in str(x) for x in items),
                  str([x for x in items if "Memory" in str(x)]))
    except Exception as e:
        check("menu introspection", False, str(e))

    # --- launcher opens a real window and it attaches ---
    app.pid = real_pid
    # exe_name is only a display label here: _open_memory_core passes
    # self.pid through and the window auto-attaches by PID. Use the real
    # target name so the label matches what the modules list shows.
    app.exe_name = TARGET_NAME
    app._open_memory_core()
    # The window auto-attaches from a deferred `after(60, ...)` callback.
    # root.update() drains callbacks that are already due but does NOT
    # wait 60ms of wall clock, so a single update races the timer and the
    # window is still detached. Pump the loop until the attach lands (or
    # give up) instead of relying on timing luck.
    win = app._mem_core_win
    deadline = time.time() + 5.0
    while time.time() < deadline:
        app.root.update()
        if win is not None and win.mem is not None and win.mem.is_attached():
            break
        time.sleep(0.02)
    app.root.update()
    check("launcher created window", win is not None)
    check("window exists on screen", win is not None and
          bool(win.winfo_exists()))
    check("window title", win is not None and
          "Memory.h" in win.title(), win.title() if win else "")
    check("auto-attached to current target", win is not None and
          win.mem is not None and win.mem.is_attached(),
          f"pid={win.mem.pid if win and win.mem else None}")
    check("attached to the right pid", win is not None and win.mem is not None
          and win.mem.pid == real_pid)
    check("modules populated", win is not None and
          len(win.mod_tree.get_children()) > 5,
          f"({len(win.mod_tree.get_children()) if win else 0} rows)")

    # --- it actually reads/writes through the app-attached handle ---
    if win and win.mem:
        win.addr_var.set("0x%X" % p1)
        win.type_var.set("uint16")
        win._do_read()
        check("app-window read HP", win.val_var.get().startswith("0x64"),
              win.val_var.get())
        win.val_var.set("777")
        win._do_write()
        check("app-window write 777", win.mem.read(p1, "uint16") == 777,
              str(win.mem.read(p1, "uint16")))
        win.val_var.set("100")
        win._do_write()

    # --- second launch reuses the same window ---
    first = win
    app._open_memory_core()
    app.root.update()
    check("second launch reuses window", app._mem_core_win is first)

    # --- close releases the handle ---
    app._close_memory_core()
    app.root.update()
    check("close clears reference", app._mem_core_win is None)

    # --- reopen after close works ---
    app._open_memory_core()
    app.root.update()
    check("reopen after close works", app._mem_core_win is not None and
          bool(app._mem_core_win.winfo_exists()))
    app._close_memory_core()

    app.root.destroy()
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
        print(f"FAILED {len(FAIL)} check(s):")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    print("ALL INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    main()
