"""
test_memory_core_gui.py — GUI smoke test for memory_core_panel.py

Creates the real Toplevel, attaches to a live DummyGame target, and drives
the actual widgets + callbacks (no mocking). Run: python test_memory_core_gui.py
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

TARGET_NAME = "MomoGuiTarget.exe"
TARGET_EXE = os.path.join(HERE, TARGET_NAME)


def check(label, cond, extra=""):
    if not cond:
        FAIL.append(label)
    print(f"[{'PASS' if cond else 'FAIL'}] {label} {extra}")


def main():
    import memory_core_panel as mcp

    # --- live target ---
    dst = TARGET_EXE
    # A crashed previous run can leave the copy locked by a live process.
    for _ in range(3):
        if not os.path.exists(dst):
            break
        try:
            os.remove(dst)
        except PermissionError:
            time.sleep(1.5)
    check("stale target copy removed", not os.path.exists(dst))
    shutil.copy2(sys.executable, dst)
    proc = subprocess.Popen([dst, "-u", "DummyGame.py"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, cwd=ROOT)
    lines = []
    real_pid = None
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
    p1 = int(re.search(r"Player @ 0x([0-9A-Fa-f]+)", "\n".join(lines)).group(1), 16)
    chain = int(re.search(r"Created pointer chain at ([0-9A-Fa-f]+)",
                          "\n".join(lines)).group(1), 16)
    check("target ready", real_pid is not None, f"pid={real_pid}")

    root = tk.Tk()
    root.withdraw()
    win = mcp.MemoryCoreWindow(root, None, "")
    root.update()
    check("window constructs", win.winfo_exists() == 1)
    check("title set", "Memory.h" in win.title(), win.title())

    try:
        # --- attach by PID (drive the real widget + callback) ---
        win.pid_var.set(str(real_pid))
        win._attach_pid_from_field()
        root.update()
        check("attach by PID via GUI", win.mem is not None and
              win.mem.is_attached(), f"pid={win.mem.pid if win.mem else None}")
        check("pid field updated", win.pid_var.get() == str(real_pid))
        check("proc name field filled", win.proc_var.get() != "",
              win.proc_var.get())
        check("modules listed in tree",
              len(win.mod_tree.get_children()) > 5,
              f"({len(win.mod_tree.get_children())} rows)")

        # --- module selection -> address fields ---
        win.mod_tree.selection_set(win.mod_tree.get_children()[0])
        win._use_selected_module()
        root.update()
        check("module base -> address field", win.addr_var.get().startswith("0x"),
              win.addr_var.get())
        check("module base -> chain field",
              win.chain_base_var.get().startswith("0x"),
              win.chain_base_var.get())

        # --- read via GUI widgets ---
        win.addr_var.set("0x%X" % p1)
        win.type_var.set("uint16")
        win._do_read()
        root.update()
        check("GUI read HP -> 100", win.val_var.get().startswith("0x64"),
              win.val_var.get())

        # --- write via GUI widgets ---
        win.val_var.set("4242")
        win._do_write()
        root.update()
        check("GUI write 4242", win.mem.read(p1, "uint16") == 4242,
              str(win.mem.read(p1, "uint16")))
        win.val_var.set("100")
        win._do_write()
        check("GUI write restored 100", win.mem.read(p1, "uint16") == 100)

        # --- hex value entry (0x prefixed) ---
        win.val_var.set("0xDEAD")
        win._do_write()
        check("GUI hex value write", win.mem.read(p1, "uint16") == 0xDEAD)
        win.val_var.set("100")
        win._do_write()

        # --- float type ---
        win.addr_var.set("0x%X" % (p1 + 0x20))
        win.type_var.set("float")
        win.val_var.set("2.5")
        win._do_write()
        check("GUI float write", abs(win.mem.read(p1 + 0x20, "float") - 2.5) < 1e-6)

        # --- chain resolve + read + write via GUI ---
        win.chain_base_var.set("0x%X" % chain)
        win.chain_off_var.set("0x100, 0x200, 0x300, 0x300")
        win.chain_type_var.set("uint32")
        win._do_resolve()
        root.update()
        resolved = win.addr_var.get()
        check("GUI chain resolve fills address",
              resolved.startswith("0x") and int(resolved, 16) != 0, resolved)
        win._do_chain_read()
        check("GUI chain read 0xDEADBEEF",
              win.mem.read_chain(chain, [0x100, 0x200, 0x300, 0x300],
                                 "uint32") == 0xDEADBEEF)
        win.val_var.set("1337")
        win._do_chain_write()
        check("GUI chain write 1337",
              win.mem.read_chain(chain, [0x100, 0x200, 0x300, 0x300],
                                 "uint32") == 1337)

        # --- '+' separated offsets also parse ---
        win.chain_off_var.set("0x100+0x200+0x300+0x300")
        win._do_resolve()
        check("'+' offset syntax", win.addr_var.get() == resolved,
              f"{win.addr_var.get()} vs {resolved}")

        # --- saved entries ---
        win.addr_var.set("0x%X" % p1)
        win.type_var.set("uint16")
        win.val_var.set("100")
        win._save_entry()
        check("entry saved to listbox",
              len(win.saved_list.get_children() if hasattr(win.saved_list, 'get_children')
                  else win.saved_list.get(0, "end")) == 1)
        win.saved_list.selection_clear(0, "end")
        win.saved_list.selection_set(0)
        win.addr_var.set("0x0")
        win._load_saved()
        check("entry loaded back", win.addr_var.get() == "0x%X" % p1,
              win.addr_var.get())
        win.saved_list.selection_set(0)
        win._remove_saved()
        check("entry removed", len(win.entries) == 0)

        # --- console output is ASCII-clean ---
        text = win.console.get("1.0", "end")
        check("console non-empty", len(text) > 50, f"({len(text)} chars)")
        check("console is ASCII-safe", all(ord(c) < 128 for c in text))

        # --- bad input handled without crashing ---
        win.addr_var.set("not_a_number")
        win._do_read()
        win.addr_var.set("0x10")
        win._do_read()
        win.addr_var.set("0x%X" % p1)
        win.val_var.set("not_a_number")
        win._do_write()
        win.chain_off_var.set("zzz")
        win._do_resolve()
        root.update()
        check("bad input handled gracefully", win.winfo_exists() == 1)

        # --- export entries to ini ---
        win._save_entry()
        ini = os.path.abspath("_gui_test_entries.ini")
        if os.path.exists(ini):
            os.remove(ini)
        win._export_ini_path = ini
        orig_asksave = mcp.filedialog.asksaveasfilename
        mcp.filedialog.asksaveasfilename = lambda **kw: ini
        try:
            win._export_ini()
        finally:
            mcp.filedialog.asksaveasfilename = orig_asksave
        check("ini exported", os.path.exists(ini))
        if os.path.exists(ini):
            body = open(ini, encoding="utf-8").read()
            check("ini contains entry", "0x%X" % p1 in body, body.strip()[:60])

        # --- detach ---
        win._detach()
        root.update()
        check("detach clears engine", win.mem is None)
        check("detach clears module list",
              len(win.mod_tree.get_children()) == 0)

        # --- attach by NAME through the GUI ---
        win2 = mcp.MemoryCoreWindow(root, None, TARGET_NAME)
        root.update()
        win2._attach_by_name()
        root.update()
        check("GUI attach by name", win2.mem is not None and
              win2.mem.is_attached(),
              win2.mem.pid if win2.mem else "None")
        if win2.mem and win2.mem.ambiguous:
            check("ambiguity warned in console",
                  "other instance" in win2.console.get("1.0", "end"))
        win2.on_close()

        # --- on_close releases handle ---
        win.on_close()
        check("on_close destroys window", not win.winfo_exists())

    finally:
        try:
            root.destroy()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.3)
        for f in (dst, os.path.abspath("_gui_test_entries.ini")):
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    print("\n" + "=" * 52)
    if FAIL:
        print(f"FAILED {len(FAIL)} check(s):")
        for f in FAIL:
            print("  -", f)
        sys.exit(1)
    print("ALL GUI TESTS PASSED")


if __name__ == "__main__":
    main()
