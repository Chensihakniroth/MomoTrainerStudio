"""
test_instance_picker.py — verify the Memory.h panel lets the user CHOOSE
which instance to attach to when an exe name is ambiguous.

A bare name lookup binds to the first matching PID, which for a
multi-instance exe is usually a windowless helper. These tests spawn two
real DummyGame targets under one exe name and assert:

  1. list_instances() finds BOTH (not just the first)
  2. each row carries a distinct, usable label
  3. attach-by-name with 1 match attaches without showing the picker
  4. attach-by-name with 2+ matches opens the picker
  5. picking a row attaches to THAT pid, not the first one
  6. cancelling the picker attaches nothing
  7. a dead pid in the list is dropped rather than crashing the picker
"""
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
TARGET_NAME = "MomoPickTarget.exe"
TARGET = os.path.join(HERE, TARGET_NAME)


def check(label, cond, extra=""):
    if not cond:
        FAIL.append(label)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", label, extra))


def prepare_target(name):
    """Copy the interpreter to a unique exe name. Once per name, not per
    spawn -- a running image cannot be deleted, so re-copying the same
    name for a second instance leaves a locked file behind."""
    dst = os.path.join(HERE, name)
    for attempt in range(6):
        if not os.path.exists(dst):
            break
        try:
            os.remove(dst)
        except PermissionError:
            time.sleep(1.0 + attempt)
    if os.path.exists(dst):
        raise RuntimeError("stale target %s locked" % name)
    shutil.copy2(sys.executable, dst)
    return dst


def spawn_target(name, prepared=False):
    """Launch DummyGame under a uniquely-named copy of the interpreter.

    Copying python.exe means the real interpreter is a CHILD of the shim,
    so the PID we parse from the child's own output is the process that
    actually holds the allocations. Takes the shim PID and every read
    fails with error 299 instead.

    Returns (proc, named_pid, real_pid, player_addr) where named_pid is
    the process the exe NAME resolves to (the shim) and real_pid owns the
    memory. Name-based lookups see named_pid; reads must use real_pid.
    """
    dst = os.path.join(HERE, name)
    if not prepared:
        prepare_target(name)
    proc = subprocess.Popen([dst, "-u", "DummyGame.py"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
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
    blob = "\n".join(lines)
    check("target %s ready" % name, real_pid is not None, "pid=%s" % real_pid)
    check("no chain error in %s" % name, "CHAIN ERROR" not in blob)
    p1 = int(re.search(r"Player @ 0x([0-9A-Fa-f]+)", blob).group(1), 16)
    return proc, proc.pid, real_pid, p1


def cleanup_target(name):
    for _ in range(6):
        try:
            os.remove(os.path.join(HERE, name))
            return
        except (PermissionError, FileNotFoundError):
            time.sleep(1.0)


def main():
    # ONE exe, TWO live instances -- this is the whole point of the test
    prepare_target(TARGET)
    procs, a_named, a_real, a_p1 = spawn_target(TARGET, prepared=True)
    procs2, b_named, b_real, b_p1 = spawn_target(TARGET, prepared=True)
    check("two distinct named pids", a_named != b_named,
          "%s vs %s" % (a_named, b_named))
    check("two distinct real pids", a_real != b_real,
          "%s vs %s" % (a_real, b_real))
    check("targets have distinct Player addresses", a_p1 != b_p1)

    try:
        # ---- 1. engine sees BOTH instances ----
        inst = mc.list_instances(TARGET_NAME)
        pids = [i[0] for i in inst]
        check("list_instances finds both targets",
              a_named in pids and b_named in pids,
              "found %s" % pids)
        check("list_instances is not just find_pid's first",
              len([p for p in pids if p in (a_named, b_named)]) == 2)
        check("find_pids agrees",
              set(mc.find_pids(TARGET_NAME)) >= {a_named, b_named})
        check("rows are (pid, name, titles)",
              all(len(i) == 3 and i[1] == TARGET_NAME for i in inst))
        check("titles are lists", all(isinstance(i[2], list) for i in inst))

        # ---- 2. labels are usable and distinct ----
        labels = [mc.describe_instance(i[0], i[1], i[2]) for i in inst]
        check("label mentions the pid",
              all(str(i[0]) in l for i, l in zip(inst, labels)))
        check("labels are distinct", len(set(labels)) == len(labels))
        print("    sample label:", labels[0])

        # window_titles_by_pid must not blow up or return junk
        tmap = mc.window_titles_by_pid([a_named, b_named, 999999])
        check("titles keyed for every requested pid",
              set(tmap) == {a_named, b_named, 999999}, str(sorted(tmap)))
        check("unknown pid has empty title list", tmap[999999] == [])
        check("describe_instance handles a dead pid",
              "999999" in mc.describe_instance(999999, "ghost.exe"))

        # ---- 3. ambiguous name must open the picker ----
        root = tk.Tk()
        root.withdraw()
        # Build the window with no pid so the constructor never schedules
        # its deferred `after(60, ...)` auto-attach. Otherwise that timer
        # can fire after the detach below and silently re-attach, making
        # "cancel attaches nothing" fail depending on machine timing.
        win = mcp.MemoryCoreWindow(root, None, TARGET_NAME)

        opened = {"n": 0}

        def _spy(*_a, **_k):
            opened["n"] += 1
            return None

        real_pick = win._pick_instance
        win._pick_instance = _spy

        win.proc_var.set(TARGET_NAME)
        win._attach_by_name()
        root.update()
        check("picker opened for ambiguous name", opened["n"] == 1,
              "calls=%d" % opened["n"])
        check("cancelling the picker attaches nothing", win.mem is None)

        # now actually pick the SECOND pid and confirm we land on it
        def _pick_second(name, instances):
            check("picker received both instances",
                  len(instances) == 2, str(len(instances)))
            return b_named

        win._pick_instance = _pick_second
        win.proc_var.set(TARGET_NAME)
        win._attach_by_name()
        root.update()
        check("picked instance is the one attached",
              win.mem is not None and win.mem.pid == b_named,
              "attached pid=%s wanted=%s"
              % (win.mem.pid if win.mem else None, b_named))
        check("attached to the SECOND pid, not the first",
              win.mem is not None and win.mem.pid != a_named)
        check("pid field updated to the choice", win.pid_var.get() == str(b_named))

        # ---- 4. cross-process read/write through the panel ----
        # Attach by the REAL pid: the copied interpreter is a launcher
        # shim that owns the name but not the allocations, so reading a
        # Player address through the shim's heap is error 299 by design.
        win._detach()
        root.update()
        win._attach_pid(b_real)
        root.update()
        check("attached to the real target", win.mem.is_attached())
        win.addr_var.set("0x%X" % b_p1)
        win.type_var.set("uint16")
        win._do_read()
        check("panel reads the chosen target",
              win.val_var.get().startswith("0x64"), win.val_var.get())
        win.val_var.set("777")
        win._do_write()
        check("panel writes the chosen target",
              win.mem.read(b_p1, "uint16") == 777,
              str(win.mem.read(b_p1, "uint16")))
        win.val_var.set("100")
        win._do_write()
        root.update()
        check("value restored", win.mem.read(b_p1, "uint16") == 100)

        # the OTHER instance must be untouched
        other = mc.Memory(pid=a_real)
        check("other instance unaffected", other.read(a_p1, "uint16") == 100,
              str(other.read(a_p1, "uint16")))
        other.close()

        # ---- 5. a dead pid in the list must not crash the picker ----
        poisoned = [(a_named, TARGET_NAME, []), (999999, TARGET_NAME, []),
                    (b_named, TARGET_NAME, [])]
        plabels = [mc.describe_instance(p, n, t) for p, n, t in poisoned]
        check("labels render with a dead pid present",
              len(plabels) == 3 and all(isinstance(x, str) for x in plabels))

        def _pick_dead(name, instances):
            return 999999

        win._pick_instance = _pick_dead
        win.proc_var.set(TARGET_NAME)
        win._attach_by_name()
        root.update()
        check("dead pid does not crash the panel", bool(root.winfo_exists()))
        check("dead pid leaves panel detached", win.mem is None)
        out = win.console.get("1.0", "end")
        check("dead pid reported as an error",
              "failed" in out.lower() or "not found" in out.lower(),
              out.strip().splitlines()[-1][:70] if out.strip() else "")

        # ---- 6. single-instance name attaches with no picker ----
        win._pick_instance = real_pick
        opened2 = {"n": 0}

        def _spy2(*_a, **_k):
            opened2["n"] += 1
            return None

        win._pick_instance = _spy2
        win.proc_var.set("MomoSingleTarget.exe")
        win._attach_by_name()
        root.update()
        check("unknown name attaches nothing", win.mem is None)
        check("unknown name does not open the picker", opened2["n"] == 0)
        check("unknown name is reported",
              "not found" in win.console.get("1.0", "end").lower())

        # one real match -> attaches directly, picker untouched
        win._detach()
        root.update()
        single = "MomoOneTarget.exe"
        p3, s_named, s_real, s_p1 = spawn_target(single)
        try:
            win._pick_instance = _spy2
            win.proc_var.set(single)
            win._attach_by_name()
            root.update()
            check("single instance picks the only one",
                  opened2["n"] == 0, "picker_calls=%d" % opened2["n"])
            check("single instance attaches without the picker",
                  win.mem is not None and win.mem.pid == s_named,
                  "pid=%s" % (win.mem.pid if win.mem else None))
            # and reading works once we are on the real pid
            win._detach()
            root.update()
            win._attach_pid(s_real)
            root.update()
            check("single instance reads correctly",
                  win.mem.read(s_p1, "uint16") == 100,
                  str(win.mem.read(s_p1, "uint16")))
        finally:
            p3.kill()
            p3.wait(timeout=10)
            cleanup_target(single)

        root.destroy()
    finally:
        for p in (procs, procs2):
            p.kill()
            p.wait(timeout=10)
        cleanup_target(TARGET)

    print()
    if FAIL:
        print("FAILED (%d): %s" % (len(FAIL), ", ".join(FAIL)))
        sys.exit(1)
    print("ALL INSTANCE-PICKER TESTS PASSED")


if __name__ == "__main__":
    main()
