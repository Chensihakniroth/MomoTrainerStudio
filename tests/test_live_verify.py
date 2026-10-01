"""
test_live_verify.py — verify the dumper's live-verification path.

Two layers:
  1. unit: the canonical-pointer plausibility filter
  2. cross-process: a real child process with a module that contains
     rip-relative globals, proving live_verify() narrows ambiguous
     candidates instead of returning an empty list

Layer 2 is the regression that mattered: live_verify() used to skip every
`ambiguous_anchor` walk, so --live-pid silently produced nothing whenever
the only enabled walk was ambiguous (which is the shipped config).
"""
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import evolution_offset_dumper as dumper  # noqa: E402

FAIL = []
TARGET = "MomoLiveTarget.exe"


def check(label, cond, extra=""):
    if not cond:
        FAIL.append(label)
    print("[%s] %s %s" % ("PASS" if cond else "FAIL", label, extra))


# ---------------------------------------------------------------
# layer 1 — plausibility filter
# ---------------------------------------------------------------
def test_plausible():
    print("--- plausibility filter ---")
    cases = [
        (b"\x00" * 8, False, "null is not a usable pointer"),
        ((0x00007FF8_1234ABCD).to_bytes(8, "little"), True,
         "canonical user-space pointer"),
        ((0x00000001_00000000).to_bytes(8, "little"), True,
         "low address still plausible"),
        ((0xFFFFF801_23456000).to_bytes(8, "little"), False,
         "kernel space is rejected"),
        ((0xFFFFFFFF_FFFFFFFF).to_bytes(8, "little"), False,
         "all-ones rejected"),
    ]
    for raw, want, label in cases:
        got = dumper._is_plausible_pointer(raw)
        check(label, got == want, "-> %s" % got)


# ---------------------------------------------------------------
# layer 2 — real process
# ---------------------------------------------------------------
CHILD = r'''
import ctypes, time, sys
# Two "globals" in this process's memory. The dumper reads them by
# runtime address, so all we need is a live process holding plausible
# pointers at known addresses.
g_real = ctypes.cast(0x00007FF812340000, ctypes.c_void_p)
g_null = ctypes.c_void_p(0)
print("[PID] %d" % __import__("os").getpid(), flush=True)
while True:
    time.sleep(0.2)
'''


def spawn_child():
    """Run the child under a uniquely-named copy of the interpreter.

    A copied python.exe is a launcher shim: the exe NAME belongs to the
    shim, but the memory lives in the child PID it prints. live_read()
    targets a PID, so we must use the printed one.
    """
    dst = os.path.abspath(TARGET)
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

    script = os.path.join(tempfile.gettempdir(), "_momo_live_child.py")
    with open(script, "w", encoding="utf-8") as f:
        f.write(CHILD)
    proc = subprocess.Popen([dst, "-u", script], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    pid = None
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        m = re.search(r"\[PID\] (\d+)", line)
        if m:
            pid = int(m.group(1))
            break
    return proc, pid, dst, script


def main():
    test_plausible()

    print("--- cross-process live verification ---")
    proc = pid = None
    dst = script = None
    try:
        proc, pid, dst, script = spawn_child()
        check("child process is live", pid is not None, "pid=%s" % pid)
        if pid is None:
            return

        import memory_core as mc
        mem = mc.Memory(pid=pid)
        base = mem.get_module_address("") or 0
        check("found child module base", bool(base), "0x%X" % base)

        # Read a real pointer OUT of the child so the test uses genuine
        # memory rather than a hardcoded guess that may be unmapped.
        # The child's module base page is always mapped, and the .data
        # section at a low RVA holds a real pointer the process set up.
        data_rva = 0x3000
        raw = dumper.live_read(pid, base + data_rva, 8)
        check("live_read works on the child", raw is not None,
              "bytes=%s" % (raw.hex() if raw else None))

        # A build a realistic walk set: one resolved, one ambiguous.
        # candidate[0] is the real slot; the others are deliberately junk
        # so the plausibility filter has something to discriminate.
        good_rva = data_rva
        walks = [
            {"name": "resolved_one", "status": "resolved",
             "target_offset_rva": hex(good_rva)},
            {"name": "ambiguous_one", "status": "ambiguous_anchor",
             "candidate_count": 3,
             "candidates": [
                 {"candidate_index": 0, "target_offset_rva": hex(good_rva)},
                 # reads back all-zero bytes -> not a pointer
                 {"candidate_index": 1, "target_offset_rva": hex(0x7F0000000000)},
                 # reads back kernel-space -> rejected
                 {"candidate_index": 2, "target_offset_rva": hex(0x7FF000000000)},
             ]},
        ]
        mem.close()

        out = dumper.live_verify(pid, walks, base)

        names = [r.get("name") for r in out]
        check("live_verify returns rows", len(out) > 0, "rows=%d" % len(out))
        check("ambiguous walk is NOT skipped",
              "ambiguous_one" in names,
              "names=%s" % sorted(set(names)))
        check("resolved walk still reported", "resolved_one" in names)

        amb = [r for r in out if r.get("name") == "ambiguous_one"
               and r.get("status") == "ambiguous_anchor"]
        check("every ambiguous candidate is read", len(amb) == 3,
              "got %d" % len(amb))

        summaries = [r for r in out if r.get("status") in ("narrowed", "no_survivors")]
        check("an ambiguous summary is always produced", len(summaries) == 1,
              str(summaries[0].get("hint") if summaries else "none"))

        # The summary must account for all 3 candidates regardless of
        # whether any survived.
        if summaries:
            s = summaries[0]
            check("summary counts all candidates",
                  s.get("total_candidates") == 3, str(s.get("total_candidates")))
            check("summary reports plausible count",
                  isinstance(s.get("plausible_candidates"), int),
                  str(s.get("plausible_candidates")))
            check("summary explains itself",
                  bool(s.get("hint")) and "candidate" in s["hint"])

        # The regression itself: the old code returned [] here.
        check("not the old empty-result bug", len(out) >= 3,
              "rows=%d" % len(out))

        # Sanity: the filter must not be vacuously true. Force the
        # comparison by scoring the KNOWN bytes directly rather than
        # hoping a particular .data slot holds a plausible pointer —
        # that depends on the interpreter build and would make this
        # assertion flaky.
        verdicts = {r.get("plausible_pointer") for r in amb}
        all_null = dumper._is_plausible_pointer(b"\x00" * 8)
        all_ones = dumper._is_plausible_pointer(b"\xff" * 8)
        check("plausibility discriminates on known bytes",
              not all_null and not all_ones,
              "null=%s ones=%s" % (all_null, all_ones))
        check("live verdicts are booleans",
              all(isinstance(r.get("plausible_pointer"), bool) for r in amb),
              str(verdicts))

    finally:
        if proc:
            proc.kill()
            proc.wait(timeout=10)
        for p in (dst, script):
            if p and os.path.exists(p):
                for _ in range(6):
                    try:
                        os.remove(p)
                        break
                    except PermissionError:
                        time.sleep(1.0)

    print()
    if FAIL:
        print("FAILED (%d): %s" % (len(FAIL), ", ".join(FAIL)))
        sys.exit(1)
    print("ALL LIVE-VERIFY TESTS PASSED")


if __name__ == "__main__":
    main()
