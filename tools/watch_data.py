"""
watch_data.py — watch Warframe's .data region for values that change.

The offset dumper proves that a static RVA is correct; it cannot tell you
whether a value MEANS anything. This does: it diffs the .data region
across time, so anything that moves while you play is a real gameplay
value rather than an initialised constant.

This is the natural follow-up to the dumper's live verification. The
dumper narrowed 52 candidates to one address (rva 0x2730070) and showed
it never changes. This finds the ones that DO change, without needing to
already know their addresses.

Usage:
    python watch_data.py                 # watch, 5s between samples
    python watch_data.py --pid 12345     # explicit pid
    python watch_data.py --seconds 60    # keep running for a minute

Then go into a mission and do something. Anything that moves gets
reported with its RVA, which is exactly what an offset is.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

# Repo root, so `import evolution_offset_dumper` works from anywhere.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import evolution_offset_dumper as dumper  # noqa: E402

# .data / .rdata region of Warframe.x64.exe, from the static PE. Verified
# against the 2026-09-24 build (sha256 d01b5cb5cff51afc).
WATCH_START_RVA = 0x2730000
WATCH_SIZE = 0x4000        # 16 KB of qwords
DEFAULT_SAMPLE = 5.0


def find_pid(name: str = "Warframe.x64.exe") -> int:
    import ctypes
    from ctypes import wintypes as wt
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE

    class E(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
            ("szExeFile", wt.WCHAR * 260),
        ]

    snap = k32.CreateToolhelp32Snapshot(2, 0)
    entry = E()
    entry.dwSize = ctypes.sizeof(E)
    found = 0
    if k32.Process32FirstW(snap, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.lower() == name.lower():
                found = int(entry.th32ProcessID)
                break
            entry = E()
            entry.dwSize = ctypes.sizeof(E)
            if not k32.Process32NextW(snap, ctypes.byref(entry)):
                break
    k32.CloseHandle(snap)
    return found


def snapshot(pid: int, base: int, start_rva: int, size: int) -> dict:
    """{offset_in_region: 8 raw bytes} for everything readable."""
    out = {}
    start = base + start_rva
    off = 0
    while off < size:
        chunk = dumper.live_read(pid, start + off, 0x400)
        if not chunk:
            break
        for i in range(0, len(chunk) - 7, 8):
            out[off + i] = chunk[i:i + 8]
        off += 0x400
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--seconds", type=float, default=0.0,
                    help="stop after N seconds (0 = run until Ctrl-C)")
    ap.add_argument("--interval", type=float, default=DEFAULT_SAMPLE)
    ap.add_argument("--start-rva", type=lambda x: int(x, 0),
                    default=WATCH_START_RVA)
    ap.add_argument("--size", type=lambda x: int(x, 0), default=WATCH_SIZE)
    args = ap.parse_args(argv)

    pid = args.pid or find_pid()
    if not pid:
        print("Warframe.x64.exe is not running. Launch the game first.")
        return 1

    import memory_core as mc
    mem = mc.Memory(pid=pid)
    base = mem.get_module_address("") or 0
    mem.close()
    if not base:
        print("could not resolve the module base for pid %d" % pid)
        return 1

    start_va = base + args.start_rva
    print("Watching pid %d  base 0x%X" % (pid, base))
    print("  region  rva 0x%X .. 0x%X  (VA 0x%X .. 0x%X)"
          % (args.start_rva, args.start_rva + args.size, start_va,
             start_va + args.size))
    print("  sampling every %.1fs. Go into a mission and do something.\n"
          % args.interval)

    seen_changes = {}
    prev = snapshot(pid, base, args.start_rva, args.size)
    print("baseline: %d qwords readable" % len(prev))

    deadline = time.time() + args.seconds if args.seconds else None
    try:
        while True:
            time.sleep(args.interval)
            cur = snapshot(pid, base, args.start_rva, args.size)
            if not cur:
                print("target no longer readable - did the game exit?")
                break
            changed = [k for k in prev
                       if k in cur and prev[k] != cur[k]]
            for off in changed:
                old = int.from_bytes(prev[off], "little")
                new = int.from_bytes(cur[off], "little")
                rva = args.start_rva + off
                key = rva
                entry = seen_changes.setdefault(key, {"first": new,
                                                      "vals": {new},
                                                      "n": 0})
                entry["vals"].add(new)
                entry["n"] += 1
                entry["last"] = new
                print("  CHANGED rva 0x%08x  0x%X -> 0x%X"
                      % (rva, old, new))
            prev = cur
            if deadline and time.time() >= deadline:
                break
    except KeyboardInterrupt:
        print("\nstopped")

    print("\n=== %d distinct addresses changed ===" % len(seen_changes))
    for rva, e in sorted(seen_changes.items()):
        vals = sorted(e["vals"])
        print("  rva 0x%08x  VA 0x%X  %d change(s), %d distinct value(s): %s"
              % (rva, base + rva, e["n"], len(vals),
                 ", ".join("0x%X" % v for v in vals[:6])))
    if not seen_changes:
        print("  nothing moved. The region may be initialised-once state;")
        print("  try a wider --start-rva/--size, or confirm you were in a")
        print("  mission rather than at the menu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())