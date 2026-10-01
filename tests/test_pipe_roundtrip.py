"""
test_pipe_roundtrip.py — end-to-end proof that the executor pipe works.

WHY THIS EXISTS
---------------
The executor pipeline has three independent layers that can each fail
while the others look healthy:

  1. DLL load / DllMain runs / pipe server starts
  2. Python client connects to the pipe (name must match EXACTLY)
  3. Script in -> response out (encoding must match on both sides)

Historically these were only ever tested against Roblox, so a failure
could not be attributed. This harness runs the SAME DLL in a plain
console host, which isolates layer 1+2+3 from Roblox entirely.

It does NOT need Roblox running, and it does NOT inject — it uses
LoadLibraryW on a host process we own. That makes it safe to run
repeatedly and it is the regression test for the pipe contract.

WHAT IT PROVES
--------------
  - the DLL's DllMain runs and creates its named pipe
  - the pipe name the DLL builds matches what velocity_connector sends
  - a script round-trips and a response comes back
  - base64 decode happens somewhere in the path (or is reported missing)

Run:  python tests/test_pipe_roundtrip.py
"""

import base64
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOWNLOADS = ROOT / "downloads"
HOST_SRC = DOWNLOADS / "PipeHost.cpp"
HOST_EXE = DOWNLOADS / "PipeHost.exe"

sys.path.insert(0, str(ROOT))

# Must match velocity_connector.PipeConnection exactly.
EXPECTED_PREFIX = "uoQcySKXSUxxJNpVQyatpHQwYoGfhcbh"

FAILURES = []


def check(label, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)
    return ok


def pick_executor_dll():
    """Prefer the CRT DLL; that is what get_executor_dll_path() returns."""
    for name in ("RobloxExecutorCRT.dll", "RobloxExecutor64.dll",
                 "RobloxExecutor.dll"):
        p = DOWNLOADS / name
        if p.exists():
            return p
    return None


def build_host():
    """Compile PipeHost.cpp — a console app that LoadLibraryW's the DLL.

    Uses MSVC via tools/msvc_build.ps1 because mingw is absent on this box.
    Returns the exe path, or None if it cannot be built.
    """
    if HOST_EXE.exists() and HOST_EXE.stat().st_mtime > HOST_SRC.stat().st_mtime:
        return HOST_EXE

    if not HOST_SRC.exists():
        print(f"[SKIP] host source missing: {HOST_SRC}")
        return None

    ps1 = ROOT / "tools" / "msvc_build.ps1"
    if not ps1.exists():
        print("[SKIP] tools/msvc_build.ps1 missing — cannot build host")
        return None

    print(f"[*] building host: {HOST_SRC.name} -> {HOST_EXE.name}")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(ps1),
         "-Source", str(HOST_SRC),
         "-Output", str(HOST_EXE)],
        capture_output=True, text=True, timeout=300,
    )
    tail = (r.stdout or "").strip().splitlines()[-6:]
    for line in tail:
        print("    " + line)
    if r.returncode != 0 or not HOST_EXE.exists():
        print("[FAIL] host build failed")
        return None
    return HOST_EXE


def pipe_ready(pid):
    """Non-destructively check the pipe is listening.

    DO NOT open the pipe to test this. Any CreateFile on a named pipe
    *connects* to it — a probe that connects and closes consumes the
    server's instance, and a single-shot DLL server never comes back.
    That bug is real; this harness must not depend on it.

    Instead the caller retries connect() itself, which is the thing we
    actually want to prove anyway.
    """
    return True  # presence is proven by a successful connect, not by a probe


def connect_with_retry(pid, attempts=20, delay=0.25):
    """Try to connect repeatedly, as the GUI does in practice.

    The DLL starts its pipe thread asynchronously after DllMain, so the
    pipe may not exist for a moment after the process launches. A single
    attempt is a race, not a test.
    """
    from velocity_connector import PipeConnection

    last = None
    for i in range(attempts):
        conn = PipeConnection(pid)
        try:
            if conn.connect(timeout=2000):
                return conn
        except Exception as e:
            last = e
        time.sleep(delay)
    if last:
        print(f"    last connect error: {last}")
    return None


def main():
    print("=" * 62)
    print("EXECUTOR PIPE ROUND-TRIP TEST")
    print("=" * 62)

    dll = pick_executor_dll()
    if not check("executor DLL found", dll is not None, str(dll)):
        return 1
    check("executor DLL is x64", _is_x64(dll))

    host = build_host()
    if not check("pipe host built", host is not None, str(host)):
        return 1

    # Launch host with the DLL path as argv[1]; it self-loads and prints its PID.
    proc = subprocess.Popen([str(host), str(dll)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    pid = proc.stdout.readline().strip()
    print(f"[*] host pid reported: {pid or '(none)'}")

    try:
        if not check("host reported a pid", bool(pid)):
            return 1

        expected_name = f"\\\\.\\pipe\\{EXPECTED_PREFIX}_{pid}"
        from velocity_connector import PipeConnection
        conn = connect_with_retry(int(pid))
        if not check("connector connected to DLL pipe", conn is not None,
                     expected_name):
            return 1

        check("connector builds expected pipe name", conn.pipe_name == expected_name,
              conn.pipe_name)

        script = 'print("momo_roundtrip_ok")'
        ok = conn.send_lua(script)
        check("script sent", ok, f"base64={base64.b64encode(script.encode()).decode()}")

        # Bound the recv so the harness cannot hang on a silent DLL.
        # The DLL's reply is CRLF-terminated; give it a moment, then stop.
        response = None
        deadline = time.time() + 6
        while time.time() < deadline:
            response = conn.recv(timeout=500)
            if response:
                break
        # bool(), not `is not None`: the DLL replies with "\r\n\r\n" when it
        # finds nothing, which is truthy-but-empty — `is not None` would
        # wave that through as a pass.
        text = (response or b"").decode("utf-8", errors="replace")
        got = bool(text.strip())
        check("non-empty response received", got,
              f"{len(response or b'')} bytes: {text!r}")
        if not got:
            print()
            print("  WHY: the pipe contract WORKS (connect/send/recv all pass),")
            print("  but the payload is empty. Python sends base64; the DLL")
            print("  never decodes it and has no Lua engine, so it echoes")
            print("  nothing. See downloads/RobloxExecutorCRT.cpp ProcessPipe().")
            print()

        if response:
            echoed = "momo_roundtrip_ok" in response
            check("response contains script text", echoed,
                  "DLL echoed the script back (payload is a STUB, not a "
                  "Lua interpreter)" if echoed else "response did not match")
            if echoed:
                print()
                print("  NOTE: the DLL echoed the script instead of executing it.")
                print("        The pipe contract WORKS. The Lua payload is the")
                print("        missing piece — see downloads/RobloxExecutorCRT.cpp")
                print("        ProcessPipe(), which only scans for quote chars.")
                print()

        conn.disconnect()
        return 0
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _is_x64(dll):
    import struct
    with open(dll, "rb") as f:
        if f.read(2) != b"MZ":
            return False
        f.seek(0x3C)
        e_lfanew = struct.unpack("<I", f.read(4))[0]
        f.seek(e_lfanew + 4)
        return struct.unpack("<H", f.read(2))[0] == 0x8664


if __name__ == "__main__":
    code = main()
    print("=" * 62)
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}): " + ", ".join(FAILURES))
    else:
        print("ALL CHECKS PASSED")
    print("=" * 62)
    sys.exit(code)