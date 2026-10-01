"""
check_cpp_toolchain.py — report which C/C++ toolchains can rebuild the executor DLL.

The pipeline needs to compile downloads/*.cpp. mingw (x86_64-w64-mingw32-g++) is
the documented toolchain but is not on PATH on this box; MSVC may be available
via vswhere/vcvars64 instead.

Run:  python tools/check_cpp_toolchain.py
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def probe_mingw():
    gpp = shutil.which("x86_64-w64-mingw32-g++")
    gcc = shutil.which("x86_64-w64-mingw32-gcc")
    return bool(gpp and gcc), (gpp or "NOT FOUND"), (gcc or "NOT FOUND")


def probe_msvc():
    """Locate MSVC via the standard vswhere installer path."""
    vswhere = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if not os.path.exists(vswhere):
        return None, "vswhere NOT FOUND"
    try:
        out = subprocess.run(
            [vswhere, "-latest", "-products", "*",
             "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-property", "installationPath"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
    except Exception as e:
        return None, f"vswhere failed: {e}"
    if not out:
        return None, "MSVC toolset NOT INSTALLED"
    cl = None
    tools_root = os.path.join(out, "VC", "Tools", "MSVC")
    if os.path.isdir(tools_root):
        for ver in sorted(os.listdir(tools_root), reverse=True):
            cand = os.path.join(tools_root, ver, "bin", "Hostx64", "x64", "cl.exe")
            if os.path.exists(cand):
                cl = cand
                break
    vcvars = os.path.join(out, "VC", "Auxiliary", "Build", "vcvars64.bat")
    return cl, (f"vcvars: {vcvars} exists={os.path.exists(vcvars)}")


def main():
    print("=" * 60)
    print("C/C++ TOOLCHAIN PROBE")
    print("=" * 60)

    ok_mingw, gpp, gcc = probe_mingw()
    print(f"\n[mingw]  usable={ok_mingw}")
    print(f"        g++  = {gpp}")
    print(f"        gcc  = {gcc}")

    cl, note = probe_msvc()
    print(f"\n[MSVC]   cl.exe = {cl or 'NOT FOUND'}")
    print(f"        {note}")

    print("\n" + "-" * 60)
    if ok_mingw:
        print("VERDICT: mingw available - documented build path works")
        return 0
    if cl:
        print("VERDICT: no mingw, but MSVC is available.")
        print("         Build via vcvars64.bat, NOT bare 'cl' (needs INCLUDE/LIB env).")
        return 0
    print("VERDICT: NO C++ COMPILER. Cannot rebuild any executor DLL.")
    print("         _create_loader_dll() will raise FileNotFoundError, uncaught.")
    return 1


if __name__ == "__main__":
    sys.exit(main())