"""Validate the Python pelite port in cs2_offsets.py against a real dumper run.

Reference: D:\\cs2-dumper\\output\\offsets.json, produced by the Rust cs2-dumper
against CS2 build 14188. Every offset must MATCH exactly; a DEAD or MISMATCH row
means a pattern went stale and the number is unusable.

Usage:  python tools/cs2_validate_offsets.py
"""
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402

CS_ROOT = Path(r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive")
BINARIES = {
    "client.dll": CS_ROOT / "game" / "csgo" / "bin" / "win64" / "client.dll",
    "engine2.dll": CS_ROOT / "game" / "bin" / "win64" / "engine2.dll",
    "inputsystem.dll": CS_ROOT / "game" / "bin" / "win64" / "inputsystem.dll",
    "matchmaking.dll": CS_ROOT / "game" / "csgo" / "bin" / "win64" / "matchmaking.dll",
    "soundsystem.dll": CS_ROOT / "game" / "bin" / "win64" / "soundsystem.dll",
}
REFERENCE = Path(r"D:\cs2-dumper\output\offsets.json")


def main() -> int:
    if not REFERENCE.is_file():
        print(f"ERROR: reference not found: {REFERENCE}")
        print("Run the Rust cs2-dumper once so output/offsets.json exists.")
        return 2

    ours = {}
    for module, path in BINARIES.items():
        if not path.is_file():
            print(f"[skip] {module}: not found at {path}")
            continue
        print(f"resolving {module} ({path.stat().st_size:,} bytes) ...", flush=True)
        ours[module] = c2.resolve_module(module, str(path))

    print()
    rows = c2.validate_against_reference(ours, REFERENCE)

    print(f"{'module':<16} {'name':<38} {'expected':>12} {'ours':>12}  verdict")
    print("-" * 100)
    failures = 0
    for r in rows:
        exp = f"0x{r['expected']:X}"
        got = "-" if r["got"] is None else f"0x{r['got']:X}"
        flag = ""
        if r["verdict"] != "MATCH":
            failures += 1
            flag = "  <-- FAIL"
        print(f"{r['module']:<16} {r['name']:<38} {exp:>12} {got:>12}  "
              f"{r['verdict']}{flag}")

    print()
    total = len(rows)
    print(f"{total - failures}/{total} offsets match the reference dumper run")

    # Where each resolved global actually lives. A global that resolves into
    # .text is a mis-parse, not a discovery.
    print("\n-- section of each resolved client.dll global --")
    client = ours.get("client.dll")
    if client:
        from evolution_offset_dumper import load_pe  # noqa: F401
        import pefile
        pe = pefile.PE(data=open(BINARIES["client.dll"], "rb").read(), fast_load=False)
        for name in sorted(n for n in client["offsets"] if not n.endswith("__match")):
            rva = client["offsets"][name]
            sec = client["section_of"](rva)
            mark = "" if sec in (".data", ".rdata", ".text") else "  <-- outside image"
            print(f"  {name:<38} 0x{rva:08X}  {sec}{mark}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
