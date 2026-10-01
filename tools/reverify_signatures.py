"""
reverify_signatures.py — re-resolve a signature database against the
CURRENT game binary and report what moved.

The database (tools/warframe_signatures.json) records RVAs captured on a
previous build. Signatures are the durable part; the RVAs are not. This
re-scans, so after a Warframe update you get fresh RVAs instead of stale
ones that read plausible-looking garbage.

Usage:
    python reverify_signatures.py                       # uses default paths
    python reverify_signatures.py --db <sig.json> --exe <Warframe.x64.exe>

Exit code 0 = every signature still unique (possibly at a new RVA).
Exit code 2 = at least one is dead or ambiguous (needs a pattern update).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pefile  # noqa: E402

DEFAULT_DB = r"D:\game\warframe_menu\tools\warframe_signatures.json"
DEFAULT_EXE = r"D:\game\warframe_menu\bin\Warframe.x64.exe"


def pattern_to_regex(hexpat: str) -> bytes:
    """IDA-style 'AA BB ?? CC' -> bytes regex. Only '?' is a wildcard."""
    rx = bytearray()
    for token in hexpat.split():
        if token in ("?", "??"):
            rx.extend(b".")
        else:
            rx.extend(re.escape(bytes([int(token, 16)])))
    return bytes(rx)


class Image:
    def __init__(self, path: str):
        self.data = open(path, "rb").read()
        self.pe = pefile.PE(path, fast_load=True)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase

    def file_to_rva(self, file_off: int):
        for s in self.pe.sections:
            start = s.PointerToRawData
            if start <= file_off < start + s.SizeOfRawData:
                name = s.Name.decode("ascii", "replace").rstrip("\x00")
                return (file_off - start) + s.VirtualAddress, name
        return None, None

    def rva_to_file(self, rva: int):
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(
                    s.SizeOfRawData, s.Misc_VirtualSize):
                return s.PointerToRawData + (rva - s.VirtualAddress)
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--update", action="store_true",
                    help="write fresh RVAs back into the database")
    ap.add_argument("--out", default="", help="write a report JSON here")
    args = ap.parse_args(argv)

    db = json.load(open(args.db, encoding="utf-8"))
    img = Image(args.exe)

    print("binary : %s (%.1f MB)" % (args.exe, len(img.data) / 1048576))
    print("db     : %s  (%d signatures)"
          % (args.db, len(db.get("signatures", []))))
    print()
    print("%-30s %-6s %-12s %-9s %s"
          % ("NAME", "HITS", "RVA", "SECTION", "VERDICT"))
    print("-" * 78)

    problems, fresh, report = [], {}, []
    for sig in db.get("signatures", []):
        name = sig.get("name", "?")
        pat = sig.get("pattern", "")
        try:
            rx = pattern_to_regex(pat)
        except Exception as e:
            print("%-30s BAD PATTERN (%s)" % (name, e))
            problems.append(name)
            continue
        hits = [m.start() for m in re.finditer(rx, img.data, re.DOTALL)]
        secs = set()
        rvas = []
        for h in hits:
            rva, sec = img.file_to_rva(h)
            if rva is not None:
                rvas.append(rva)
                secs.add(sec)
        if len(hits) == 1:
            verdict = "unique"
            rva_s = "0x%08X" % rvas[0]
            sec = list(secs)[0] if secs else "?"
            fresh[name] = rvas[0]
        elif not hits:
            verdict = "DEAD (pattern no longer matches)"
            rva_s = "-"
            sec = "-"
            problems.append(name)
        else:
            verdict = "AMBIGUOUS (%d hits)" % len(hits)
            rva_s = ",".join("0x%08X" % r for r in rvas[:4])
            sec = ",".join(sorted(s for s in secs if s))[:18]
            problems.append(name)
        print("%-30s %-6d %-12s %-9s %s"
              % (name, len(hits), rva_s, sec, verdict))
        report.append({"name": name, "hits": len(hits), "rvas": rvas,
                       "sections": sorted(s for s in secs if s),
                       "verdict": verdict})

    print()
    if problems:
        print("%d signature(s) need attention: %s"
              % (len(problems), ", ".join(problems)))
    else:
        print("all signatures resolved uniquely")

    if args.update and fresh:
        for sig in db.get("signatures", []):
            if sig.get("name") in fresh:
                sig["_verified_rva"] = "0x%08X" % fresh[sig["name"]]
        db["_reverified"] = {"exe": args.exe,
                             "size": len(img.data),
                             "imagebase": "0x%X" % img.image_base}
        with open(args.db, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        print("updated %d _verified_rva entries in %s"
              % (len(fresh), args.db))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("wrote %s" % args.out)

    return 2 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())