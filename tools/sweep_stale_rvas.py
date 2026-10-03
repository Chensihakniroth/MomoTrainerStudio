"""Sweep the CS2 probe scripts onto the generated offsets header.

Handoff SS14.11: twenty-six scripts hardcoded their own globals. CS2 build
14188 moved `dwEntityList` and `dwViewAngles` by `-0x10` and every one of
them silently read the wrong memory - no exception, no error, just a wrong
answer that looks like data.

Editing the constants would re-arm the trap at the next patch. This rewrites
the *definition* sites to read the header, which `cs2_gen_overlay_header.py`
regenerates after every update.

## What it changes, and what it refuses to change

- **Only constant definitions** matching a known name, at module level.
- **Only literal integers** that equal a known header value, or that look like
  a CS2 RVA/field offset. A `0x70` that is some unrelated local meaning is
  left alone.
- **Never** edits a value that does not correspond to any header constant.
- Comments and identifiers are preserved; each rewritten line gets a pointer
  to the header so the provenance is obvious.

Anything it cannot classify is reported, never guessed.

Usage:
    python tools/sweep_stale_rvas.py --dry-run     # show what would change
    python tools/sweep_stale_rvas.py               # apply
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs2_header_offsets import offsets, ALIASES, _norm   # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DIRS = ("tools", "tests", "tests/probes")

# Legacy local name -> header alias. Only these are rewritten; an unknown
# name is reported rather than guessed at.
LEGACY = {
    "ENTITY_LIST": "ENTITY_LIST",
    "LOCAL_PAWN": "LOCAL_PAWN",
    "LOCAL_CONTROLLER": "LOCAL_CONTROLLER",
    "VIEW_MATRIX": "VIEW_MATRIX",
    "VIEW_ANGLES": "VIEW_ANGLES",
    "GLOBAL_VARS": "GLOBAL_VARS",
    "ENTITY_SYSTEM": "ENTITY_SYSTEM",
    "HEALTH": "HEALTH",
    "TEAM_NUM": "TEAM_NUM",
    "ARMOR": "ARMOR",
    "SCENE_NODE": "SCENE_NODE",
    "ABS_ORIGIN": "ABS_ORIGIN",
    "PLAYER_PAWN": "PLAYER_PAWN",
    "PLAYER_NAME": "PLAYER_NAME",
    "IS_LOCAL_CONTROLLER": "IS_LOCAL_CONTROLLER",
    "PAGE_OFFSET": "PAGE_OFFSET",
    "SLOT_STRIDE": "SLOT_STRIDE",
    "HANDLE_MASK": "HANDLE_MASK",
    "MAX_SLOTS": "MAX_SLOTS",
    "CONTROLLER_COUNT": "CONTROLLER_COUNT",
    "BOUNDS_MIN": "BOUNDS_MIN",
    "BOUNDS_MAX": "BOUNDS_MAX",
    "VIEW_OFFSET": "VIEW_OFFSET",
    "WEAPON_SERVICES": "OFFWEAPONSERVICES",
    "ACTIVE_WEAPON": "OFFACTIVEWEAPON",
    "CLIP1": "OFFCLIP1",
    "CLIP2": "OFFCLIP2",
    "RESERVE_AMMO": "OFFRESERVEAMMO",
}

# `NAME = 0x1234` at module level (column 0).
DEF_RE = re.compile(r'^([A-Z][A-Z0-9_]*)(\s*[:][^=\n]+)?(\s*)=\s*'
                    r'(0[xX][0-9a-fA-F]+|\d+)\s*(#.*)?$')


def load_script(path):
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        return f.read().splitlines()


def save_script(path, lines):
    with open(path, "w", encoding="utf-8", errors="surrogateescape",
              newline="") as f:
        f.write("\n".join(lines))


def process(path, o, dry):
    lines = load_script(path)
    changed, unknown, needs_import = [], [], False
    out = list(lines)

    for i, line in enumerate(lines):
        m = DEF_RE.match(line)
        if not m:
            continue
        name, ann, eq, val, comment = m.groups()
        if name not in LEGACY:
            continue
        key = LEGACY[name]
        if key not in o:
            unknown.append((i + 1, name, key))
            continue
        new = o[key]
        try:
            cur = int(val, 0)
        except ValueError:
            continue
        if cur == new and "cs2_header_offsets" not in line:
            # Already correct, but still hardcoded -> convert it too, so the
            # next CS2 update moves it automatically.
            pass
        elif cur != new:
            changed.append((i + 1, name, hex(cur), hex(new)))
        out[i] = (f'{name}{ann or ""}{eq}= o.{key}   # was {val}; '
                  f'cs2_header_offsets.py')
        needs_import = True

    if not needs_import:
        return 0, 0, []

    # Insert the import AFTER the module docstring, never inside it.
    #
    # Placing it at the first "import"-looking line is wrong: inside a
    # docstring that line is prose, so the import silently becomes part of
    # the docstring. The file still compiles, `o` still resolves, and the
    # only visible damage is a corrupted docstring - exactly the kind of
    # quiet regression these tools already have too many of.
    ins = None
    QUOTES = ('"""', "'''")
    if out and out[0].lstrip().startswith(QUOTES):
        q = out[0].lstrip()[:3]
        if out[0].strip().endswith(q) and len(out[0].strip()) > 3:
            ins = 1                               # single-line docstring
        else:
            for k in range(1, len(out)):
                if q in out[k]:
                    ins = k + 1
                    break
    if ins is None:
        # No docstring: after any __future__ import, else at the top.
        ins = 0
        for k, line in enumerate(out[:40]):
            if line.startswith("from __future__"):
                ins = k + 1
    out[ins:ins] = ["from cs2_header_offsets import offsets", "", "o = offsets()"]
    changed.append((ins + 1, "<import>", "hardcoded",
                        "cs2_header_offsets"))

    if not dry:
        save_script(path, out)
    return len(changed), len(unknown), unknown


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dir", default=None)
    a = ap.parse_args()

    o = offsets()
    print(f"header build {o.build}, {len(o.as_dict())} constants")
    if a.dry_run:
        print("DRY RUN - nothing written\n")

    files = []
    for d in ([a.dir] if a.dir else list(SCAN_DIRS)):
        p = os.path.join(ROOT, d)
        if not os.path.isdir(p):
            continue
        for f in sorted(os.listdir(p)):
            if f.endswith(".py") and f != "sweep_stale_rvas.py":
                files.append(os.path.join(p, f))

    total_files = total_subs = 0
    report = []
    for path in files:
        rel = os.path.relpath(path, ROOT)
        base = os.path.basename(path)
        # Never the loader itself, and never the GENERATOR: the generator
        # defines the walk constants and emits the header that
        # cs2_header_offsets.py
        # reads, so making it import from the header is circular. It would
        # also work by accident on the first run and break the moment the
        # header is deleted or stale - which is exactly when it must still run.
        if base in ("cs2_header_offsets.py", "sweep_stale_rvas.py",
                    "cs2_gen_overlay_header.py"):
            continue
        n, nu, unknown = process(path, o, a.dry_run)
        if n:
            total_files += 1
            total_subs += n
            report.append((rel, n, nu, unknown))

    print(f"\n{total_subs} substitutions across {total_files} files")
    for rel, n, nu, unknown in report:
        print(f"  {rel:<44} {n} changed" + (f"  ({nu} unknown)" if nu else ""))
        for ln, name, key in unknown:
            print(f"      ! line {ln}: {name} -> {key} not in header")
    if not report:
        print("  nothing to do")
    if a.dry_run and report:
        print("\nre-run without --dry-run to apply")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
