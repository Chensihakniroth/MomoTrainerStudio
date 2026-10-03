"""Why is dwSoundSystem dead? Compare the on-disk bytes to the expected shape."""
import os
import struct
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402
from evolution_offset_dumper import load_pe  # noqa: E402

SS = Path(r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive"
          r"\game\bin\win64\soundsystem.dll")
pe, raw, meta = load_pe(str(SS))
print(f"soundsystem.dll {len(raw):,} bytes  sha256 {meta['sha256_short']}  "
      f"mtime-ish timestamp {meta['pe_timestamp_utc']}")
print("reference dump was build 14188, captured 2026-10-01\n")

PAT = "488d0d${'} e8${} 488d0d${} [3] 4c8b82"
atoms = c2.parse_pattern(PAT)
print("pattern:", PAT)
print("atoms:")
for i, a in enumerate(atoms):
    print(f"  {i}: {a}")
print("anchor:", c2._anchor(atoms))

rva_to_file = c2.make_rva_mapper(pe, len(raw))
needle, _ = c2._anchor(atoms)
print(f"\nsweeping {needle!r} in executable sections...")
found = 0
for w_start, w_end, w_rva in c2.exec_windows(pe, len(raw)):
    pos = w_start
    while True:
        hit = raw.find(needle, pos, w_end)
        if hit < 0:
            break
        pos = hit + 1
        found += 1
        rva = w_rva + (hit - w_start)
        after = raw[hit + 3:hit + 3 + 24]
        save = c2._match_at(atoms, raw, rva, rva_to_file)
        print(f"  rva 0x{rva:06X} next bytes: {after.hex(' ')}")
        print(f"      -> {'MATCH save=' + str(['0x%X' % s for s in save]) if save is not None else 'no match'}")
        if found > 12:
            break
    if found > 12:
        break
print(f"\ntotal 48 8d 0d occurrences checked: {found}")

# What does the shape have to be?  48 8d 0d <d1> e8 <d2> 48 8d 0d <d3> [3] 4c 8b 82
print("\nexpected byte shape after '48 8d 0d':")
print("  e8 xx xx xx xx  48 8d 0d xx xx xx xx  ?? ?? ??  4c 8b 82")
# search directly for the tail signature 4c 8b 82 to see if it exists at all
tail = bytes.fromhex("4c8b82")
print(f"\n'4c 8b 82' occurrences in file: {raw.count(tail)}")
mid = bytes.fromhex("e8")
print(f"'48 8d 0d e8' occurrences: {raw.count(bytes.fromhex('488d0de8'))}")
