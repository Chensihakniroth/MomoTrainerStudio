"""Debug the ${'} bookmarked-jump patterns against real client.dll bytes."""
import os
import struct
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402
from evolution_offset_dumper import load_pe  # noqa: E402

CLIENT = r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"
pe, raw, _ = load_pe(CLIENT)

PAT = "488b05${'} 4189be"
print("pattern:", PAT)
atoms = c2.parse_pattern(PAT)
for i, a in enumerate(atoms):
    print(f"  atom {i}: {a}")
print("anchor:", c2._anchor(atoms))

# How many raw occurrences of 48 8b 05 exist in .text, and how many of those
# are followed by 41 89 be exactly 7 bytes later?
for w_start, w_end, w_rva in c2.exec_windows(pe, len(raw)):
    print(f"\nexec window file=0x{w_start:X}..0x{w_end:X} rva=0x{w_rva:X}")
    needle = bytes([0x48, 0x8B, 0x05])
    pos, total, followed = w_start, 0, []
    while True:
        hit = raw.find(needle, pos, w_end)
        if hit < 0:
            break
        pos = hit + 1
        total += 1
        if raw[hit + 7:hit + 10] == b"\x41\x89\xbe":
            disp = struct.unpack_from("<i", raw, hit + 3)[0]
            match_rva = w_rva + (hit - w_start)
            dest = match_rva + 7 + disp
            followed.append((match_rva, dest))
    print(f"  48 8b 05 occurrences: {total}")
    print(f"  ...followed by 41 89 be at +7: {len(followed)}")
    for m, d in followed[:10]:
        print(f"    match rva 0x{m:08X}  -> dest rva 0x{d & 0xFFFFFFFF:08X}")
    break

print("\nreference dwLocalPlayerController = 0x2538008")

# Now try our matcher on the same window.
print("\nmatcher result:")
hits = []
for w_start, w_end, w_rva in c2.exec_windows(pe, len(raw)):
    hits.extend(c2.scan_window(atoms, raw, w_start, w_end, w_rva, collect_all=True))
print(f"  {len(hits)} hits")
for h in hits[:10]:
    print(f"    match=0x{h[0]:08X} save={['0x%X' % s for s in h[1]]}")
