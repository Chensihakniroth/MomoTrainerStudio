"""Quick probe: which Source 2 entity/networkvar strings exist in CS2 client.dll."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evolution_offset_dumper import load_pe, find_pattern, file_off_to_rva, section_name_at_rva

CLIENT = r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"

pe, raw, meta = load_pe(CLIENT)
print(f"client.dll {len(raw)} bytes  ImageBase=0x{pe.OPTIONAL_HEADER.ImageBase:X}")
print(f"sha256 {meta['sha256_short']}  timestamp {meta['pe_timestamp_utc']}")
for sec in pe.sections:
    name = sec.Name.rstrip(b"\0").decode("latin-1")
    print(f"  {name:10s} raw=0x{sec.PointerToRawData:08X} vsize=0x{sec.Misc_VirtualSize:08X}")

NEEDLES = [
    b"m_iHealth", b"m_pGameSceneNode", b"CCSPlayerController", b"CBaseEntity",
    b"m_iTeamNum", b"m_vecAbsOrigin", b"m_flHealth", b"localplayer",
    b"DT_CSPlayerController", b"CCSPlayerPawn", b"m_pInGameMoneyServices",
    b"m_ArmorValue", b"m_bIsScoped", b"CCSPlayer_WeaponServices",
]
print("\n-- string presence (rva / section) --")
for n in NEEDLES:
    off = raw.find(n)
    if off < 0:
        print(f"  {n.decode():32s} NOT FOUND")
        continue
    rva = file_off_to_rva(pe, off)
    print(f"  {n.decode():32s} off=0x{off:08X} rva=0x{rva:08X} sec={section_name_at_rva(pe, rva)}")
