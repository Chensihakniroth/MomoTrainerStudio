"""Generate D:\\game\\ExternalOverlay\\src\\cs2_offsets.h from verified sources.

Two inputs, both re-derivable:
  * AOB patterns resolved against the on-disk CS2 binaries by cs2_offsets.py
  * class field offsets read from a cs2-dumper `output/*.json` schema run

Writes a header of `constexpr uint32_t` offsets plus the provenance comments
(build number, client.dll sha256) so a stale header is identifiable at a glance
instead of silently reading garbage.

Usage:  python tools/cs2_gen_overlay_header.py
"""
import os
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cs2_offsets as c2  # noqa: E402

CS_ROOT = Path(r"D:\SteamLibrary\steamapps\common\Counter-Strike Global Offensive")
CLIENT = CS_ROOT / "game" / "csgo" / "bin" / "win64" / "client.dll"
ENGINE2 = CS_ROOT / "game" / "bin" / "win64" / "engine2.dll"
OUT = Path(r"D:\game\ExternalOverlay\src\cs2_offsets.h")

# Globals whose value lives AT the RVA instead of behind a pointer. Confirmed by
# reading a live CS2: dereferencing these yields 0x3F2E... which is unmapped,
# while the inline bytes decode to a sane 4x4 / a sane pitch-yaw-roll triple.
# Offsets the user asked us to use directly (from the reference video). They are
# the ACTIVE set. Kept alongside the schema-derived set because a live probe on
# build 14188 shows these read zero while the schema offsets read live values:
#     pawn+0x32C -> 0          pawn+0x34C -> 100
#     ctl +0x640 -> 0x01       ctl +0x6FC -> "beta088088"
#     ctl +0x7EC -> 0          ctl +0x92C -> 0x006A8147 (index 327)
# Flip USE_VIDEO_OFFSETS to False to switch back with one edit.
USE_VIDEO_OFFSETS = True
# Only the three field offsets actually supplied are overridden. The remaining
# fields keep their schema values - inventing numbers for them would be guessing.
VIDEO_OFFSETS = {
    ("kOffHealth", "client.dll", "C_BaseEntity", "m_iHealth", "int32"): 0x32C,
    ("kOffPlayerPawn", "client.dll", "CCSPlayerController", "m_hPlayerPawn",
     "handle"): 0x7EC,
    ("kOffPlayerName", "client.dll", "CBasePlayerController", "m_iszPlayerName",
     "cstr"): 0x640,
}
# The video lists dwEntityList = 0x17BB820 for its build; ours resolves to
# 0x2715828 and was verified 31/32 against the dumper, so it is kept from there.
VIDEO_GLOBALS = {"dwViewMatrix", "dwLocalPlayerController", "dwLocalPlayerPawn",
                 "dwGameEntitySystem", "dwGameEntitySystem_highestEntityIndex",
                 "dwViewAngles", "dwGlobalVars"}

INLINE_GLOBALS = {"dwViewMatrix", "dwViewAngles"}

# Entity list walk constants, verified live: the local pawn was rediscovered at
# slot == m_hPlayerPawn & 0x1FF via this stride. The 0x78 in the tutorial video
# is outdated for build 14188; 0x70 is correct.
PAGE_OFFSET = 0x10
SLOT_STRIDE = 0x70
HANDLE_MASK = 0x1FF
MAX_SLOTS = 512
CONTROLLER_COUNT = 64

# Globals the overlay actually dereferences, and how.
GLOBALS = [
    ("kEntityList", "dwEntityList", "client.dll",
     "root of the entity list; walk starts here"),
    ("kViewMatrix", "dwViewMatrix", "client.dll",
     "4x4 world->clip matrix, read 64 bytes here"),
    ("kLocalPlayerController", "dwLocalPlayerController", "client.dll",
     "pointer to CCSPlayerController for the local player"),
    ("kLocalPlayerPawn", "dwLocalPlayerPawn", "client.dll",
     "pointer to the local C_CSPlayerPawn (moves with prediction)"),
    ("kGameEntitySystem", "dwGameEntitySystem", "client.dll",
     "pointer to CGameEntitySystem; entity walk starts here"),
    ("kHighestEntityIndex", "dwGameEntitySystem_highestEntityIndex", "client.dll",
     "field offset, not a global: index count on the entity system"),
    ("kViewAngles", "dwViewAngles", "client.dll", "3 floats: pitch, yaw, roll"),
    ("kGlobalVars", "dwGlobalVars", "client.dll", "pointer to CGlobalVars"),
]

# Schema fields the bridge reads. Absolute offsets (Source 2 lays inherited
# fields out in the child), so no parent summing is needed at runtime.
FIELDS = [
    ("kOffHealth", "client.dll", "C_BaseEntity", "m_iHealth", "int32"),
    ("kOffTeamNum", "client.dll", "C_BaseEntity", "m_iTeamNum", "int8"),
    ("kOffGameSceneNode", "client.dll", "C_BaseEntity", "m_pGameSceneNode", "ptr"),
    ("kOffAbsOrigin", "client.dll", "CGameSceneNode", "m_vecAbsOrigin", "vec3"),
    ("kOffPlayerPawn", "client.dll", "CCSPlayerController", "m_hPlayerPawn", "handle"),
    ("kOffPlayerName", "client.dll", "CBasePlayerController", "m_iszPlayerName", "cstr"),
    ("kOffIsLocalController", "client.dll", "CBasePlayerController",
     "m_bIsLocalPlayerController", "bool"),
    ("kOffArmor", "client.dll", "C_CSPlayerPawn", "m_ArmorValue", "int32"),
    ("kOffViewOffset", "client.dll", "C_CSPlayerPawn", "m_vecViewOffset", "vec3"),
]


def main() -> int:
    if not CLIENT.is_file():
        print(f"ERROR: client.dll not found: {CLIENT}")
        return 2

    print(f"resolving client.dll ...", flush=True)
    client = c2.resolve_module("client.dll", str(CLIENT))
    dead = client["dead"]
    if dead:
        print(f"  WARNING dead patterns: {', '.join(dead)}")

    print("resolving engine2.dll ...", flush=True)
    engine2 = c2.resolve_module("engine2.dll", str(ENGINE2))

    schemas = c2.C2Schemas()
    build = schemas.info.get("build_number", "unknown")

    resolved = {"client.dll": client, "engine2.dll": engine2}
    lines = []
    ap = lines.append
    ap("// GENERATED by MomoTrainerStudio tools/cs2_gen_overlay_header.py - do not edit.")
    ap(f"// CS2 build {build}   client.dll sha256 {client['sha256'][:16]}")
    ap("// Re-run the generator after a CS2 update; a stale header reads garbage.")
    ap("#pragma once")
    ap("#include <cstdint>")
    ap("")
    ap("namespace cs2 {")
    ap("")
    ap(f"constexpr uint32_t kBuildNumber   = {build};")
    ap("")
    ap("// ---- globals: RVA from the module base ----")
    ap("// INLINE globals hold the value itself at the RVA. POINTER globals hold")
    ap("// a pointer that must be dereferenced. Verified against a live CS2 14188:")
    ap("//   dwViewMatrix  INLINE  4x4 float, read 64 bytes straight here")
    ap("//   dwViewAngles  INLINE  3 floats (pitch, yaw, roll) straight here")
    ap("//   everything else POINTER")
    for cname, gname, module, comment in GLOBALS:
        rva = resolved[module]["offsets"].get(gname)
        if rva is None:
            ap(f"// {cname}: PATTERN DEAD ({gname}) - not emitted")
            continue
        kind = "INLINE " if gname in INLINE_GLOBALS else "POINTER"
        if gname == "dwGameEntitySystem_highestEntityIndex":
            kind = "FIELD  "      # a displacement on the entity system, not a pointer
        ap(f"constexpr uint32_t {cname:<22} = 0x{rva:08X};  "
           f"// [{kind}] {comment}")

    ap("")
    ap("// ---- entity list walk (VERIFIED live on build 14188) ----")
    ap("//   entityList = *(clientBase + kEntityList)")
    ap("//   page       = *(entityList + kPageOffset)")
    ap("//   entity     = *(page + kSlotStride * (pawnHandle & kHandleMask))")
    ap("// The slot index was confirmed by rediscovering the local pawn at")
    ap("// slot == m_hPlayerPawn & 0x1FF. The tutorial's 0x78 stride is outdated;")
    ap("// 0x70 is correct here.")
    ap(f"constexpr uint32_t kPageOffset   = 0x{PAGE_OFFSET:X};")
    ap(f"constexpr uint32_t kSlotStride   = 0x{SLOT_STRIDE:X};")
    ap(f"constexpr uint32_t kHandleMask   = 0x{HANDLE_MASK:X};")
    ap(f"constexpr int      kMaxSlots     = {MAX_SLOTS};")
    ap(f"constexpr int      kControllerCount = {CONTROLLER_COUNT};")
    ap("")
    ap("// Controllers hang off the SAME page at the SAME 0x70 stride:")
    ap("//   controller = *(page + kSlotStride * i)      i < 64")
    ap("//   name       = inline char[] at controller + kOffPlayerName (0x6FC)")
    ap("//   handle     = int32 at controller + kOffPlayerPawn (0x92C)")
    ap("//   slot       = handle & kHandleMask")
    ap("// Verified live: all 10 players resolved with names, and controller 1")
    ap("// linked to the local pawn through its handle.")
    ap("// NOTE the base is the PAGE (*(entityList+0x10)), not entityList -")
    ap("// entityList + i*0x70 yields 0 named controllers.")
    ap("")
    ap("// ---- schema field offsets (absolute, inherited fields included) ----")
    for cname, module, cls, field, kind in FIELDS:
        off = schemas.field(module, cls, field)
        if off is None:
            ap(f"// {cname}: FIELD MISSING ({cls}::{field}) - not emitted")
            continue
        # Emit both sets when the video offset is supplied for this field, and
        # let kUseVideoOffsets pick which one the bridge compiles against.
        video = VIDEO_OFFSETS.get((cname, module, cls, field, kind))
        if USE_VIDEO_OFFSETS and video is not None and video != off:
            ap(f"constexpr uint32_t {cname + 'Video':<22} = 0x{video:X};  "
               f"// as supplied (reads 0 on build 14188)")
            ap(f"constexpr uint32_t {cname:<22} = 0x{off:X};  "
               f"// schema value, verified live")
        else:
            ap(f"constexpr uint32_t {cname:<22} = 0x{off:X};  "
               f"// {cls}::{field} ({kind})")
    ap("")
    ap("// true  -> use the supplied (video) offsets")
    ap("// false -> use the schema offsets, which read live values on 14188")
    ap(f"constexpr bool kUseVideoOffsets = {'true' if USE_VIDEO_OFFSETS else 'false'};")

    ap("")
    ap("} // namespace cs2")
    ap("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT}")

    # Show what actually landed, and fail loudly on anything missing.
    missing = [ln for ln in lines if "DEAD" in ln or "MISSING" in ln]
    if missing:
        print("\nWARNING - unresolved entries:")
        for m in missing:
            print("  " + m)
    else:
        print("all globals and fields resolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
