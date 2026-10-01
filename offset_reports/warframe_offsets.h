// ============================================================================
// Evolution Engine / Warframe offsets (AUTO-GENERATED, do not hand-edit)
// Tool: _warframe_offset_dumper.py v2.0.0
// Generated: 2026-09-24T15:29:04
// Binary: D:\game\warframe_menu\bin\Warframe.x64.exe
// SHA-256: d01b5cb5cff51afc5ffb7d3af051674aafa84000bee764780ff71d9d073cad93
// ImageBase: 0x140000000
// ============================================================================
#pragma once
#include <stdint.h>

#define MW_OWH_BASE_DEFAULT 0x140000000ULL

// ----- Auto-detected code anchors -----
#define MW_RVA_MAININTERFACE                    0x00B4F0D8  // verified_but_misunderstood
#define MW_OFFSET_MAININTERFACE                    0x00B4F0D8  // legacy alias
#define MW_RVA_IS_AVATAR_FRIENDLY_PROLOGUE      0x01284939  // verified
#define MW_OFFSET_IS_AVATAR_FRIENDLY_PROLOGUE      0x01284939  // legacy alias
// DEAD: is_avatar_friendly_vtable_call (0 hits)
// AMBIGUOUS: lea_to_global_singleton (52 hits; inspect candidates)
//   candidate[0]: 0x001D8310
//   candidate[1]: 0x0032BF8F
//   candidate[2]: 0x0038F3A3
//   candidate[3]: 0x004FFDB2
//   candidate[4]: 0x00571F5D
#define MW_RVA_MOV_RCX_RIP_GLOBAL               0x01D63340  // heuristic
#define MW_OFFSET_MOV_RCX_RIP_GLOBAL               0x01D63340  // legacy alias
// REVIEW: xmm_movaps_subps_movaps status=fewer_than_expected hits=4

// ----- Resolved global anchor walks -----
// MW_GLOBAL_FROM_MAININTERFACE_WRONG_DO_NOT_USE: status=disabled
// MW_GLOBAL_LEA_RDX_GLOBAL_CANDIDATE: status=ambiguous_anchor

// ----- Stable contracts -----
// Warframe.x64.exe is ASLR-backed. Static PE ImageBase is not the runtime address; resolve the loaded module base first, then add the RVA.
// USE: runtime_address = GetModuleBase(Warframe.x64.exe) + generated_rva

// Every C++ object with virtual methods has its vtable pointer at offset 0. This layout is more stable than a build-specific RVA.
// USE: Read 8 bytes at object_address + 0, then inspect the vtable only after confirming the object type.

// Entity containers may contain pointer indirection. Confirm each dereference in the current build before treating it as an entity pointer.
// USE: Read and validate every pointer before following it; do not assume a forum chain is still current.

// A unique byte-pattern hit proves bytes, not meaning. Confirm the function, callers, object layout, and live values in IDA/runtime before shipping an offset.
// USE: Mark patterns as candidates until semantic and live verification agree.

// Runtime note: use the loaded Warframe.x64.exe base + RVA.
// The static PE image base is not the runtime base under ASLR.
