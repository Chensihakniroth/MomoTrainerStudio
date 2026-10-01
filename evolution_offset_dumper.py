#!/usr/bin/env python3
"""
Warframe / Evolution Engine offset dumper v2.

What this tool does:
  * scans a PE with section-aware wildcard patterns;
  * reports every hit as file offset, RVA, VA, and section;
  * refuses to silently choose the first hit of an ambiguous anchor;
  * resolves RIP-relative references with explicit bounds checks;
  * optionally verifies globals against a running Warframe process using the
    real ASLR module base (never the static PE image base);
  * emits a stable JSON report and a compatibility C header.

Evolution Engine is the engine used by Warframe. This tool is intentionally
pattern-library driven: add/replace signatures in patterns.json instead of
hard-coding offsets in the scanner.

Usage:
  python _warframe_offset_dumper.py --binary "D:\\game\\warframe_menu\\bin\\Warframe.x64.exe"
  python _warframe_offset_dumper.py --binary ... --live-pid 12345
  python _warframe_offset_dumper.py --diff old.json new.json
  python _warframe_offset_dumper.py --binary ... --fail-on-unverified

Requires: pefile
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import Any, Iterable

TOOL_VERSION = "2.0.0"
SCHEMA_VERSION = 2
DEFAULT_BINARY = r"D:\game\warframe_menu\bin\Warframe.x64.exe"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PATTERN_FILE = str(SCRIPT_DIR / "evolution_offset_patterns.json")
DEFAULT_OUT_DIR = str(SCRIPT_DIR)
DEFAULT_MODULE_NAME = "Warframe.x64.exe"

# Sections that hold toolchain metadata, never game state. A rip-relative
# reference that lands here is coincidental, not a discovered global.
METADATA_SECTIONS = frozenset({".pdata", ".xdata", ".debug", ".reloc"})


# ---------------------------------------------------------------------------
# PE and pattern primitives
# ---------------------------------------------------------------------------
def hex_to_regex(hexpat: str) -> bytes:
    """Convert an IDA-style 'AA BB ?? CC' pattern to a bytes regex.

    Supported wildcards: '?' and '??'. A wildcard consumes exactly one byte.
    """
    if not isinstance(hexpat, str) or not hexpat.strip():
        raise ValueError("pattern must be a non-empty hex string")
    rx = bytearray()
    for token in hexpat.split():
        if token in ("?", "??"):
            rx.extend(b".")
            continue
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            raise ValueError(f"bad pattern byte {token!r}")
        # Escape literal bytes because values such as 0x28/0x29 are regex
        # metacharacters; only the wildcard token may remain unescaped.
        rx.extend(re.escape(bytes([int(token, 16)])))
    return bytes(rx)


def _section_name(section) -> str:
    return section.Name.rstrip(b"\0").decode("latin-1", "replace")


def _section_ranges(pe, raw_size: int, requested: Iterable[str] | None):
    """Return (name, file_start, file_end) ranges for requested sections."""
    requested_set = {str(x).lower() for x in requested} if requested else None
    for sec in pe.sections:
        name = _section_name(sec)
        if requested_set is not None and name.lower() not in requested_set:
            continue
        start = int(sec.PointerToRawData)
        end = min(raw_size, start + int(sec.SizeOfRawData))
        if end > start:
            yield name, start, end


def find_pattern(data: bytes, hexpat: str, start: int = 0, end: int | None = None):
    """Return all file offsets matching hexpat in [start:end)."""
    rx = hex_to_regex(hexpat)
    end = len(data) if end is None else min(end, len(data))
    start = max(0, start)
    if start >= end:
        return []
    return [m.start() + start for m in re.finditer(re.escape(rx) if False else rx, data[start:end], re.DOTALL)]


def file_off_to_rva(pe, file_off: int) -> int | None:
    for sec in pe.sections:
        start = int(sec.PointerToRawData)
        end = start + int(sec.SizeOfRawData)
        if start <= file_off < end:
            return int(sec.VirtualAddress) + file_off - start
    return None


def section_name_at_rva(pe, rva: int) -> str | None:
    """Name of the section containing `rva`, or None if unmapped."""
    if rva is None:
        return None
    for sec in pe.sections:
        start = int(sec.VirtualAddress)
        end = start + max(int(sec.Misc_VirtualSize), int(sec.SizeOfRawData))
        if start <= rva < end:
            return sec.Name.rstrip(b"\x00").decode("ascii", "replace")
    return None


def rva_to_file_off(pe, rva: int) -> int | None:
    for sec in pe.sections:
        start = int(sec.VirtualAddress)
        end = start + max(int(sec.Misc_VirtualSize), int(sec.SizeOfRawData))
        if start <= rva < end:
            file_off = int(sec.PointerToRawData) + rva - start
            if file_off < int(sec.PointerToRawData) + int(sec.SizeOfRawData):
                return file_off
    return None


def file_off_to_va(pe, file_off: int, image_base: int | None = None) -> int | None:
    rva = file_off_to_rva(pe, file_off)
    if rva is None:
        return None
    return (pe.OPTIONAL_HEADER.ImageBase if image_base is None else image_base) + rva


def load_pe(path: str):
    try:
        import pefile
    except ImportError as exc:
        raise SystemExit("ERROR: pefile not installed. Run: python -m pip install pefile") from exc

    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise SystemExit(f"ERROR: binary not found: {path}")
    raw = Path(path).read_bytes()
    pe = pefile.PE(data=raw, fast_load=False)
    pe.parse_data_directories()
    timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    try:
        timestamp_text = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        timestamp_text = str(timestamp)
    meta = {
        "path": path,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha256_short": hashlib.sha256(raw).hexdigest()[:16],
        "machine": hex(pe.FILE_HEADER.Machine),
        "pe_timestamp": timestamp,
        "pe_timestamp_utc": timestamp_text,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": [
            {
                "name": _section_name(sec),
                "va": hex(sec.VirtualAddress),
                "virtual_size": int(sec.Misc_VirtualSize),
                "raw": hex(sec.PointerToRawData),
                "raw_size": int(sec.SizeOfRawData),
                "entropy": round(sec.get_entropy(), 3),
            }
            for sec in pe.sections
        ],
    }
    return pe, raw, meta


# ---------------------------------------------------------------------------
# Pattern library validation and scanning
# ---------------------------------------------------------------------------
def validate_pattern_library(pattern_lib: dict[str, Any]) -> None:
    if not isinstance(pattern_lib.get("patterns"), list):
        raise SystemExit("ERROR: the pattern library must contain a 'patterns' list")
    seen: set[str] = set()
    for index, pat in enumerate(pattern_lib["patterns"]):
        if not isinstance(pat, dict):
            raise SystemExit(f"ERROR: pattern #{index} is not an object")
        name = pat.get("name")
        if not name or name in seen:
            raise SystemExit(f"ERROR: duplicate/missing pattern name at #{index}: {name!r}")
        seen.add(name)
        try:
            hex_to_regex(pat["hex"])
        except (KeyError, ValueError) as exc:
            raise SystemExit(f"ERROR: invalid pattern {name!r}: {exc}") from exc
        for section in pat.get("sections", []):
            if not isinstance(section, str):
                raise SystemExit(f"ERROR: pattern {name!r} has non-string section")


def classify_hits(actual: int, exp_min: int | None, exp_max: int | None, confidence: str) -> str:
    if actual == 0:
        return "dead"
    if exp_min is None and exp_max is None:
        return "verified_unique_hit" if actual == 1 else "ambiguous_multi_hit"
    if exp_min is not None and actual < exp_min:
        return "fewer_than_expected"
    if exp_max is not None and actual > exp_max:
        return "ambiguous_over_expected"
    if actual == 1:
        return "verified_unique_hit"
    return "verified_multi_hit"


def scan_patterns(pe, raw: bytes, pattern_lib: dict[str, Any], max_hits: int = 200):
    default_sections = pattern_lib.get("scan_defaults", {}).get("sections")
    results = []
    for pat in pattern_lib["patterns"]:
        if pat.get("enabled", True) is False:
            results.append({"name": pat["name"], "status": "disabled", "hits": 0})
            continue
        sections = pat.get("sections", default_sections)
        locs: list[dict[str, Any]] = []
        for section_name, start, end in _section_ranges(pe, len(raw), sections):
            for file_off in find_pattern(raw, pat["hex"], start, end):
                rva = file_off_to_rva(pe, file_off)
                locs.append({
                    "section": section_name,
                    "file": hex(file_off),
                    "rva": hex(rva) if rva is not None else None,
                    "va": hex(file_off_to_va(pe, file_off)) if rva is not None else None,
                })
        locs.sort(key=lambda item: int(item["file"], 16))
        n = len(locs)
        exp_min = pat.get("expected_hits_min", pat.get("expected_hits"))
        exp_max = pat.get("expected_hits_max", pat.get("expected_hits"))
        status = classify_hits(n, exp_min, exp_max, pat.get("confidence", "unknown"))
        first = locs[0] if locs else None
        results.append({
            "name": pat["name"],
            "hex": pat["hex"],
            "sections": sections,
            "confidence": pat.get("confidence", "unknown"),
            "source": pat.get("source", ""),
            "notes": pat.get("notes", ""),
            "hits": n,
            "expected_min": exp_min,
            "expected_max": exp_max,
            "status": status,
            "first_offset_file": first["file"] if first else None,
            "first_offset_rva": first["rva"] if first else None,
            "first_offset_va": first["va"] if first else None,
            "all_offsets_file": [x["file"] for x in locs[:max_hits]],
            "all_offsets_rva": [x["rva"] for x in locs[:max_hits]],
            "all_offsets_va": [x["va"] for x in locs[:max_hits]],
            "hit_sections": sorted({x["section"] for x in locs}),
            "truncated": n > max_hits,
        })
    return results


# ---------------------------------------------------------------------------
# Anchor walking
# ---------------------------------------------------------------------------
def _resolve_one_walk(pe, raw: bytes, walk: dict[str, Any], anchor: dict[str, Any]):
    follow = walk["follow"]
    if follow.get("kind", "i32_le") not in ("i32_le", "u32_le"):
        return {"status": "unsupported_kind", "kind": follow.get("kind")}
    if int(follow.get("size", 4)) != 4:
        return {"status": "unsupported_size", "size": follow.get("size")}
    anchor_file = int(anchor["file"], 16)
    disp_off = anchor_file + int(follow["offset_within_match"])
    if disp_off < 0 or disp_off + 4 > len(raw):
        return {"status": "out_of_bounds", "disp_file": hex(disp_off)}
    disp = struct.unpack_from("<i" if follow.get("kind", "i32_le") == "i32_le" else "<I", raw, disp_off)[0]
    rip_file = anchor_file + int(follow["rip_base_offset_within_match"])
    target_file = rip_file + disp
    target_rva = file_off_to_rva(pe, target_file)
    target_va = file_off_to_va(pe, target_file)
    target_section = section_name_at_rva(pe, target_rva) if target_rva is not None else None
    return {
        "status": "resolved" if target_rva is not None else "target_not_file_backed",
        "anchor_offset_file": anchor["file"],
        "anchor_offset_rva": anchor["rva"],
        "anchor_section": anchor["section"],
        "rip_relative_disp": disp,
        "target_offset_file": hex(target_file),
        "target_offset_rva": hex(target_rva) if target_rva is not None else None,
        "target_offset_va": hex(target_va) if target_va is not None else None,
        "target_section": target_section,
        # A rip-relative LEA in .text pointing at .pdata is almost always
        # landing on the RUNTIME_FUNCTION unwind table (BeginAddress,
        # EndAddress, UnwindInfo) by coincidence of the displacement —
        # never on a game global. Flag it so the candidate list is not
        # padded with 48 identical non-answers.
        "target_is_metadata": target_section in METADATA_SECTIONS,
    }


def walk_anchors(pe, raw: bytes, pattern_lib: dict[str, Any], pattern_results, max_candidates: int = 50):
    by_name = {p["name"]: p for p in pattern_results}
    out = []
    for walk in pattern_lib.get("anchor_walks", []):
        name = walk["name"]
        if walk.get("disabled") or "DO_NOT_USE" in name:
            out.append({"name": name, "status": "disabled", "description": walk.get("description", "")})
            continue
        source = by_name.get(walk.get("from_pattern"))
        if not source or not source.get("all_offsets_file"):
            out.append({"name": name, "status": "skipped_anchor_missing", "from_pattern": walk.get("from_pattern")})
            continue
        candidates = []
        for file_hex, rva_hex, section in zip(
            source.get("all_offsets_file", []),
            source.get("all_offsets_rva", []),
            [None] * len(source.get("all_offsets_file", [])),
        ):
            # The scanner keeps section names separately; recover it when present.
            section = source.get("hit_sections", [None])[0] if len(source.get("hit_sections", [])) == 1 else section
            resolved = _resolve_one_walk(pe, raw, walk, {"file": file_hex, "rva": rva_hex, "section": section})
            resolved["candidate_index"] = len(candidates)
            candidates.append(resolved)
        if len(candidates) == 1:
            item = dict(candidates[0])
            item.update({"name": name, "from_pattern": walk["from_pattern"], "description": walk.get("description", "")})
            out.append(item)
        else:
            # Separate real data targets from coincidences that landed in
            # unwind/debug metadata. Presenting 48 .pdata hits as equals
            # buries the handful that could actually be a global.
            real = [c for c in candidates if not c.get("target_is_metadata")]
            meta = [c for c in candidates if c.get("target_is_metadata")]
            distinct = sorted({c["target_offset_rva"] for c in candidates
                               if c.get("target_offset_rva")})
            out.append({
                "name": name,
                "from_pattern": walk["from_pattern"],
                "description": walk.get("description", ""),
                "status": "ambiguous_anchor",
                "candidate_count": len(candidates),
                "distinct_target_count": len(distinct),
                "data_candidate_count": len(real),
                "metadata_candidate_count": len(meta),
                "distinct_targets": distinct,
                "note": ("%d of %d candidates land in %s (unwind/debug metadata, "
                         "not game state); %d are in data sections"
                         % (len(meta), len(candidates),
                            "/".join(sorted({c.get("target_section") or "?"
                                             for c in meta})) or "metadata",
                            len(real))) if meta else "",
                "candidates": candidates[:max_candidates],
            })
    return out


# ---------------------------------------------------------------------------
# Windows live verification
# ---------------------------------------------------------------------------
def _win_process_api():
    if os.name != "nt":
        return None
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumProcessModules.restype = wintypes.BOOL
    psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    psapi.GetModuleBaseNameW.restype = wintypes.DWORD
    return k32, psapi, wintypes


def runtime_module_base(pid: int, module_name: str = DEFAULT_MODULE_NAME):
    """Return (base, error). Correctly handles 64-bit module addresses."""
    if os.name != "nt":
        return None, "live verification is Windows-only"
    api = _win_process_api()
    if api is None:
        return None, "Windows API unavailable"
    k32, psapi, wintypes = api
    process_query = 0x1000
    process_vm_read = 0x0010
    handle = k32.OpenProcess(process_query | process_vm_read, False, int(pid))
    if not handle:
        return None, f"OpenProcess failed: {ctypes.get_last_error()}"
    try:
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModules(handle, None, 0, ctypes.byref(needed)):
            return None, f"EnumProcessModules size failed: {ctypes.get_last_error()}"
        count = max(1, needed.value // ctypes.sizeof(ctypes.c_void_p))
        modules = (ctypes.c_void_p * count)()
        if not psapi.EnumProcessModules(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            return None, f"EnumProcessModules failed: {ctypes.get_last_error()}"
        for module in modules[:count]:
            buf = ctypes.create_unicode_buffer(260)
            if psapi.GetModuleBaseNameW(handle, module, buf, sizeof := 260):
                if buf.value.lower() == module_name.lower():
                    # Iterating a ctypes array yields plain ints, not
                    # c_void_p, so `module.value` raises AttributeError.
                    base = module if isinstance(module, int) else (module.value or 0)
                    if base:
                        return int(base), None
        return None, f"module not found: {module_name}"
    finally:
        k32.CloseHandle(handle)


def live_read(pid: int, va: int, size: int = 8):
    api = _win_process_api()
    if api is None:
        return None
    k32, _, _ = api
    handle = k32.OpenProcess(0x1000 | 0x0010, False, int(pid))
    if not handle:
        return None
    try:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(int(va)), buf, size, ctypes.byref(got))
        return bytes(buf) if ok and got.value == size else None
    finally:
        k32.CloseHandle(handle)


def _is_plausible_pointer(raw: bytes) -> bool:
    """A user-mode 64-bit pointer is normally non-null and canonical.

    Bits 63:48 must all match bit 47, so anything >= 0x0000800000000000 with
    the top bit set (0xFFFF8xxx...) is kernel space. Real globals live in
    the low canonical range, which is what makes this a cheap filter
    against following a bad displacement into garbage.
    """
    val = int.from_bytes(raw, "little")
    if val == 0:
        return False
    if val >= 0x0000800000000000:
        return False
    if val & 0xFFFF000000000000 == 0xFFFF000000000000:
        return False
    return True


def live_verify(pid: int, walks, module_base: int, module_name: str = DEFAULT_MODULE_NAME):
    """Read every resolved walk target in a live process.

    An `ambiguous_anchor` walk is the interesting case: it has N candidates
    because the byte pattern matched N places. Verifying only walks with
    status == "resolved" would skip every ambiguous walk and return an
    empty result — which is exactly what happened, leaving --live-pid
    silently useless. So ambiguous candidates are read too, and each is
    scored on whether it actually points at readable, plausible memory.
    That turns "52 candidates" into a shortlist you can act on.
    """
    out = []
    for walk in walks:
        status = walk.get("status")
        if status == "resolved" and walk.get("target_offset_rva"):
            entries = [dict(walk, candidate_index=0)]
        elif status == "ambiguous_anchor":
            entries = list(walk.get("candidates", []))
        else:
            continue

        readable = 0
        for entry in entries:
            target_rva = entry.get("target_offset_rva")
            if not target_rva:
                continue
            target_rva = int(target_rva, 16)
            runtime_va = module_base + target_rva
            buf = live_read(pid, runtime_va, 8)
            plausible = bool(buf) and _is_plausible_pointer(buf)
            if buf is not None:
                readable += 1
            out.append({
                "name": walk["name"],
                "status": status,
                "candidate_index": entry.get("candidate_index", 0),
                "candidate_count": walk.get("candidate_count", 1),
                "target_rva": entry.get("target_offset_rva"),
                "runtime_va": hex(runtime_va),
                "live_read_bytes_hex": buf.hex() if buf else None,
                "live_read_ok": buf is not None,
                "plausible_pointer": plausible,
            })

        # A shortlist, not 52 equal rows: only candidates that read AND
        # look like a pointer survive. Report even when NOTHING survives —
        # "checked 3, none plausible" is actionable, silence is not, and a
        # silent empty result is what made this look broken in the first
        # place.
        if status == "ambiguous_anchor" and entries:
            live = [r for r in out if r["name"] == walk["name"]]
            survivors = [r for r in live if r["plausible_pointer"]]
            out.append({
                "name": walk["name"],
                "status": "narrowed" if survivors else "no_survivors",
                "readable_candidates": readable,
                "plausible_candidates": len(survivors),
                "total_candidates": len(entries),
                "hint": (("%d of %d candidates point at plausible user-mode "
                          "memory — inspect these in IDA"
                          % (len(survivors), len(entries))) if survivors else
                         ("none of %d candidates read back a plausible pointer "
                          "(%d were readable) — the pattern is probably wrong "
                          "for this build, or the anchor moved"
                          % (len(entries), readable))),
            })
    return out


# ---------------------------------------------------------------------------
# Header/report output
# ---------------------------------------------------------------------------
def c_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return value if value and not value[0].isdigit() else f"_{value}"


def emit_header(meta, pattern_results, walks, stable_contracts):
    lines = [
        "// ============================================================================",
        "// Evolution Engine / Warframe offsets (AUTO-GENERATED, do not hand-edit)",
        f"// Tool: _warframe_offset_dumper.py v{TOOL_VERSION}",
        f"// Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"// Binary: {meta['path']}",
        f"// SHA-256: {meta['sha256']}",
        f"// ImageBase: {meta['image_base']}",
        "// ============================================================================",
        "#pragma once",
        "#include <stdint.h>",
        "",
        f"#define MW_OWH_BASE_DEFAULT {meta['image_base']}ULL",
        "",
        "// ----- Auto-detected code anchors -----" ,
    ]
    for result in pattern_results:
        ident = c_identifier(result["name"])
        if result["status"] == "verified_unique_hit" and result.get("first_offset_rva"):
            rva = int(result["first_offset_rva"], 16)
            lines.append(f"#define MW_RVA_{ident.upper():<32s} 0x{rva:08X}  // {result['confidence']}")
            lines.append(f"#define MW_OFFSET_{ident.upper():<32s} 0x{rva:08X}  // legacy alias")
        elif result["status"] == "dead":
            lines.append(f"// DEAD: {result['name']} (0 hits)")
        elif result["status"].startswith("ambiguous") or result["status"] == "verified_multi_hit":
            lines.append(f"// AMBIGUOUS: {result['name']} ({result['hits']} hits; inspect candidates)")
            for i, rva in enumerate(result.get("all_offsets_rva", [])[:5]):
                if rva:
                    lines.append(f"//   candidate[{i}]: 0x{int(rva, 16):08X}")
        else:
            lines.append(f"// REVIEW: {result['name']} status={result['status']} hits={result['hits']}")
    lines.extend(["", "// ----- Resolved global anchor walks -----" ])
    for walk in walks:
        ident = c_identifier(walk["name"])
        if walk.get("status") == "resolved" and walk.get("target_offset_rva"):
            rva = int(walk["target_offset_rva"], 16)
            lines.append(f"#define MW_GLOBAL_{ident.upper():<32s} 0x{rva:08X}")
        else:
            lines.append(f"// MW_GLOBAL_{ident.upper()}: status={walk.get('status')}")
    lines.extend(["", "// ----- Stable contracts -----"])
    for contract in stable_contracts:
        for line in contract.get("description", "").splitlines():
            lines.append(f"// {line}")
        lines.append(f"// USE: {contract.get('use', '')}")
        lines.append("")
    lines.extend([
        "// Runtime note: use the loaded Warframe.x64.exe base + RVA.",
        "// The static PE image base is not the runtime base under ASLR.",
        "",
    ])
    return "\n".join(lines)


def atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def diff_reports(old: dict[str, Any], new: dict[str, Any]):
    changes = []
    old_hash = old.get("binary", {}).get("sha256")
    new_hash = new.get("binary", {}).get("sha256")
    if old_hash != new_hash:
        changes.append(f"~ BINARY: {old_hash} -> {new_hash}")
    old_pats = {p["name"]: p for p in old.get("patterns", [])}
    new_pats = {p["name"]: p for p in new.get("patterns", [])}
    for name in sorted(set(old_pats) | set(new_pats)):
        before, after = old_pats.get(name), new_pats.get(name)
        if before is None:
            changes.append(f"+ NEW: {name} ({after.get('status')}, {after.get('hits')} hits)")
        elif after is None:
            changes.append(f"- REMOVED: {name}")
        elif (before.get("first_offset_rva"), before.get("hits"), before.get("status")) != (after.get("first_offset_rva"), after.get("hits"), after.get("status")):
            changes.append(
                f"~ CHANGED: {name}\n"
                f"    old: {before.get('status')} {before.get('hits')} hits @ {before.get('first_offset_rva')}\n"
                f"    new: {after.get('status')} {after.get('hits')} hits @ {after.get('first_offset_rva')}"
            )
        else:
            changes.append(f"  same: {name}")
    return "\n".join(changes)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate Evolution Engine / Warframe offsets")
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--patterns", default=DEFAULT_PATTERN_FILE)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--live-pid", type=int, default=0, help="verify resolved globals in a running Warframe process")
    parser.add_argument("--runtime-base", type=lambda x: int(x, 0), default=0, help="override runtime module base for --live-pid")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_JSON", "NEW_JSON"))
    parser.add_argument("--max-hits", type=int, default=200)
    parser.add_argument("--no-header", action="store_true")
    parser.add_argument("--fail-on-unverified", action="store_true")
    args = parser.parse_args(argv)

    if args.diff:
        old = json.loads(Path(args.diff[0]).read_text(encoding="utf-8"))
        new = json.loads(Path(args.diff[1]).read_text(encoding="utf-8"))
        print(diff_reports(old, new))
        return 0

    pattern_path = Path(args.patterns)
    if not pattern_path.is_file():
        raise SystemExit(f"ERROR: pattern library not found: {pattern_path}")
    pattern_lib = json.loads(pattern_path.read_text(encoding="utf-8"))
    validate_pattern_library(pattern_lib)
    pattern_hash = hashlib.sha256(pattern_path.read_bytes()).hexdigest()
    pe, raw, meta = load_pe(args.binary)
    patterns = scan_patterns(pe, raw, pattern_lib, max(1, args.max_hits))
    walks = walk_anchors(pe, raw, pattern_lib, patterns, max_candidates=max(1, args.max_hits))

    runtime = {"requested": bool(args.live_pid), "pid": args.live_pid or None, "module": DEFAULT_MODULE_NAME}
    live = []
    if args.live_pid:
        module_base = args.runtime_base
        if not module_base:
            module_base, error = runtime_module_base(args.live_pid)
            if error:
                runtime["error"] = error
        if module_base:
            runtime["base"] = hex(module_base)
            live = live_verify(args.live_pid, walks, module_base)
            # Summarize per walk, and only from per-candidate rows. The
            # old code indexed by name and took whichever row came last,
            # which both raised KeyError once summary rows were added and
            # would have promoted a walk to verified_live on the strength
            # of an unrelated candidate.
            per_candidate = [e for e in live
                             if e.get("status") in ("resolved", "ambiguous_anchor")]
            for walk in walks:
                mine = [e for e in per_candidate if e["name"] == walk["name"]]
                if not mine:
                    continue
                if any(e.get("plausible_pointer") for e in mine):
                    walk["status"] = "verified_live"
                    walk["live_plausible_candidates"] = sum(
                        1 for e in mine if e.get("plausible_pointer"))
                elif any(e.get("live_read_ok") for e in mine):
                    # readable, but the bytes are not a usable pointer —
                    # report it rather than claiming a hit
                    walk["status"] = "live_read_no_pointer"

    report = {
        "_comment": "Evolution Engine / Warframe offset dump v2",
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "binary": meta,
        "pattern_library": {"path": str(pattern_path), "sha256": pattern_hash},
        "runtime": runtime,
        "patterns": patterns,
        "anchor_walks": walks,
        "live_verification": live,
        "stable_contracts": pattern_lib.get("stable_contracts", []),
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = out_dir / f"warframe_offsets_{stamp}.json"
    latest_path = out_dir / "warframe_offsets_latest.json"
    header_path = out_dir / "warframe_offsets.h"
    serialized = json.dumps(report, indent=2, sort_keys=True)
    atomic_write(json_path, serialized)
    atomic_write(latest_path, serialized)
    if not args.no_header:
        atomic_write(header_path, emit_header(meta, patterns, walks, report["stable_contracts"]))

    print("=" * 78)
    print("Evolution Engine / Warframe offset dumper v2")
    print("=" * 78)
    print(f"Binary: {meta['path']}")
    print(f"  SHA-256:    {meta['sha256']}")
    print(f"  Image base: {meta['image_base']}")
    print(f"  Size:       {meta['size']:,} bytes")
    print(f"Patterns:    {pattern_path}")
    print()
    print(f"{'pattern':<35s} {'hits':>5s}  {'status':<24s}  first_rva")
    print("-" * 78)
    for result in patterns:
        print(f"  {result['name']:<33s} {result['hits']:>5d}  {result['status']:<24s}  {result.get('first_offset_rva') or '-'}")
    print("\nAnchor walks:")
    for walk in walks:
        if walk.get("status") == "resolved":
            print(f"  {walk['name']:<32s} -> {walk.get('target_offset_rva')} live={walk.get('live_read_ok', 'n/a')}")
        elif walk.get("status") == "ambiguous_anchor":
            meta = walk.get("metadata_candidate_count", 0)
            data = walk.get("data_candidate_count", 0)
            distinct = walk.get("distinct_target_count", 0)
            extra = ""
            if meta:
                extra = (" -> %d distinct targets, %d in data, %d in metadata"
                         % (distinct, data, meta))
            print(f"  {walk['name']:<32s} [AMBIGUOUS: "
                  f"{walk.get('candidate_count')} candidates{extra}]")
        else:
            print(f"  {walk['name']:<32s} [{walk.get('status')}]")
    if args.live_pid:
        print(f"\nLive verification PID {args.live_pid}:")
        if runtime.get("error"):
            print(f"  ERROR: {runtime['error']}")
        for entry in live:
            if entry.get("status") in ("narrowed", "no_survivors"):
                # summary row, not a per-candidate read
                print(f"  {entry['name']:<32s} {entry['hint']}")
                continue
            mark = "OK " if entry["live_read_ok"] else "FAIL"
            ptr = "ptr" if entry.get("plausible_pointer") else ("non-ptr" if entry["live_read_ok"] else "")
            print(f"  {entry['name']:<32s} [{entry.get('candidate_index')}] {mark} "
                  f"{entry.get('live_read_bytes_hex')} {ptr}")
    print(f"\nWrote: {json_path}")
    print(f"Wrote: {latest_path}")
    if not args.no_header:
        print(f"Wrote: {header_path}")

    unverified = [p for p in patterns if p["status"] not in ("verified_unique_hit", "verified_multi_hit", "disabled")]
    if args.fail_on_unverified and unverified:
        print(f"ERROR: {len(unverified)} pattern(s) are dead/ambiguous/review", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
