"""
trainer_compiler.py - Turn a YAML trainer spec into a standalone .exe
made by Momo aka Steav Beoung Salang

Reads:
  - templates/trainer_template.cpp
  - trainers/<name>.yaml  (or any .yaml you point at)

Writes:
  - trainers/<name>_gen.cpp  (filled-in template)
  - trainers/<name>.exe      (compiled standalone trainer, optional)

Usage:
  python trainer_compiler.py trainers/my_game.yaml            # generate .cpp only
  python trainer_compiler.py trainers/my_game.yaml --build    # also compile .exe
  python trainer_compiler.py trainers/my_game.yaml --build --g++ "C:/mingw64/bin/g++.exe"
"""

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:
    print("Missing dependency: PyYAML. Install with:")
    print("  pip install pyyaml")
    sys.exit(2)


FEATURE_TYPES = {'value', 'freeze', 'nudge'}
VALUE_WIDTHS = {1, 2, 4, 8}
MAX_SIGNATURE_BYTES = 64


def _cpp_string(value):
    """Return a safely escaped C++ string literal."""
    return json.dumps(str(value), ensure_ascii=True)


def _validated_width(value, field='width'):
    try:
        width = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be one of 1, 2, 4, or 8 bytes") from exc
    if width not in VALUE_WIDTHS:
        raise ValueError(f"{field} must be one of 1, 2, 4, or 8 bytes")
    return width


def _validated_number(value, field, integer=False):
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric, not boolean")
    try:
        result = int(value) if integer else float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if isinstance(result, float) and not math.isfinite(result):
        raise ValueError(f"{field} must be finite")
    return result


def validate_spec(spec):
    """Validate a trainer spec and return it unchanged for rendering.

    YAML is user-editable, so fail before generating C++ with a field-specific
    message instead of producing a trainer that silently does nothing.
    """
    if not isinstance(spec, dict):
        raise ValueError("Spec must be a YAML mapping at top level")
    for key in ('features', 'actions'):
        value = spec.get(key, [])
        if value is None:
            spec[key] = []
        elif not isinstance(value, list):
            raise ValueError(f"{key} must be a list")
    for index, feature in enumerate(spec.get('features', [])):
        if not isinstance(feature, dict):
            raise ValueError(f"features[{index}] must be a mapping")
        name = feature.get('name', 'Unnamed')
        if not str(name).strip():
            raise ValueError(f"features[{index}].name cannot be empty")
        ftype = str(feature.get('type') or 'value').lower()
        if ftype not in FEATURE_TYPES:
            raise ValueError(
                f"features[{index}].type {ftype!r} is invalid; use value, freeze, or nudge")
        if 'pointer' in feature:
            pointer = feature['pointer']
            if not isinstance(pointer, dict) or not str(pointer.get('base', '')).strip():
                raise ValueError(f"features[{index}].pointer.base is required")
            offsets = pointer.get('offsets', [])
            if not isinstance(offsets, list):
                raise ValueError(f"features[{index}].pointer.offsets must be a list")
            for off in offsets:
                _validated_number(off, f"features[{index}].pointer offset", integer=True)
        elif 'address' not in feature:
            raise ValueError(f"features[{index}] needs an address or pointer")
        _validated_width(feature.get('width', 4), f"features[{index}].width")
        _validated_number(feature.get('interval_ms', 16),
                          f"features[{index}].interval_ms", integer=True)
        if int(feature.get('interval_ms', 16)) < 1:
            raise ValueError(f"features[{index}].interval_ms must be at least 1")
        _validated_number(feature.get('delta', 0), f"features[{index}].delta", integer=True)
        value = feature.get('value', 0)
        if isinstance(value, float):
            _validated_number(value, f"features[{index}].value")
        else:
            _validated_number(value, f"features[{index}].value", integer=True)
        if feature.get('signature'):
            from memory_scanner import parse_signature
            try:
                pattern, _ = parse_signature(feature['signature'])
            except ValueError as exc:
                raise ValueError(f"features[{index}].signature: {exc}") from exc
            if not pattern:
                raise ValueError(f"features[{index}].signature cannot be empty")
            if len(pattern) > MAX_SIGNATURE_BYTES:
                raise ValueError(
                    f"features[{index}].signature is {len(pattern)} bytes; maximum is {MAX_SIGNATURE_BYTES}")
    for index, action in enumerate(spec.get('actions', [])):
        if not isinstance(action, dict):
            raise ValueError(f"actions[{index}] must be a mapping")
        if not str(action.get('name', 'Action')).strip():
            raise ValueError(f"actions[{index}].name cannot be empty")
        if not str(action.get('hotkey', 'VK_F1')).strip():
            raise ValueError(f"actions[{index}].hotkey cannot be empty")
        if 'pointer' not in action and 'address' not in action:
            raise ValueError(f"actions[{index}] needs an address or pointer")
        _validated_width(action.get('width', 4), f"actions[{index}].width")
        _validated_number(action.get('value', 0), f"actions[{index}].value",
                          integer=not isinstance(action.get('value', 0), float))
    return spec


# ----- color helper for kawaii error messages -----
def err(msg):
    print(f"\033[91m✗ {msg}\033[0m", file=sys.stderr)

def ok(msg):
    print(f"\033[92m✓ {msg}\033[0m")

def info(msg):
    print(f"\033[96mℹ {msg}\033[0m")


def parse_color(hex_str):
    """'#FF66CC' -> 0xCC66FF (Windows COLORREF is BGR)"""
    default = 0xCC66FF  # #FF66CC in Windows COLORREF (BGR) order
    if not isinstance(hex_str, str):
        return default

    h = hex_str.strip().lstrip('#')
    if len(h) != 6 or not re.fullmatch(r'[0-9a-fA-F]{6}', h):
        return default

    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return (b << 16) | (g << 8) | r  # BGR


def _to_int(v):
    """Accept hex string ('0x1234' or '1234'), int (0x1234), or str int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(('0x', '0X')):
            return int(s, 16)
        try:
            return int(s)
        except ValueError:
            # Try hex interpretation without prefix
            return int(s, 16) if all(c in '0123456789abcdefABCDEF' for c in s) else 0
    return int(v)


def render_feature_block(features):
    """Turn the YAML features into C++ Feature struct initializers."""
    lines = []
    for index, f in enumerate(features or []):
        if not isinstance(f, dict):
            raise ValueError(f"features[{index}] must be a mapping")
        name    = f.get('name', 'Unnamed')
        ftype_s = (f.get('type') or 'value').lower()
        if ftype_s not in FEATURE_TYPES:
            raise ValueError(f"features[{index}].type {ftype_s!r} is invalid")
        is_ptr  = 'pointer' in f
        is_flt  = isinstance(f.get('value'), float) or ftype_s == 'freeze'
        # default width based on type
        width   = _validated_width(f.get('width') or 4, f"features[{index}].width")
        interval_ms = f.get('interval_ms', 16)
        value   = f.get('value', 0)
        delta   = f.get('delta', 0)
        # resolve pointer chain fields at template time as placeholders
        if is_ptr:
            base_expr = f['pointer']['base']
            offsets   = f['pointer'].get('offsets', [])
            addr_str  = "0 /* set in runtime */"
            ptr_base  = "/* resolved at runtime */"
            ptr_off_str = ", ".join(f"0x{_to_int(o) & 0xFFFFFFFFFFFFFFFF:x}ULL" for o in offsets)
        else:
            addr_str = f"0x{_to_int(f.get('address', 0)) & 0xFFFFFFFFFFFFFFFF:x}ULL"
            base_expr = None
            offsets = []
            ptr_off_str = ""
        # --- NEW: sigscan support ---
        # If 'signature' is set, we embed the bytes/mask and use
        # signature_scan() at runtime. 'address' can also be set as
        # a fast-path hint (the last known location) to avoid re-scanning.
        sig_len = 0
        sig_byte_init = ", ".join("0x00" for _ in range(64))
        sig_mask_init = ", ".join("false" for _ in range(64))
        if 'signature' in f and f['signature']:
            from memory_scanner import parse_signature
            try:
                pat_bytes, pat_mask = parse_signature(f['signature'])
            except ValueError as exc:
                raise ValueError(f"features[{index}].signature: {exc}") from exc
            sig_len = len(pat_bytes)
            if sig_len > MAX_SIGNATURE_BYTES:
                raise ValueError(
                    f"features[{index}].signature exceeds {MAX_SIGNATURE_BYTES} bytes")
            sig_byte_init = ", ".join(f"0x{b:02X}" for b in pat_bytes)
            if sig_len < MAX_SIGNATURE_BYTES:
                sig_byte_init += ", " + ", ".join("0x00" for _ in range(MAX_SIGNATURE_BYTES - sig_len))
            sig_mask_init = ", ".join("true" if m else "false" for m in pat_mask)
            if sig_len < MAX_SIGNATURE_BYTES:
                sig_mask_init += ", " + ", ".join("false" for _ in range(MAX_SIGNATURE_BYTES - sig_len))
        # type enum
        ftype = {'value': 'FType::VALUE',
                 'freeze': 'FType::FREEZE',
                 'nudge': 'FType::NUDGE'}.get(ftype_s, 'FType::VALUE')
        # value handling: cast int to int64_t for the union
        if is_flt:
            val_init = f"static_cast<int64_t>(0)"
            val_f_init = f"{float(value)}"
        else:
            val_init = f"{int(value)}LL"
            val_f_init = "0.0"
        # has_sig flag (only for non-pointer features with a signature)
        has_sig = bool(sig_len) and not is_ptr
        # build the init
        if is_ptr:
            init = (
                 f'    {{{_cpp_string(name)}, {ftype}, true, '
                f'0ULL, 0ULL, {{{ptr_off_str}}}, 0ULL, '
                f'{val_init}, {val_f_init}, {int(delta)}LL, '
                f'{int(width)}, {str(is_flt).lower()}, '
                f'{str(bool(f.get("default_on", False))).lower()}, '
                f'{int(interval_ms)}, '
                f'{str(has_sig).lower()}, '
                f'{sig_len}, '
                f'{{{sig_byte_init}}}, '
                f'{{{sig_mask_init}}}}},'
            )
        else:
            init = (
                f'    {{{_cpp_string(name)}, {ftype}, false, '
                f'{addr_str}, 0ULL, {{}}, 0ULL, '
                f'{val_init}, {val_f_init}, 0LL, '
                f'{int(width)}, {str(is_flt).lower()}, '
                f'{str(bool(f.get("default_on", False))).lower()}, '
                f'{int(interval_ms)}, '
                f'{str(has_sig).lower()}, '
                f'{sig_len}, '
                f'{{{sig_byte_init}}}, '
                f'{{{sig_mask_init}}}}},'
            )
        lines.append(init)
    return "\n".join(lines)


def render_action_block(actions):
    lines = []
    for index, a in enumerate(actions or []):
        if not isinstance(a, dict):
            raise ValueError(f"actions[{index}] must be a mapping")
        name   = a.get('name', 'Action')
        vk     = a.get('hotkey', 'VK_F1')
        val    = a.get('value', 0)
        width  = _validated_width(a.get('width', 4), f"actions[{index}].width")
        is_flt = isinstance(val, float)
        # use the pointer's resolved base, or absolute address
        if 'pointer' in a:
            # the trainer walks the chain at action time
            addr_str = "0ULL /* set in runtime */"
        else:
            addr_raw = a.get('address', 0)
            addr_val = _to_int(addr_raw) if addr_raw else 0
            addr_str = f"0x{addr_val & 0xFFFFFFFFFFFFFFFF:x}ULL"
        val_init = f"{int(val)}LL" if not is_flt else f"{float(val)}"
        lines.append(
            f'    {{{_cpp_string(name)}, {vk}, {addr_str}, '
            f'{val_init}, {int(width)}, {str(is_flt).lower()}}},'
        )
    return "\n".join(lines)


def compile_template(spec, template_cpp, out_cpp):
    validate_spec(spec)
    with open(template_cpp, 'r', encoding='utf-8') as f:
        tmpl = f.read()

    feats = render_feature_block(spec.get('features', []))
    acts  = render_action_block(spec.get('actions', []))
    hk_t  = spec.get('hotkey_toggle', 'VK_F8')
    hk_p  = spec.get('hotkey_panic',  'VK_END')
    win   = spec.get('window_size', [420, 320])
    color = parse_color(spec.get('window_title_color', '#FF66CC'))

    rendered = (tmpl
        .replace('// {{FEATURES_BEGIN}}\n    // {{FEATURES_END}}',
                 f'// {{FEATURES_BEGIN}}\n{feats}\n    // {{FEATURES_END}}')
        .replace('// {{ACTIONS_BEGIN}}\n    // {{ACTIONS_END}}',
                 f'// {{ACTIONS_BEGIN}}\n{acts}\n    // {{ACTIONS_END}}')
        .replace('{{GAME}}',        _cpp_string(spec.get('game', ''))[1:-1])
        .replace('{{HOTKEY_TOGGLE}}', f'vk_from_name("{hk_t}")')
        .replace('{{HOTKEY_PANIC}}',  f'vk_from_name("{hk_p}")')
        .replace('{{WIN_W}}', str(int(win[0])))
        .replace('{{WIN_H}}', str(int(win[1])))
        .replace('{{WIN_COLOR}}', f'0x{color:06X}U')
    )

    # resolve pointer bases at runtime: we patch g_features[*].ptr_base
    # by emitting a small runtime block. Easier: do it in C++ via a
    # runtime helper. Append it.
    runtime_init = """
// ============================================================
// Runtime pointer resolution (injected by trainer_compiler.py)
// ============================================================
static void resolve_pointer_bases() {
"""
    for i, feat in enumerate(spec.get('features', [])):
        if 'pointer' in feat:
            base_expr = feat['pointer']['base']
            # Use the same escaping rules as all generated C++ strings.
            base_expr_c = _cpp_string(base_expr)[1:-1]
            runtime_init += f'    g_features[{i}].ptr_base = resolve_address(g_proc, g_pid, "{base_expr_c}");\n'
    runtime_init += "}\n"

    # hook it into WinMain before worker thread starts
    rendered = rendered.replace(
        "    gather_modules();\n    CreateThread(nullptr, 0, worker_thread, nullptr, 0, NULL);",
        "    gather_modules();\n    init_sigscan_features();\n    CreateThread(nullptr, 0, worker_thread, nullptr, 0, NULL);"
    )
    rendered = rendered.replace(
        "static void init_sigscan_features();  // injected by trainer_compiler.py",
        "static void init_sigscan_features();  // injected by trainer_compiler.py\n"
        "static void resolve_pointer_bases(); // injected by trainer_compiler.py"
    )
    rendered = rendered.replace(
        "            if (!g_proc) { g_pid = 0; continue; }",
        "            if (!g_proc) { g_pid = 0; continue; }\n"
        "            gather_modules();\n"
        "            resolve_pointer_bases();"
    )

    # runtime init for sigscan features: set embedded addr + signature bytes
    sigscan_runtime_init = """
// ============================================================
// Sigscan feature initialization (injected by trainer_compiler.py)
// ============================================================
static void init_sigscan_features() {
"""
    for i, feat in enumerate(spec.get('features', [])):
        if 'signature' in feat and feat['signature'] and 'pointer' not in feat:
            from memory_scanner import parse_signature
            sig_bytes, _ = parse_signature(feat['signature'])
            sigscan_runtime_init += f'    g_features[{i}].has_signature = true;\n'
            sigscan_runtime_init += f'    g_features[{i}].sig_len = {len(sig_bytes)};\n'
            addr = feat.get('address', '0')
            addr_val = _to_int(addr) if addr else 0
            sigscan_runtime_init += f'    g_features[{i}].addr = 0x{addr_val & 0xFFFFFFFFFFFFFFFF:x}ULL;\n'
    sigscan_runtime_init += "}\n"
    rendered += sigscan_runtime_init
    rendered += runtime_init

    out_dir = os.path.dirname(os.path.abspath(out_cpp))
    os.makedirs(out_dir, exist_ok=True)
    with open(out_cpp, 'w', encoding='utf-8') as f:
        f.write(rendered)
    ok(f"Wrote {out_cpp}")
    return out_cpp


def build_exe(src_cpp, out_exe, gpp):
    cmd = [gpp, '-O2', '-mwindows', '-static', '-o', out_exe, src_cpp,
           '-luser32', '-lgdi32', '-lkernel32']
    info(f"Compiling: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        err(f"Could not run compiler: {exc}")
        return False
    if p.returncode != 0:
        err("Compilation failed:")
        print(p.stdout); print(p.stderr)
        return False
    if not os.path.isfile(out_exe):
        err(f"Compiler reported success but output was not created: {out_exe}")
        return False
    sz = os.path.getsize(out_exe)
    ok(f"Built {out_exe} ({sz:,} bytes)")
    return True


def main():
    ap = argparse.ArgumentParser(description="Compile a YAML trainer spec into a .exe")
    ap.add_argument('spec', help='path to .yaml trainer spec')
    ap.add_argument('--build', action='store_true', help='compile to .exe after generating .cpp')
    ap.add_argument('--g++',  default='g++', help='path to g++ (default: g++ in PATH)')
    ap.add_argument('--template', default='templates/trainer_template.cpp',
                    help='path to C++ template')
    ap.add_argument('--out-cpp',  default=None, help='output .cpp path (default: <spec>_gen.cpp)')
    ap.add_argument('--out-exe',  default=None, help='output .exe path (default: <spec_stem>.exe)')
    args = ap.parse_args()

    if not os.path.isfile(args.spec):
        err(f"Spec not found: {args.spec}")
        return 1

    if not os.path.isfile(args.template):
        err(f"Template not found: {args.template}")
        return 1

    try:
        with open(args.spec, 'r', encoding='utf-8') as f:
            spec = yaml.safe_load(f)
        validate_spec(spec)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        err(f"Invalid trainer spec: {exc}")
        return 1
    name = spec.get('name') or os.path.splitext(os.path.basename(args.spec))[0]

    if args.out_cpp is None:
        args.out_cpp = os.path.join(os.path.dirname(args.spec) or '.',
                                    f"{name}_gen.cpp")
    if args.out_exe is None:
        args.out_exe = os.path.join(os.path.dirname(args.spec) or '.',
                                    f"{name}.exe")

    try:
        compile_template(spec, args.template, args.out_cpp)
    except (OSError, ValueError) as exc:
        err(f"Could not generate C++: {exc}")
        return 1

    if args.build:
        gpp = getattr(args, 'g++')
        if not shutil.which(gpp) and not os.path.isfile(gpp):
            err(f"g++ not found: {gpp}")
            return 1
        if not build_exe(args.out_cpp, args.out_exe, gpp):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
