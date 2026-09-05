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


# ----- color helper for kawaii error messages -----
def err(msg):
    print(f"\033[91m✗ {msg}\033[0m", file=sys.stderr)

def ok(msg):
    print(f"\033[92m✓ {msg}\033[0m")

def info(msg):
    print(f"\033[96mℹ {msg}\033[0m")


def parse_color(hex_str):
    """'#FF66CC' -> 0xCC66FF (Windows COLORREF is BGR)"""
    h = hex_str.lstrip('#')
    if len(h) != 6:
        return 0x00CC66  # default kawaii pink
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return (b << 16) | (g << 8) | r  # BGR


def _to_int(v):
    """Accept hex string ('0x1234'), int (0x1234), or str int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.startswith(('0x', '0X')):
            return int(s, 16)
        return int(s, 0)
    return int(v)


def render_feature_block(features):
    """Turn the YAML features into C++ Feature struct initializers."""
    lines = []
    for f in features or []:
        name    = f.get('name', 'Unnamed')
        ftype_s = (f.get('type') or 'value').lower()
        is_ptr  = 'pointer' in f
        is_flt  = isinstance(f.get('value'), float) or ftype_s == 'freeze'
        # default width based on type
        width   = f.get('width') or (4 if not is_flt else 4)
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
        # build the init
        if is_ptr:
            # addr=0 at static init; ptr_base and ptr_offsets carry the
            # info we need at runtime to resolve.
            init = (
                f'    {{"{name}", {ftype}, true, '
                f'0ULL, 0ULL, {{{ptr_off_str}}}, 0ULL, '
                f'{val_init}, {val_f_init}, {int(delta)}LL, '
                f'{int(width)}, {str(is_flt).lower()}, '
                f'{str(bool(f.get("default_on", False))).lower()}, '
                f'{int(interval_ms)}}},'
            )
        else:
            init = (
                f'    {{"{name}", {ftype}, false, '
                f'{addr_str}, 0ULL, {{}}, 0ULL, '
                f'{val_init}, {val_f_init}, 0LL, '
                f'{int(width)}, {str(is_flt).lower()}, '
                f'{str(bool(f.get("default_on", False))).lower()}, '
                f'{int(interval_ms)}}},'
            )
        lines.append(init)
    return "\n".join(lines)


def render_action_block(actions):
    lines = []
    for a in actions or []:
        name   = a.get('name', 'Action')
        vk     = a.get('hotkey', 'VK_F1')
        val    = a.get('value', 0)
        width  = a.get('width', 4)
        is_flt = isinstance(val, float)
        # use the pointer's resolved base, or absolute address
        if 'pointer' in a:
            # the trainer walks the chain at action time
            addr_str = "0ULL /* set in runtime */"
        else:
            addr_str = f"0x{int(a.get('address', 0), 16) & 0xFFFFFFFFFFFFFFFF:x}ULL"
        val_init = f"{int(val)}LL" if not is_flt else f"{float(val)}"
        lines.append(
            f'    {{"{name}", {vk}, {addr_str}, '
            f'{val_init}, {int(width)}, {str(is_flt).lower()}}},'
        )
    return "\n".join(lines)


def compile_template(spec, template_cpp, out_cpp):
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
        .replace('{{GAME}}',        spec.get('game', ''))
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
            # escape any quotes
            base_expr_c = base_expr.replace('"', '\\"')
            runtime_init += f'    g_features[{i}].ptr_base = resolve_address(g_proc, g_pid, "{base_expr_c}");\n'
    runtime_init += "}\n"

    # hook it into WinMain before worker thread starts
    rendered = rendered.replace(
        "    CreateThread(nullptr, 0, worker_thread, nullptr, 0, NULL);",
        "    resolve_pointer_bases();\n    CreateThread(nullptr, 0, worker_thread, nullptr, 0, NULL);"
    )
    rendered += runtime_init

    with open(out_cpp, 'w', encoding='utf-8') as f:
        f.write(rendered)
    ok(f"Wrote {out_cpp}")
    return out_cpp


def build_exe(src_cpp, out_exe, gpp):
    cmd = [gpp, '-O2', '-mwindows', '-static', '-o', out_exe, src_cpp,
           '-luser32', '-lgdi32', '-lkernel32']
    info(f"Compiling: {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        err("Compilation failed:")
        print(p.stdout); print(p.stderr)
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

    with open(args.spec, 'r', encoding='utf-8') as f:
        spec = yaml.safe_load(f)
    if not isinstance(spec, dict):
        err("Spec must be a YAML mapping at top level")
        return 1
    name = spec.get('name') or os.path.splitext(os.path.basename(args.spec))[0]

    if args.out_cpp is None:
        args.out_cpp = os.path.join(os.path.dirname(args.spec) or '.',
                                    f"{name}_gen.cpp")
    if args.out_exe is None:
        args.out_exe = os.path.join(os.path.dirname(args.spec) or '.',
                                    f"{name}.exe")

    compile_template(spec, args.template, args.out_cpp)

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