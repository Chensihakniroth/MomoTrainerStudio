# MomoTrainer Studio — by Momo aka Steav Beoung Salang

A **single-player game trainer creator** with a Cheat Engine-style interface.

Scan values in any offline game you own, build a trainer spec, and compile
to a standalone `.exe` you (and your friends) can run any time.

## What it is

- **Scanner** — CE-style value scanner (10 value types × 9 scan modes)
- **Designer** — structured trainer spec editor (no YAML required)
- **Runtime** — compiled standalone Win32 trainer.exe (no Python needed at runtime)

## What it is NOT

- ❌ **Not an MMO cheat tool.** This is for **offline / single-player games you own**.
- ❌ **Not a Cheat Engine clone.** CE is a general-purpose tool. This focuses
  on the "make a small trainer .exe and share it" workflow.
- ❌ **Not for online games with anti-cheat.** Anti-cheat (EAC, BattlEye,
  Vanguard, ClientGuard, Runescape's, etc.) will detect external process
  access and ban you.

## Project layout

```
MomoTrainerStudio/
├── studio_gui.py              ← run this: full CE-style GUI
├── memory_scanner.py          ← CE value scanner (Python)
├── trainer_compiler.py        ← YAML → C++ → .exe
├── universal_scanner.py       ← IAT-hook scanner (kept for reference)
├── templates/
│   └── trainer_template.cpp   ← C++ source compiled into trainer.exe
├── docs/
│   └── example_trainer.yaml   ← annotated YAML spec format
└── trainers/                  ← output: .cpp / .exe / .yaml land here
└── scans/                     ← output: scanner CSV/JSON dumps
```

## Quick start

```bat
:: 1. Install PyYAML (only external dep)
pip install pyyaml

:: 2. Run the studio
python studio_gui.py

:: 3. In the GUI:
::    - Pick your offline game in the left list
│ Scanner tab → set Type=Int, Mode=Exact, Value=100
::    - Click [First scan]
::    - Change the value in the game (e.g. take damage)
::    - Scanner tab → Mode=Decreased by, Value=N
::    - Click [Next scan] until you have 1-3 hits
::    - Select rows → click [Add to trainer]
::    - Trainer Spec tab → edit values (HP=999999, etc.)
::    - Build tab → click [Build .exe]
:: 4. trainers/<Game>_Trainer.exe is your standalone trainer

## Signature scanning (AoB / pattern scan)

In the Scanner tab, the **Signature** row lets you find a byte pattern
across memory, like CE's "Array of Bytes" scan:

    48 8B 05 ?? ?? ?? ?? 48 85 C0 74

- `??` is a wildcard (one byte, any value)
- Click `[Find]` to scan; hits land in the Address list below
- Use case: when the game updates and addresses change, the
  signature finds the new location at runtime — trainers can store
  the pattern in YAML and re-resolve on every launch


## Scanner modes

`exact`, `greater`, `less`, `between`, `increased`, `decreased`, `changed`,
`unchanged`, `initial`

Standard CE workflow: first scan with exact → do stuff in the game → re-scan
with `changed` or `increased`/`decreased` until you're down to 1-3 candidates.

## Value types

`uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`, `float`,
`double`, `string` (ASCII/UTF-8).

## Trainer spec format

See `docs/example_trainer.yaml`. Top-level fields:

```yaml
name: "My Game Trainer"
game: "GameName.exe"               # target exe name
hotkey_toggle: VK_F8               # show/hide trainer window
hotkey_panic:  VK_END              # emergency disable
window_size: [420, 320]
window_title_color: "#FF66CC"      # kawaii pink (◕‿◕)
features:                          # one toggle per entry
  - name: "God Mode"
    type: value                    # value / freeze / nudge
    address: 0x00ABCDEF
    value: 999999
    width: 4
actions:                           # one-shot hotkey triggers
  - name: "Refill Health"
    hotkey: VK_F1
    address: 0x00ABCDEF
    value: 999999
    width: 4
```

## Building trainers from CLI

```bat
python trainer_compiler.py trainers\my_game.yaml --build --g++ "C:\mingw64\bin\g++.exe"
```

Requires MinGW g++ in PATH (or pass `--g++` with full path).

## Quality-of-life and diagnostics

- Scan requests are validated before workers start, with field-specific errors
  for unsupported types, modes, bounds, strides, and stale candidates.
- A scan that returns zero hits remains a valid scan session, so the next scan
  does not unexpectedly restart from all memory. Use `new_scan: true` (or the
  **Clear scan** action) to begin again.
- The Electron backend supports `get_status`, `clear_scan`, and
  `detach_process`. Scan responses include `phase`, `elapsed_ms`, `count`,
  `returned`, `truncated`, and the active type/mode for clearer UI feedback.
- Trainer specs are checked before C++ is generated. Invalid widths, pointer
  offsets, signatures over 64 bytes, and malformed feature/action entries now
  stop with a useful error instead of producing a broken trainer.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Studio (Python / Tkinter GUI) — design tool          │
│  ┌─────────────┐ ┌──────────────┐ ┌───────────────┐  │
│  │ Process     │ │ Value        │ │ Address       │  │
│  │ picker      │ │ scanner      │ │ table (live)  │  │
│  └─────────────┘ └──────────────┘ └───────────────┘  │
│  ┌─────────────┐ ┌──────────────┐ ┌───────────────┐  │
│  │ Hex viewer  │ │ Spec editor  │ │ Build tab     │  │
│  └─────────────┘ └──────────────┘ └───────────────┘  │
└──────────────────────┬───────────────────────────────┘
                       │ writes YAML
                       ▼
            ┌─────────────────────┐
            │  trainer_compiler.py │
            └──────────┬──────────┘
                       │ fills template + invokes g++
                       ▼
            ┌─────────────────────┐
            │  trainers/Foo.exe    │   ← standalone Win32 trainer
            │  (no Python at run)  │
            └─────────────────────┘
```

## Verified

- PID scan finds 17 hits in 0.08s on a busy process
- Rescan-exact correctly retains all candidates
- Rescan-changed correctly identifies a modified value
- Test_Trainer.exe (622 KB) launches Win32 window and exits cleanly

## License

See `LICENSE`. Personal/educational use only. Do not distribute trainers for
games you don't own. Do not use against online games with anti-cheat.

## Brand

- **Title**: `MomoTrainer Studio`
- **Splash**: `MomoTrainer — by Momo aka Steav Beoung Salang`
- **Default color**: `#FF66CC` (kawaii pink, ◕‿◕)
- Same brand family as `Mwtrainer` (Warframe) and `MomoMenu` (Combat Master, JX2 Royal).
