# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['studio_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'memory_scanner',
        'themes',
        'trainer_compiler',
        'yaml',
        'yaml.cyaml',
        'yaml.error',
        'yaml.nodes',
        'yaml.tokens',
        'struct',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MomoTrainer Studio',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
