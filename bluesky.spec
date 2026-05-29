# -*- mode: python ; coding: utf-8 -*-
"""
Bluesky PyInstaller Spec
Genera un binario único para Linux.

Uso:
    pip install pyinstaller
    pyinstaller bluesky.spec

Resultado: dist/bluesky (binario único, sin dependencias)
"""

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['bluesky/cli.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Core
        'bluesky',
        'bluesky.core',
        'bluesky.core.engine',
        'bluesky.core.session',
        'bluesky.core.hardware',
        'bluesky.core.reporter',
        # Attacks
        'bluesky.modules',
        'bluesky.modules.attacks',
        'bluesky.modules.attacks.bluejacking',
        'bluesky.modules.attacks.bluesnarfing',
        'bluesky.modules.attacks.bluebugging',
        'bluesky.modules.attacks.blueborne',
        'bluesky.modules.attacks.blesa',
        'bluesky.modules.attacks.whisperpair',
        'bluesky.modules.attacks.knob',
        'bluesky.modules.attacks.bias',
        'bluesky.modules.attacks.bluffs',
        'bluesky.modules.attacks.sweyntooth',
        # Exploits
        'bluesky.modules.exploits',
        'bluesky.modules.exploits.keystroke_injection',
        'bluesky.modules.exploits.l2cap_fuzz',
        'bluesky.modules.exploits.rfcomm_shell',
        # Scanners
        'bluesky.modules.scanners',
        'bluesky.modules.scanners.device_scanner',
        'bluesky.modules.scanners.service_scanner',
        # Utils
        'bluesky.utils',
        'bluesky.utils.format',
        'bluesky.utils.network',
        'bluesky.utils.termux',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='bluesky',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    contents_directory='.',
)

# Also create a one-folder bundle for easier debugging
# coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas, strip=False, upx=True, upx_exclude=[], name='bluesky')
