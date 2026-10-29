# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

# NOTE: ui/ hashcat/ tools/ are NOT bundled here. They must sit NEXT TO the exe
# (engine.app_dir() = dirname(sys.executable)), but PyInstaller puts datas in
# _internal/. build_exe.bat xcopies those three folders next to the exe after the
# build — that is the single source of truth for them. Only code deps live here.
datas = []
binaries = []
hiddenimports = ['webview.platforms.edgechromium', 'clr']
# webview stack + native PDF hash extraction (pypdf needs cryptography for AES PDFs)
for pkg in ('webview', 'clr_loader', 'pythonnet', 'pypdf', 'cryptography', 'cffi'):
    d, b, h = collect_all(pkg)
    datas += d; binaries += b; hiddenimports += h


a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['customtkinter', 'tkinter'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ArchiveRecovery',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='appicon.ico',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ArchiveRecovery',
)
