# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

PROJECT_ROOT = Path(SPECPATH).resolve()
python_base = Path(sys.base_prefix).resolve()
venv_root = Path(sys.prefix).resolve()

# Dynamic Tcl/Tk paths
tcl_data = python_base / 'tcl' / 'tcl8.6'
tk_data = python_base / 'tcl' / 'tk8.6'
tkinter_binary = python_base / 'DLLs' / '_tkinter.pyd'
tcl_binary = python_base / 'DLLs' / 'tcl86t.dll'
tk_binary = python_base / 'DLLs' / 'tk86t.dll'

datas = [
    (str(tcl_data), '_tcl_data'),
    (str(tk_data), '_tk_data'),
]
binaries = [
    (str(tkinter_binary), '.'),
    (str(tcl_binary), '.'),
    (str(tk_binary), '.'),
]
hiddenimports = [
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'tkinter.font',
    'tkinter.messagebox',
    'keyring.backends.Windows',
    'proton.session',
    'updater',
]

# Core packages
packages = [
    'keyring',
    'proton',
    'gnupg',
    'cryptography',
    'pystray',
    'PIL',
]

for pkg in packages:
    pkg_datas, pkg_binaries, pkg_hidden = collect_all(pkg)
    datas += pkg_datas
    binaries += pkg_binaries
    hiddenimports += pkg_hidden

# Playwright: collect driver/node.exe but filter out sensitive .ps1, .sh, .bat scripts
# which trigger heuristic AV detection (e.g. Wacatac.C!ml, Dropper.Agent)
pw_datas, pw_binaries, pw_hidden = collect_all('playwright')
filtered_pw_datas = [
    (src, dst) for src, dst in pw_datas
    if not any(src.lower().endswith(ext) for ext in ('.ps1', '.sh', '.bat', '.cmd', '.vbs'))
]
datas += filtered_pw_datas
binaries += pw_binaries
hiddenimports += pw_hidden

tk_hook = venv_root / 'Lib' / 'site-packages' / 'PyInstaller' / 'hooks' / 'rthooks' / 'pyi_rth__tkinter.py'
runtime_hooks = [str(tk_hook)] if tk_hook.exists() else []

a = Analysis(
    [str(PROJECT_ROOT / 'proton_warp_material_gui.py')],
    pathex=[str(PROJECT_ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[str(PROJECT_ROOT / 'pyinstaller_hooks')],
    hooksconfig={},
    runtime_hooks=runtime_hooks,
    excludes=[],
    noarchive=False,
    optimize=0,
)

# Strip any sensitive installer scripts (.ps1, .sh, .bat, .cmd, .vbs) that may have been collected by hooks
a.datas = [
    entry for entry in a.datas
    if not any(str(entry[0]).lower().endswith(ext) for ext in ('.ps1', '.sh', '.bat', '.cmd', '.vbs'))
]

pyz = PYZ(a.pure)

build_mode = os.environ.get('FREETON_BUILD_MODE', 'onedir').strip().lower()
version_file = str(PROJECT_ROOT / 'file_version_info.txt')
icon_file = [str(PROJECT_ROOT / 'freeton_icon.ico')]

if build_mode in ('onefile', 'single'):
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name='FreetonVPN',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        version=version_file,
        icon=icon_file,
    )
else:
    # onedir mode (recommended: clean standalone directory, zero dropper behavior)
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='FreetonVPN',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        version=version_file,
        icon=icon_file,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name='FreetonVPN',
    )
