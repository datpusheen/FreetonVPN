# Freeton VPN

Windows desktop client that connects to Proton VPN servers through WireGuard.

## Run the app

- **Packaged app:** open [`dist/FreetonVPN.exe`](dist/FreetonVPN.exe).
- **Run from source:** open `run_freeton.bat`. It prefers `.venv-windows`, then `.venv`, then Python on `PATH`.
- **WireGuard:** WireGuard for Windows must be installed. The app can open its dependency setup flow if it is missing.

`run_warp_gui.bat` is a compatibility launcher with the same behavior as `run_freeton.bat`.

## Run from source for the first time

Use Python 3.10 or newer:

```powershell
python -m venv .venv-windows
.\.venv-windows\Scripts\python.exe -m pip install -r requirements.txt
.\run_freeton.bat
```

## Build Windows packages

```powershell
.\build_exe.ps1
```

The build script uses `.venv-windows` (or `.venv` as a fallback). It writes distributable packages to `dist/` and recreatable PyInstaller intermediates to `build/`:

- `dist/FreetonVPN.exe` — single-file build
- `dist/FreetonVPN/FreetonVPN.exe` — folder build
- `dist/FreetonVPN-v2.4.3-windows-x64-portable.zip` — portable folder build

## Browser VPN extension

The companion extension lists Proton VPN Free servers and can route browser web traffic through a Proton HTTPS proxy. Sign in to Proton VPN in the browser first; the extension uses that tab's existing session and does not store account credentials. It only protects browser traffic, not other apps on the computer; use the desktop app for a full-device WireGuard tunnel and ICMP latency checks.

Build loadable Chromium and Firefox packages with:

```powershell
.\browser-extension\build.ps1
```

The package folders and ZIP archives are written to `dist/browser-extension/`. See [`browser-extension/README.md`](browser-extension/README.md) for install steps.

## Project map

| File or folder | Purpose |
| --- | --- |
| `proton_warp_material_gui.py` | Main GUI, Proton API client, and WireGuard lifecycle |
| `windows_vpn.py` | Windows service, handshake, and DNS health checks |
| `updater.py` | App update handling |
| `main.py` | Small entry point for the GUI module |
| `requirements.txt` | Python dependencies |
| `run_freeton.bat` | Preferred source launcher |
| `build_exe.ps1` | Windows packaging script |
| `FreetonVPN.spec` | PyInstaller build recipe used by the packaging script |
| `pyinstaller_hooks/` | PyInstaller runtime hooks |
| `.venv-windows/`, `.venv/` | Local Python environments; do not copy into a release |
| `build/` | Generated build cache; safe to recreate |
| `dist/` | Packaged app output |
| `archive/legacy-builds/` | Older local binaries kept for reference |
| `website/` | Static project website |
| `browser-extension/` | Shared source and build script for Chromium and Firefox node checker add-ons |

`qa_gui.py`, `smoke_windows_gui.py`, `test_connection.py`, and `test_updater.py` are development and verification utilities.

## Project status

Freeton VPN is an independent, unofficial project and is not affiliated with or endorsed by Proton AG. The app is provided as-is.
