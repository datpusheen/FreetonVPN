# Freeton VPN

Windows x64 desktop client and browser extension that connect to Proton VPN Free servers.

## Desktop Client (Rust v3.0.0)

The v3.0.0 desktop client is a native Rust Windows x64 application (`FreetonVPN.exe`) paired with a privileged Windows service broker (`FreetonVPNService.exe`) and bundled WireGuard libraries (`tunnel.dll` + `wireguard.dll`). Users do not need to install WireGuard for Windows, GPG, Python, or Playwright separately, and routine VPN connect/disconnect toggles run without UAC prompts.

### Install & Run

- **Installer:** run [`dist/FreetonVPN-Setup-x64.exe`](dist/FreetonVPN-Setup-x64.exe).
  - Installs into `C:\Program Files\FreetonVPN\`.
  - Registers and starts `FreetonVPNService` with non-admin Interactive User IPC permissions.
  - Creates Start Menu shortcuts (`Freeton VPN` and `Uninstall Freeton VPN`).
- **Auto-updates:** v3.0.0+ checks [`version-rust.json`](version-rust.json) (isolated from the legacy v2.4.3 [`version.json`](version.json) feed) and verifies the installer's SHA-256 before launching a silent `/S` upgrade.

### Build & Package Windows Installer

Prerequisites on Windows 10/11 x64:

- Rust toolchain (`rustup`, `stable-x86_64-pc-windows-msvc`) + Visual Studio Build Tools (C++ & Windows 10/11 SDK)
- Go (`C:\Program Files\Go\bin`) and `git`
- NSIS 3 (`C:\Program Files (x86)\NSIS\makensis.exe`)

Run the full build and packaging pipeline:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\rust\scripts\build_windows.ps1
```

What `build_windows.ps1` does:

1. Clones and verifies the pinned `wireguard-windows` release (`v1.1.1`) into `rust/build/wireguard-windows/`, runs `embeddable-dll-service\build.bat`, and stages `tunnel.dll` into `rust/assets/bin/tunnel.dll`.
2. Downloads and SHA-256-verifies `wireguard-nt-1.1.zip`, then extracts `amd64/wireguard.dll` into `rust/assets/bin/wireguard.dll`.
3. Runs `cargo test --manifest-path rust/Cargo.toml --workspace` and `cargo build --manifest-path rust/Cargo.toml --release`.
4. Compiles [`rust/installer/freeton.nsi`](rust/installer/freeton.nsi) with `makensis.exe` to produce:
   - `dist/FreetonVPN-Setup-x64.exe`
   - `dist/FreetonVPN-Setup-x64.exe.sha256`
   - Updated [`version-rust.json`](version-rust.json) with exact `file_size_bytes` and `sha256`.

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
| `rust/freeton-core/` | Proton SRP/OpenPGP auth, API client, ICMP pinger, Windows Credential Manager, fail-closed updater, WireGuard helpers |
| `rust/freeton-service/` | `FreetonVPNService.exe` broker and `WireGuardTunnel$FreetonVPN` runner (`tunnel.dll` + `wireguard.dll`) |
| `rust/freeton-app/` | Native `eframe`/`egui` tray flyout UI and WebView2 CAPTCHA modal (`FreetonVPN.exe`) |
| `rust/scripts/build_windows.ps1` | End-to-end Windows x64 build, DLL staging, NSIS packaging, and manifest update script |
| `rust/installer/freeton.nsi` | NSIS installer and uninstaller script |
| `version-rust.json` | Release manifest for Rust v3.0.0+ desktop channel |
| `version.json` | Legacy v2.4.3 release manifest (preserved for existing v2.x users) |
| `browser-extension/` | Shared source and build script for Chromium and Firefox node checker add-ons |
| `website/` | Static project website |
| `dist/` | Packaged installer and checksum outputs (git-ignored) |

## Project status

Freeton VPN is an independent, unofficial project and is not affiliated with or endorsed by Proton AG. The app is provided as-is.
