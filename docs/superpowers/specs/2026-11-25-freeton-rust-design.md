# Freeton VPN — Rust Desktop Replacement Design

**Date:** 2026-11-25  
**Status:** Ready for user approval (builder check complete)  
**Target Platform:** Windows 10 / Windows 11 (`x86_64-pc-windows-msvc`)  
**Replaces:** Legacy Python/Tkinter/PyInstaller desktop client (`proton_warp_material_gui.py`, `windows_vpn.py`, `updater.py`, `FreetonVPN.spec`)

---

## 1. Intent & Why

Freeton VPN v2.4.3 is currently distributed as a ~68.5 MB single-file PyInstaller bundle wrapping Python, Tcl/Tk, Pillow, `cryptography`, `proton-core`, and Playwright hooks, while still requiring users to separately download and install **WireGuard for Windows** and **GnuPG / Gpg4win**. That architecture creates three recurring problems:

1. **Heavy footprint & dependency friction:** Users face multi-step external installer dialogs and UAC prompts before they can even sign in or connect.
2. **Avoidable failure surfaces:** Windows compatibility shims (`os.getuid` monkeypatch for `proton-core`), external `gpg.exe` subprocess execution with regex fallback, Playwright browser automation for login/CAPTCHA, locale-dependent `ping.exe` stdout parsing, and Tkinter custom canvas/threading synchronization races (`_connection_generation`, focus/modal quirks).
3. **Brittle updates & UAC fatigue:** Self-updating relies on a detached `.bat` script polling in a loop to overwrite a locked `.exe`, and non-admin users receive UAC prompts on every tunnel toggle.

The goal of this project is a **complete native Rust replacement** of the desktop client that is significantly lighter, far less error-prone, bundles WireGuard cleanly with zero external GPG/Playwright downloads, and installs properly into `Program Files` so normal VPN toggles require no UAC and updates happen cleanly.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
- **Full end-user feature parity** with Freeton VPN v2.4.3 desktop workflows (except features explicitly retired below).
- **Zero external user-installed prerequisites:**
  - Pure-Rust Proton SRP authentication + OpenPGP modulus signature verification (eliminates GnuPG / `gpg.exe` and `proton-core`).
  - Bundled official WireGuard kernel service DLLs (`tunnel.dll` + `wireguard.dll`) managed by a dedicated Rust Windows Service (eliminates separate WireGuard installer downloads).
  - System Edge WebView2 used **only on demand** as a transient popup when Proton requests CAPTCHA (`HumanVerificationNeeded`).
- **Proper Windows installation & clean updates:** NSIS/MSI installer deploying into `Program Files\FreetonVPN`, registering a privileged helper Windows Service (`FreetonVPNService`) so standard users can toggle VPN without repeated UAC prompts, and upgrading via clean service stop → verified installer run → relaunch.
- **Backward-compatible data migration:** Reuse existing Windows Credential Manager entries (`proton-node-checker`, `proton-node-checker-wireguard`), `servers_cache.json`, and `version.json` / GitHub Releases metadata format so upgrading users keep their session, WireGuard keys, and preferences.
- **Strict concurrency & connection safety:** Single source-of-truth async state machine serialized across UI, background API/ping workers, and service IPC.

### Non-Goals
- **Cross-platform desktop support:** Linux and macOS are out of scope; this targets Windows 10/11 x64 only.
- **Browser cookie login (`[DEV] Đăng nhập bằng trình duyệt`) & Playwright:** Explicitly retired and removed.
- **Replacing non-desktop components:** `browser-extension/` and `website/` remain untouched.
- **In-app account creation:** Signup link continues opening `https://account.protonvpn.com/signup` in the user's default browser.

### Anti-Goals
- Reporting "Connected" based solely on Windows Service `RUNNING` state — must require both a fresh WireGuard handshake (`<= 180s`) for the expected server `x25519PublicKey` and a valid DNS response sent strictly from the tunnel's local interface IP (never falling back to the physical NIC).
- Blocking the GUI render loop with network I/O, ICMP pings, DNS probes, or SCM/pipe calls.
- Retaining the batch-file copy-over-locked-EXE updater or requiring manual `gpg.exe`/`wireguard-installer.exe` downloads.
- Introducing privilege-escalation vulnerabilities in the privileged service (e.g., allowing unprivileged clients to execute arbitrary installers or arbitrary file paths via the local pipe).

---

## 3. Constraints & Assumptions

1. **Build Toolchain Prerequisite:** The current development machine does not yet have `rustc`/`cargo`, Visual Studio Build Tools, Windows 10/11 SDK, Go (needed alongside MinGW `gcc.exe` to compile WireGuard's `tunnel.dll`), or NSIS/WiX installed (`winget`, `gcc.exe`, and Edge WebView2 Runtime `158.0.4370.33` are present). Installing the `x86_64-pc-windows-msvc` toolchain, Windows SDK, Go, and installer packager is required before building.
2. **Proton API & SRP Contract:**
   - Auth endpoints (`https://api.protonmail.ch`): `POST /auth/info` (or `auth/v4/info`), `POST /auth`, `POST /auth/2fa`, `POST /auth/v4/refresh` (`GrantType: "refresh_token"`, `ResponseType: "token"`).
   - Headers: `Accept: application/vnd.protonmail.v1+json`, `x-pm-appversion: Other`, `x-pm-locale: en_US`, plus `x-pm-uid` and `Authorization: Bearer <AccessToken>` when authenticated.
   - SRP implementation must match Proton's protocol already verified in `browser-extension/shared/proton-srp.js`:
     - Verify clearsigned modulus against Proton's embedded Ed25519 PGP public key (`SRP_MODULUS_FINGERPRINT = 248097092b458509c508dac0350585c4e9518f26`), enforcing 256-byte (2048-bit) odd modulus.
     - Support SRP `Version` `3` and `4`, `bcrypt` `$2y$10$` prefix over `(salt || "proton")[..16]`, `PMHash` (`SHA-512(input || 0..3)` = 256 bytes), `g = 2`, little-endian integer encoding, and constant-time `ServerProof` verification.
     - Preserve full 2FA/recovery code characters (do not strip non-digits).
     - On Proton API error `9001` or `12087`, build the verification URL from `Details.WebUrl` (or `https://verify.proton.me/?methods=captcha&token=...`) with `ForceWebMessaging=1`, open a transient WebView2 modal, capture the token posted via `window.postMessage` (`Token`, `token`, `verificationToken`, `HumanVerificationToken`, `humanVerificationToken`), close the popup, and retry SRP login with `x-pm-human-verification-token` and `x-pm-human-verification-token-type`.
   - VPN API endpoints (ordered fallback: `https://account.protonvpn.com/api`, `https://api.protonmail.ch`, `https://account.proton.me/api`) with automatic `401` refresh-and-retry:
     - `GET /vpn/v1/logicals?WithIpV6=1`: filter `Tier == 0`, physical servers `Status == 1 && ServicesDown == 0`, deduplicate ping targets, score `(ping_ms * 0.7) + (load * 0.8)` (defaulting unreachable ping to `9999` and missing load to `50`).
     - `GET /vpn/v1/certificate/key/EC` and `POST /vpn/v1/certificate` (`ClientPublicKey`, `Platform: "Windows"`, `Features: {}`), deriving the WireGuard X25519 private key from the Ed25519 PKCS8 private seed via `SHA-512(seed)[..32]` with Curve25519 clamping (`[0] &= 0xF8`, `[31] &= 0x7F`, `[31] |= 0x40`).
3. **WireGuard Kernel Driver Requirement:** Windows requires Administrator privileges (`LocalSystem` service) to load `wireguard-nt` (`wireguard.dll`) and create TUN interfaces. Normal desktop users must not need UAC prompts during routine connect/disconnect once installed.

---

## 4. Approaches Considered

| Approach | Summary | Trade-offs | Decision |
| :--- | :--- | :--- | :--- |
| **1. Pure Rust Native GUI + Transient WebView2 CAPTCHA + Rust Service (`tunnel.dll` + `wireguard.dll`)** | Single-language Rust stack for UI, tray, SRP, ICMP ping, and privileged WireGuard service; WebView2 opens only when Proton requires CAPTCHA; packaged via Windows installer. | Lowest RAM and binary footprint, no background browser engine at rest, strict Rust type/state safety end-to-end. Requires custom native dark-glass UI styling, font/emoji setup, and explicit installer/updater setup. | **Selected** |
| **2. Tauri v2 (Rust backend + WebView2 UI) + Rust Service (`tunnel.dll` + `wireguard.dll`)** | Same Rust backend/service, but UI rendered continuously in WebView2 HTML/CSS/TS with Tauri NSIS/updater. | Fast CSS dark-glass styling and built-in NSIS/updater, but higher RAM footprint while window is open and an extra Rust <-> JS IPC boundary. | Rejected |
| **3. Pure Rust GUI + Bundled `wireguard.exe` & `wg.exe`** | Native Rust UI/SRP, but ships `wireguard.exe` (~9.3 MB) + `wg.exe` (~140 KB) in `Program Files` and shells out to CLI commands. | Reuses `wireguard.exe` CLI directly, but adds ~9.5 MB payload, keeps CLI subprocess parsing, and still needs a privileged service or UAC per toggle. | Rejected |

*(Weak alternatives ruled out upfront: PyO3 hybrid wrapping Python, Electron, and user-space `boringtun` without kernel `wireguard-nt`.)*

---

## 5. System Architecture (Selected Approach)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ User Session (Standard User)                                            │
│                                                                         │
│  ┌──────────────────────────────┐     ┌──────────────────────────────┐  │
│  │ freeton-app (FreetonVPN.exe) │────▶│ freeton-core (library)       │  │
│  │ • Native Rust Dark-Glass UI  │     │ • Pure-Rust Proton SRP+PGP   │  │
│  │ • Tray Icon & 390x610 Flyout │     │ • HTTPS Pooling & AutoRefresh│  │
│  │ • On-demand WebView2 CAPTCHA │     │ • Native Win32 ICMP Ping     │  │
│  │ • NSIS/Updater Launcher      │     │ • Credential Manager + Cache │  │
│  └──────────────┬───────────────┘     └──────────────────────────────┘  │
│                 │ Named Pipe (\\.\pipe\FreetonVPNService, DACL: IU/BA)  │
└─────────────────┼───────────────────────────────────────────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LocalSystem (Privileged Services)                                       │
│                                                                         │
│  ┌────────────────────────────────────┐                                 │
│  │ FreetonVPNService.exe (Broker)     │                                 │
│  │ • Validates config parameters      │                                 │
│  │ • Writes %ProgramData%\FreetonVPN\ │                                 │
│  │   tunnels\FreetonVPN.conf (ACL)    │                                 │
│  │ • Starts/Stops WireGuardTunnelSvc  │                                 │
│  │ • Reads WG handshake via IPC pipe  │                                 │
│  │ • Runs tunnel-bound UDP DNS probe  │                                 │
│  └──────────────┬─────────────────────┘                                 │
│                 │ Windows SCM                                           │
│                 ▼                                                       │
│  ┌────────────────────────────────────┐                                 │
│  │ WireGuardTunnel$FreetonVPN         │                                 │
│  │ (FreetonVPNService.exe --tunnel)   │                                 │
│  │ • Loads tunnel.dll + wireguard.dll │                                 │
│  └────────────────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.1 Workspace Structure & Migration Strategy
- Build the Rust solution as a Cargo workspace inside `rust/` (crates: `freeton-core`, `freeton-service`, `freeton-app`, plus installer packaging scripts) so existing Python code and unit tests (`test_connection.py`, `test_updater.py`, `qa_gui.py`) remain runnable as a behavioral reference until the Rust implementation passes full verification.
- Once verified and approved for cutover, archive or remove the legacy Python desktop source/spec files and update `version.json` and release build scripts to target the Rust installer output.

### 5.2 `freeton-core` (Networking, Auth, Persistence)
- **Proton Auth & Session:** Direct HTTPS via `reqwest` (`rustls`), implementing `/auth/info`, `/auth`, `/auth/2fa`, `/auth/v4/refresh`, and `/vpn/v1/*`.
- **Credential Manager Compatibility:**
  - Read/write Windows Credential Manager targets `proton-node-checker` (`active-account`, `session:<account_lower>`) and `proton-node-checker-wireguard` (`client_config`), preserving JSON fields (`AccessToken`, `RefreshToken`, `UID`, `private_key`, `public_key`, `expiration`, `address`, `dns`, `port`, `animations_enabled`, `auto_check_update`, `debug_mode`).
  - Cache server list in `%LOCALAPPDATA%\FreetonVPN\servers_cache.json` for sub-50ms startup rendering before background refresh finishes.
- **Native ICMP Pinger:** Use Win32 `IcmpCreateFile` / `IcmpSendEcho` (with 800ms timeout and bounded async/thread concurrency, deduplicated by `pingTarget` IP/domain). Zero `ping.exe` spawning or localized stdout parsing.
- **Key Management:** Auto-fetch/refresh WireGuard key when missing or expiring within 7,200 seconds (`needs_key_refresh`), preserving static imported keys (`expiration == 0`), serialized by an async mutex.

### 5.3 `freeton-service` (Bundled WireGuard Service & Health Verification)
- **Packaging & Provenance:** Ships alongside `FreetonVPN.exe` in `Program Files\FreetonVPN\` together with x64 `tunnel.dll` and `wireguard.dll`:
  - **`tunnel.dll`:** Built from source in our build script from a pinned `wireguard-windows` release tag (`embeddable-dll-service`, using Go + MinGW).
  - **`wireguard.dll`:** Official prebuilt WHQL-signed `wireguard-nt` x64 binary, verified by pinned version and SHA-256 checksum during build.
- **Dual-Mode Binary (`FreetonVPNService.exe`):**
  1. **Broker Service (`FreetonVPNService`):** Registered at install time (`start = auto` or `demand` with service start permission granted to Interactive Users, running as `LocalSystem`). Listens on `\\.\pipe\FreetonVPNService` with an explicit Security Descriptor allowing `Interactive Users (IU)` / `Authenticated Users (AU)` + `Administrators` + `SYSTEM`.
  2. **Tunnel Service (`WireGuardTunnel$FreetonVPN`):** Managed by the Broker via Windows SCM (`FreetonVPNService.exe --tunnel <abs_conf_path>`, unrestricted SID type, dependencies `Nsi`, `TcpIp`). Calls `WireGuardTunnelService` exported by `tunnel.dll` and shuts down cleanly on `SERVICE_CONTROL_STOP`.
- **Tunnel Lifecycle Across UI Restart & Windows Logoff *(Design Call)*:**
  - `FreetonVPNService` stores active tunnel metadata (`server_name`, `country`, `entry_ip`, `x25519_public_key`, `connected_at`, local IP/DNS) in memory and returns it in `Status` responses. If `FreetonVPN.exe` crashes or is restarted by the same user, the reopened UI re-attaches seamlessly, verifies handshake + DNS, and restores `"ĐÃ KẾT NỐI"` and the session timer.
  - Explicit `Disconnect`, UI `Thoát` (`ShutdownTunnelOnExit`), `Đăng xuất`, or Windows session logoff/user-switch (`WTS` session notification) automatically tears down `WireGuardTunnel$FreetonVPN` and deletes the `.conf` file.
- **Strict Connection Verification:**
  - Before tearing down an existing working tunnel, validate endpoint, X25519 server public key, client private key, and port (`1..=65535`).
  - Uninstall any existing `WireGuardTunnel$FreetonVPN` and wait for SCM state `0` (absent) before installing the new one (matching `test_connection.py` invariants).
  - Wait for SCM `SERVICE_RUNNING` (`4`), then poll WireGuard's Windows driver/IPC state (via WireGuard's `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\FreetonVPN` or `wireguard.dll` peer query — no `wg.exe`) until the expected peer has a non-zero `latest_handshake` within `180` seconds, **and** perform a UDP DNS query (`account.protonvpn.com` A record) strictly bound to the configured tunnel local IP (never unbound / never falling back to physical adapter).
  - Distinguish handshake timeout vs DNS failure in structured errors; automatically uninstall tunnel and delete `.conf` if connection verification fails. If uninstall fails, keep `.conf` and surface the error.
- **Security Boundaries:**
  - The Broker pipe only accepts typed commands (`Connect { validated WG params }`, `Disconnect`, `Status`, `ShutdownTunnelOnExit`) — **never** arbitrary shell commands, arbitrary file paths, or binary execution requests.
  - `.conf` files are written only inside `%ProgramData%\FreetonVPN\tunnels\` with ACL restricted to `SYSTEM` and `Administrators`.
  - If the user launches `FreetonVPN.exe` without the service registered (e.g., broken install), the UI detects this and offers a one-click UAC repair action (`FreetonVPNService.exe --install`) rather than failing obscurely.

### 5.4 `freeton-app` (Native Rust GUI & Tray)
- **Window & Tray Behavior:**
  - Compact `390x610` dark-glass frameless flyout (`#101419` background, `#1b222b` cards, `#8bd5c5` mint accent) positioned near the Windows taskbar notification area unless user-dragged, with Win11 DWM rounded corners (`DWMWA_WINDOW_CORNER_PREFERENCE`).
  - System tray icon dynamically reflects state (violet idle, amber connecting/unverified, emerald connected) with context menu: `Mở Freeton VPN`, `Bật/Tắt VPN`, `Cài đặt`, `Giới thiệu`, `Thoát`.
  - Clicking `×` hides to tray (respecting animations toggle); Focus-out does **not** unexpectedly hide during modals or CAPTCHA popups. Clicking `Thoát` disconnects an active tunnel cleanly before exiting.
- **Views & User Flows (All Parity Retained, Browser Login Removed):**
  1. **Login Gate:** Brand hero, security summary, primary `Đăng nhập Proton VPN (Email/Mật khẩu)` button, signup external link, About button.
  2. **SRP Login View:** Email/Username, Password with show/hide eye toggle, 2FA/Recovery code input, live status banner, Enter-to-submit, friendly 429/CAPTCHA/2FA error handling; opens transient WebView2 modal automatically on `9001`/`12087`.
  3. **Home Dashboard:** Status card (Unprotected / Verifying / Protected + exit IP lookup via `https://api.ipify.org?format=json` + endpoint & internal IP), live `HH:MM:SS` session timer pill, central iOS-style toggle switch, selected server card (country, name, ping pill, load pill), bottom bar (`[Dev: Xuất .conf]`, `Cài đặt`, `Giới thiệu`, `Đăng xuất`).
  4. **Server Picker Drawer:** Debounced text search (`name`, `city`, `domain`, country display), country dropdown + quick-filter pills (`Tất cả`, `SG`, `JP`, `US`, `NL`), sort chips (`Tối ưu`, `Ping`, `Tải`, `A-Z`), highlighted "Best server" card, and virtualized scrollable server list (preserving manual selection during background refresh).
  5. **Settings Dialog:** Startup with Windows (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), UI animations toggle, Auto-check updates toggle, manual check update button, WireGuard service health indicator/repair button (replacing legacy Dependency Setup), key status & expiry, `Cấp Key mới (API)`, `Nhập file .conf`, Private Key / DNS / Port fields. Middle-mouse press-and-hold (`750ms`) toggles **Dev Mode** (persisted `debug_mode`, unlocks `.conf` export buttons and technical error details).
  6. **About Dialog:** Version display, manual update check, Vietnamese legal disclaimer.
- **Concurrency Model:** UI maintains a single authoritative `AppState` updated exclusively from typed worker messages (`ScanProgress`, `ScanComplete`, `TunnelStateChanged`, `PublicIpResolved`, `UpdateAvailable`), eliminating stale callback overwrites.

### 5.5 Installer & Auto-Updater
- **Cutover from v2.4.3:** Rust releases (starting `v3.0.0`) use a dedicated Rust installer manifest/feed (e.g., `version-rust.json` or an `installer` object in `version.json`) separate from legacy v2.4.3's `download_url`, so legacy Python `.bat` self-replacers never download an installer binary by mistake. Existing v2.4.3 users do a clean one-time install from GitHub Releases.
- **Installer (`FreetonVPN-Setup-x64.exe` via NSIS or `.msi` via WiX):**
  - Installs binaries and `tunnel.dll` + `wireguard.dll` into `%ProgramFiles%\FreetonVPN\`.
  - On install/upgrade: stops `WireGuardTunnel$FreetonVPN` and `FreetonVPNService`, overwrites binaries cleanly, registers/updates `FreetonVPNService` with Interactive User pipe permissions, creates Start Menu shortcut, and optionally relaunches `FreetonVPN.exe` after silent upgrade.
  - On uninstall: disconnects & deletes `WireGuardTunnel$FreetonVPN` and `FreetonVPNService`, removes `%ProgramFiles%\FreetonVPN\` and `%ProgramData%\FreetonVPN\tunnels\`.
- **Updater & Integrity Policy *(Design Call)*:**
  - Checks the Rust update manifest (with cache-busting query and GitHub Releases API fallback) on startup (+3s if enabled) and manually from Settings/About.
  - Releases remain unsigned / locally self-signed (matching v2.4.3) unless a trusted CA Authenticode certificate is supplied in the release pipeline.
  - **Fail-closed SHA-256 verification:** Shows changelog dialog (`UpdateDialog` parity); on user confirmation, streams installer to `%TEMP%`, verifies exact `SHA-256` checksum, launches the downloaded installer via standard Windows UAC (`ShellExecuteW runas`) with silent/passive upgrade flags, and exits the running UI cleanly. When falling back to the GitHub Releases API, it parses a companion `.sha256` release asset; if no SHA-256 checksum is available, it refuses automatic `runas` execution and instead offers to open the GitHub Releases page in the browser.

---

## 6. Left to the Builder

The implementation planner / builder owns the following choices within the boundaries above:
- Exact Rust crates for:
  - Native UI & tray (`egui`/`eframe` or `slint` or `iced` + `tray-icon`), provided Windows 10/11 DPI scaling, Vietnamese UTF-8 + emoji rendering, software rendering fallback on systems lacking modern GPU drivers, and virtualized smooth scrolling work reliably.
  - Pure-Rust OpenPGP signature verification (`pgp` / `sequoia-openpgp` or verified Ed25519 OpenPGP packet verifier) and SRP math (`num-bigint`, `bcrypt`, `sha2`).
  - Transient WebView2 wrapper (`wry` or `webview2-com`).
  - NSIS vs WiX packaging toolchain details and exact Named Pipe serialization format between `freeton-app` and `freeton-service`.
- Internal module layout, automated unit/integration test suite (porting all behavioral assertions from `test_connection.py`, `test_updater.py`, and `qa_gui.py`), and CI/build PowerShell scripts.
