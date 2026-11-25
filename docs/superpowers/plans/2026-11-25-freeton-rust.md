# Freeton VPN Rust Desktop Replacement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure-Rust Windows x64 desktop replacement (`FreetonVPN.exe`, `FreetonVPNService.exe`, bundled `tunnel.dll` + `wireguard.dll`, and NSIS installer `FreetonVPN-Setup-x64.exe`) that achieves v2.4.3 desktop parity with zero external user-installed dependencies, no UAC on routine toggles, and SHA-256-verified silent upgrades.

**Architecture:** A Cargo workspace under `rust/` splits into three crates: `freeton-core` (Proton HTTPS API, pure-Rust OpenPGP + SRP auth, Ed25519->X25519 key derivation, native Win32 ICMP ping, Windows Credential Manager, server cache, and fail-closed updater), `freeton-service` (a dual-mode `LocalSystem` Windows Service acting as an authenticated Named Pipe broker + `WireGuardTunnel$FreetonVPN` runner loading `tunnel.dll` and `wireguard.dll`), and `freeton-app` (an `eframe`/`egui` `390x610` dark-glass tray flyout + on-demand `webview2-com` CAPTCHA modal). Legacy Python files remain untouched until the Rust build passes all verification gates and cutover completes.

**Tech Stack:** Rust (`x86_64-pc-windows-msvc`), `tokio`, `reqwest` (`rustls-tls`), `pgp` (pure-Rust OpenPGP), `bcrypt`, `num-bigint`, `sha2`, `ed25519-dalek` / `pkcs8`, `windows` & `windows-service`, `eframe`/`egui`, `tray-icon`, `webview2-com`, `wireguard-windows` (`tunnel.dll` via Go + MinGW), `wireguard-nt` (`wireguard.dll`), NSIS (`makensis`).

**Spec:** [2026-11-25-freeton-rust-design.md](file:///c:/Users/datpusheen123/Documents/ChatGPT/proton-node-checker/docs/superpowers/specs/2026-11-25-freeton-rust-design.md)

---

## Global Constraints

- Target platform: Windows 10 / Windows 11 x64 (`x86_64-pc-windows-msvc`) only; non-desktop `browser-extension/` and `website/` remain untouched.
- Zero external user prerequisites: no `gpg.exe`, no `proton-core`, no Playwright/`node.exe`, no separate `wireguard-installer.exe`; `[DEV] Đăng nhập bằng trình duyệt` is permanently removed.
- Proton SRP requirements: verify clearsigned modulus against embedded Ed25519 PGP key (`SRP_MODULUS_FINGERPRINT = 248097092b458509c508dac0350585c4e9518f26`), 256-byte odd modulus, SRP `Version` 3 & 4, `bcrypt` `$2y$10$` prefix with `(salt || "proton")[..16]`, `PMHash` (4x `SHA-512`), `g = 2`, constant-time `ServerProof` check, preserve non-digit 2FA/recovery characters, WebView2 CAPTCHA modal on `9001` / `12087`.
- Proton API compatibility: auth on `https://api.protonmail.ch` (`/auth/info`, `/auth`, `/auth/2fa`, `/auth/v4/refresh`); VPN endpoints fallback order `https://account.protonvpn.com/api`, `https://api.protonmail.ch`, `https://account.proton.me/api` with `x-pm-appversion: Other`; filter `Tier == 0`, physical `Status == 1 && ServicesDown == 0`, score `(ping_ms * 0.7) + (load * 0.8)` (missing ping -> `9999`, missing load -> `50`).
- Persistence parity: Windows Credential Manager targets `proton-node-checker` (`active-account`, `session:<account_lower>`) and `proton-node-checker-wireguard` (`client_config`); cache file `%LOCALAPPDATA%\FreetonVPN\servers_cache.json`.
- Tunnel verification & lifecycle: require **both** fresh handshake (`<= 180s`) for expected server `x25519PublicKey` **and** tunnel-bound UDP DNS query (`account.protonvpn.com` bound to tunnel IP, never unbound); persist tunnel metadata in `FreetonVPNService` across UI restarts/crashes, and auto-disconnect on explicit `Thoát`/`Đăng xuất` or Windows logoff/user switch.
- Security & updates: `.conf` written only under `%ProgramData%\FreetonVPN\tunnels\` with `SYSTEM`/`Administrators` ACL; validate all WireGuard config fields against directive/newline injection; Rust releases start at `3.0.0` using dedicated `version-rust.json` feed (never overwriting v2.4.3 `download_url`); fail-closed SHA-256 verification before `ShellExecuteW runas` (on GitHub Releases fallback, require `.sha256` asset or fall back to opening release page in browser).

## Review Focus

1. **Corrupted `servers_cache.json` or legacy `client_config` JSON missing newer fields (`animations_enabled`, `auto_check_update`, `debug_mode`)** — must load cleanly with v2.4.3 defaults without panicking or losing saved keys (tested in Task 3).
2. **Proton API `401` token expiration with concurrent callers (scan + key fetch)** — refresh must serialize via mutex and retry once; transient network failures must not wipe stored credentials (tested in Task 3).
3. **Non-digit Proton recovery codes in 2FA & IPv6 literal `entryIP` endpoints** — recovery codes must pass verbatim (outer-trimmed only), and IPv6 endpoints must format as `[addr]:port` while IPv4 stays `addr:port` (tested in Task 2 & Task 5).
4. **Malicious/malformed Named Pipe `Connect` payload attempting WireGuard `.conf` directive injection (`\nPostUp = ...`) or path traversal** — `freeton-service` must reject any non-base64 key, newline/control character, invalid CIDR/IP/DNS, or out-of-range port before touching disk or SCM (tested in Task 5).
5. **Updater GitHub Releases API fallback lacking `.sha256` asset or returning mismatched SHA-256** — must refuse `runas` installer launch and signal browser fallback instead (tested in Task 4).

---

## File Structure

- `.gitignore` — ignore `rust/target/`, `rust/build/`, and fetched/compiled WireGuard DLL staging artifacts.
- `rust/Cargo.toml` — workspace manifest (`freeton-core`, `freeton-service`, `freeton-app`).
- `rust/freeton-core/Cargo.toml` — core library dependencies.
- `rust/freeton-core/src/lib.rs` — public exports and shared error/config types.
- `rust/freeton-core/src/srp.rs` — embedded Ed25519 PGP key, OpenPGP cleartext verifier, SRP v3/v4 proof & server proof verification, Ed25519->X25519 key derivation.
- `rust/freeton-core/src/api.rs` — Proton auth/refresh/VPN client, CAPTCHA challenge error types, server filter/scorer.
- `rust/freeton-core/src/storage.rs` — Windows Credential Manager wrapper + `servers_cache.json` + startup registry (`HKCU\...\Run`).
- `rust/freeton-core/src/ping.rs` — Win32 `IcmpSendEcho` concurrent pinger with IP/domain deduplication.
- `rust/freeton-core/src/updater.rs` — version comparison, `version-rust.json` + GitHub Releases parser, `.sha256` verification, streaming downloader.
- `rust/freeton-core/src/wg.rs` — `.conf` validation/generation, WireGuard UAPI handshake parser, tunnel-bound UDP DNS query, Named Pipe IPC protocol types.
- `rust/freeton-service/Cargo.toml` — service binary dependencies.
- `rust/freeton-service/src/main.rs` — CLI mode dispatch (`--service`, `--tunnel <conf>`, `--install`, `--uninstall`).
- `rust/freeton-service/src/broker.rs` — `FreetonVPNService` SCM entrypoint, Named Pipe server with SDDL DACL, WTS logoff listener, serialized tunnel state + metadata.
- `rust/freeton-service/src/tunnel_runner.rs` — `WireGuardTunnel$FreetonVPN` SCM registration/wait, `tunnel.dll` dynamic loader (`WireGuardTunnelService`), WireGuard named pipe handshake reader, restricted `%ProgramData%\FreetonVPN\tunnels\` writer.
- `rust/freeton-app/Cargo.toml` — GUI app dependencies & Windows manifest/icon build script (`build.rs`).
- `rust/freeton-app/build.rs` — embeds `freeton_icon.ico`, DPI-aware manifest, and Windows version resource (`3.0.0.0`).
- `rust/freeton-app/src/main.rs` — `eframe` app bootstrap, Windows 11 DWM rounded corners, tray-area positioning, single-instance guard.
- `rust/freeton-app/src/state.rs` — authoritative `AppState`, `UiCommand`/`WorkerEvent` state machine, async worker coordinator.
- `rust/freeton-app/src/captcha.rs` — transient Win32 + `webview2-com` CAPTCHA modal capturing `postMessage` token.
- `rust/freeton-app/src/tray.rs` — `tray-icon` setup, dynamic colored status icons, context menu actions.
- `rust/freeton-app/src/ui/mod.rs` — theme tokens (`#101419`, `#1b222b`, `#8bd5c5`), reusable pill/card/toggle widgets, Vietnamese + emoji font setup.
- `rust/freeton-app/src/ui/login.rs` — Login Gate + SRP Login views.
- `rust/freeton-app/src/ui/home.rs` — Home Dashboard + status card + iOS toggle + timer pill + public IP display.
- `rust/freeton-app/src/ui/drawer.rs` — Server Picker Drawer (search, country dropdown, quick pills, sort chips, virtualized list).
- `rust/freeton-app/src/ui/dialogs.rs` — Settings (with 750ms middle-mouse Dev Mode), About, UpdateDialog, Service Repair prompt.
- `rust/scripts/build_windows.ps1` — builds `tunnel.dll` (pinned `wireguard-windows`), fetches/verifies `wireguard.dll`, compiles workspace, builds NSIS installer + `.sha256` + `version-rust.json`.
- `rust/installer/freeton.nsi` — NSIS script stopping services cleanly, installing to `$PROGRAMFILES64\FreetonVPN`, registering `FreetonVPNService` + DACL, silent `/S` upgrade & clean uninstall.
- `version-rust.json` — root release manifest for Rust v3.0.0+ installer channel.

---

### Task 1: Development Toolchain & Cargo Workspace Setup

**Files:**
- Modify: `.gitignore`
- Create: `rust/Cargo.toml`
- Create: `rust/freeton-core/Cargo.toml`
- Create: `rust/freeton-core/src/lib.rs`
- Create: `rust/freeton-service/Cargo.toml`
- Create: `rust/freeton-service/src/main.rs`
- Create: `rust/freeton-app/Cargo.toml`
- Create: `rust/freeton-app/src/main.rs`

**Interfaces:**
- Produces: Compilable Cargo workspace `rust/Cargo.toml` targeting `x86_64-pc-windows-msvc` with stub test target in `freeton-core`.

- [ ] **Step 1: Verify or install Windows build prerequisites (`rustup`, MSVC Build Tools + Windows SDK, Go, NSIS)**

Run check first:
`rustc --version; cargo --version; go version; makensis -VERSION`
If missing, install via `winget` (`Rustlang.Rustup`, `Microsoft.VisualStudio.2022.BuildTools` with C++ & Windows 10/11 SDK workload, `GoLang.Go`, `NSIS.NSIS`), set default toolchain to `stable-x86_64-pc-windows-msvc`, and re-verify all four commands succeed.

- [ ] **Step 2: Update `.gitignore` for Rust build outputs and staged WireGuard DLLs**

Append to `.gitignore`:
```gitignore
# Rust workspace & staged WireGuard binaries
rust/target/
rust/build/
rust/assets/bin/
```

- [ ] **Step 3: Create failing workspace smoke test**

Create `rust/Cargo.toml` with members `["freeton-core", "freeton-service", "freeton-app"]`, minimal crate manifests, stub `main.rs` files, and in `rust/freeton-core/src/lib.rs` add:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn workspace_version_matches_major_three() {
        assert!(crate::APP_VERSION.starts_with("3."));
    }
}
```
Omit `APP_VERSION` initially so compilation fails as expected.

- [ ] **Step 4: Run test to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core`
Expected: FAIL with unresolved item `crate::APP_VERSION`.

- [ ] **Step 5: Add `pub const APP_VERSION: &str = "3.0.0";` and `pub const APP_NAME: &str = "Freeton VPN";` in `rust/freeton-core/src/lib.rs` and verify**

Run: `cargo check --manifest-path rust/Cargo.toml --workspace && cargo test --manifest-path rust/Cargo.toml -p freeton-core`
Expected: PASS (1 test passed).

- [ ] **Step 6: Commit workspace skeleton**

```bash
git add .gitignore rust/Cargo.toml rust/freeton-core rust/freeton-service rust/freeton-app
git commit -m "chore: initialize Rust workspace for Freeton VPN"
```

---

### Task 2: Pure-Rust Proton SRP, OpenPGP Modulus Verification & Key Derivation

**Files:**
- Modify: `rust/freeton-core/Cargo.toml` (add `pgp`, `bcrypt`, `num-bigint`, `sha2`, `base64`, `ed25519-dalek`, `pkcs8`, `rand`, `zeroize`, `thiserror`)
- Create: `rust/freeton-core/src/srp.rs`
- Modify: `rust/freeton-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::APP_VERSION`.
- Produces:
  - `pub struct SrpChallenge { pub version: u8, pub modulus_armored: String, pub server_ephemeral_b64: String, pub salt_b64: String }`
  - `pub struct SrpProof { pub client_ephemeral_b64: String, pub client_proof_b64: String, pub expected_server_proof: Vec<u8> }`
  - `pub fn verify_and_read_modulus(armored: &str) -> Result<([u8; 256], num_bigint::BigUint), SrpError>`
  - `pub fn create_srp_proof(challenge: &SrpChallenge, username: &str, password: &str) -> Result<SrpProof, SrpError>`
  - `pub fn verify_server_proof(expected: &[u8], actual_b64: &str) -> bool`
  - `pub fn ed25519_pem_to_wireguard_privkey(priv_pem: &str) -> Result<String, SrpError>`

- [ ] **Step 1: Write failing unit tests in `rust/freeton-core/src/srp.rs`**

Include tests verifying:
1. `test_rejects_unsigned_or_tampered_modulus`: passing unsigned text or modified modulus signature returns `Err(SrpError::InvalidModulusSignature)`.
2. `test_rejects_unsupported_srp_version`: `version: 2` returns `Err(SrpError::UnsupportedVersion(2))`.
3. `test_srp_proof_deterministic_vector_and_constant_time_server_proof`: test `pm_hash` length (256 bytes), `bcrypt` `$2y$10$` salt encoding (22 chars from `./A-Za-z0-9`), little-endian 256-byte `BigUint` roundtrip, and `verify_server_proof` returning `true` on exact match and `false` on 1-bit flip.
4. `test_ed25519_pem_to_wireguard_privkey_matches_sha512_clamping`: given a known PKCS8 Ed25519 PEM, output base64 decodes to 32 bytes with `(bytes[0] & 0x07) == 0`, `(bytes[31] & 0x80) == 0`, and `(bytes[31] & 0x40) == 0x40`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core srp`
Expected: FAIL (`srp` module/functions not defined).

- [ ] **Step 3: Implement `rust/freeton-core/src/srp.rs`**

Embed exact `SRP_MODULUS_KEY` and `SRP_MODULUS_FINGERPRINT` (`248097092b458509c508dac0350585c4e9518f26`) matching `browser-extension/shared/proton-srp.js`. Use `pgp` crate to parse public key, assert fingerprint match, parse `CleartextSignedMessage`, verify signature, decode base64 256-byte little-endian modulus, assert 2048-bit odd integer. Implement `bcrypt` `$2y$10$` formatting over `(salt || "proton")[..16]`, 4-round `SHA-512` `PMHash`, `modpow` SRP proof math, and `pkcs8` + `sha2` Ed25519->X25519 clamping.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core srp`
Expected: PASS (all 4 tests pass).

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-core/Cargo.toml rust/freeton-core/src/lib.rs rust/freeton-core/src/srp.rs
git commit -m "feat(core): add pure-Rust Proton SRP and OpenPGP modulus verifier"
```

---

### Task 3: Proton API Client, Windows Credential Manager Storage & Server Cache

**Files:**
- Modify: `rust/freeton-core/Cargo.toml` (add `reqwest`, `tokio`, `serde`, `serde_json`, `windows`)
- Create: `rust/freeton-core/src/storage.rs`
- Create: `rust/freeton-core/src/api.rs`
- Modify: `rust/freeton-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::srp::{SrpChallenge, create_srp_proof, verify_server_proof, ed25519_pem_to_wireguard_privkey}`.
- Produces:
  - `pub struct ClientConfig` (with `private_key`, `public_key`, `expiration: i64`, `address`, `dns`, `port`, `animations_enabled: bool`, `auto_check_update: bool`, `debug_mode: bool`, defaulting missing legacy fields cleanly)
  - `pub struct StoredAuthSession { pub uid: String, pub access_token: String, pub refresh_token: String, pub scopes: Vec<String> }`
  - `pub trait CredentialStore` + `WindowsCredentialStore` (targets `proton-node-checker` / `proton-node-checker-wireguard`)
  - `pub struct ServerCacheManager` (`load(path) -> (Option<Value>, Vec<ServerNode>)`, `save(path, payload, servers)`)
  - `pub struct StartupManager` (`is_enabled() -> bool`, `set_enabled(exe_path: &Path, enable: bool) -> Result<(), StorageError>`)
  - `pub struct ProtonClient` (`login_srp(user, pass, human_verification: Option<HumanVerificationToken>) -> Result<LoginOutcome, ApiError>`, `submit_2fa(pending: &StoredAuthSession, code: &str) -> Result<StoredAuthSession, ApiError>`, `fetch_logicals() -> Result<Vec<ServerNode>, ApiError>`, `ensure_wg_key(force: bool) -> Result<ClientConfig, ApiError>`, `fetch_public_ip() -> Result<String, ApiError>`)

- [ ] **Step 1: Write failing unit tests in `storage.rs` and `api.rs`**

Include tests covering:
1. `test_client_config_defaults_when_legacy_json_omits_fields` (Review Focus #1): deserializing `{"private_key":"abc","expiration":0}` preserves `"abc"` and fills defaults (`address == "10.2.0.2/32"`, `dns == "10.2.0.1, 1.1.1.1"`, `port == "51820"`, `animations_enabled == true`, `auto_check_update == true`, `debug_mode == false`).
2. `test_server_cache_handles_corrupt_json_gracefully` (Review Focus #1): corrupted file returns `(None, vec![])` instead of panicking/erroring.
3. `test_select_free_servers_filters_tier_zero_and_usable_physical`: mirrors `select_free_servers_with_wg` (`Tier == 0`, physical `Status == 1 && ServicesDown == 0`).
4. `test_2fa_code_preserves_recovery_characters` (Review Focus #3): `" abcd-1234 "` trims outer whitespace to `"abcd-1234"` without stripping letters/hyphens.
5. `test_concurrent_401_triggers_single_refresh_and_retries` (Review Focus #2): using a mock `CredentialStore` and local `tokio` mock HTTP server, two parallel `api_request` calls hitting `401` trigger `/auth/v4/refresh` **once**, persist updated tokens, and both retry and succeed; a network error on refresh preserves existing stored credentials.
6. `test_human_verification_9001_extracts_force_web_messaging_url`: mock `9001` JSON returns `LoginOutcome::NeedsHumanVerification { url, methods }` with `ForceWebMessaging=1` appended.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core storage api`
Expected: FAIL.

- [ ] **Step 3: Implement `storage.rs` and `api.rs`**

Implement Win32 `CredReadW` / `CredWriteW` / `CredDeleteW` (UTF-16 `CRED_TYPE_GENERIC`), `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` helper, `servers_cache.json` under `%LOCALAPPDATA%\FreetonVPN\`, and `ProtonClient` with `tokio::sync::Mutex` around token refresh and WireGuard key registration (`within_seconds = 7200`).

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core storage api`
Expected: PASS (all 6 tests pass).

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-core/Cargo.toml rust/freeton-core/src/lib.rs rust/freeton-core/src/storage.rs rust/freeton-core/src/api.rs
git commit -m "feat(core): add Proton API client, Credential Manager storage, and cache"
```

---

### Task 4: Native ICMP Pinger, Server Scorer & Fail-Closed Updater

**Files:**
- Modify: `rust/freeton-core/Cargo.toml` (add `futures` if needed, `Win32_NetworkManagement_IpHelper` feature on `windows`)
- Create: `rust/freeton-core/src/ping.rs`
- Create: `rust/freeton-core/src/updater.rs`
- Modify: `rust/freeton-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::api::ServerNode`.
- Produces:
  - `pub enum SortMode { Best, Ping, Load, Name }`
  - `pub fn score_server(node: &ServerNode) -> f64`
  - `pub fn sort_and_filter_servers(servers: &[ServerNode], country: Option<&str>, query: &str, sort: SortMode) -> (Option<ServerNode>, Vec<ServerNode>)`
  - `pub async fn ping_servers<F>(servers: &mut [ServerNode], timeout_ms: u32, max_workers: usize, on_progress: F)`
  - `pub struct UpdateInfo { pub version: String, pub release_date: String, pub title: String, pub changelog: Vec<String>, pub download_url: String, pub file_size_bytes: u64, pub sha256: String, pub mandatory: bool, pub min_supported_version: String }`
  - `pub enum UpdateAction { LaunchVerifiedInstaller(PathBuf), OpenReleasePageInBrowser(String) }`
  - `pub fn is_newer_version(current: &str, remote: &str) -> bool`
  - `pub async fn fetch_update_info(manifest_url: Option<&str>, repo: Option<&str>) -> Result<Option<UpdateInfo>, UpdateError>`
  - `pub async fn download_and_verify_update(info: &UpdateInfo, dest_dir: &Path, on_progress: impl Fn(u64, u64, f32)) -> Result<UpdateAction, UpdateError>`

- [ ] **Step 1: Write failing unit tests in `ping.rs` and `updater.rs`**

Port all assertions from `test_updater.py` and `test_connection.py::test_zero_load_is_better_than_fifty_percent`, plus Review Focus #5:
1. `test_zero_load_is_better_than_fifty_percent`: `score_server` picks `(ping 20, load 0)` over `(ping 20, load 50)`.
2. `test_deduplicated_ping_updates_all_matching_targets`: using an injected pinger closure/trait, servers sharing `pingTarget` only probe once and all receive the measured latency; `127.0.0.1` real Win32 `IcmpSendEcho` smoke test succeeds locally.
3. `test_version_comparison_and_manifest_parsing`: matches `test_updater.py` (`2.4 < 2.4.1`, `3.0-beta` -> `(3, 0)`, `v2.4.0 == 2.4`).
4. `test_github_fallback_parses_companion_sha256_or_fails_closed` (Review Focus #5): when GitHub Releases JSON has `FreetonVPN-Setup-x64.exe` + `FreetonVPN-Setup-x64.exe.sha256`, `sha256` is populated; when `.sha256` asset is absent (`sha256` empty), `download_and_verify_update` returns `Ok(UpdateAction::OpenReleasePageInBrowser(...))` and never writes/executes an unverified installer; when `sha256` mismatches downloaded bytes, returns `Err(UpdateError::ChecksumMismatch)` and deletes partial file.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core ping updater`
Expected: FAIL.

- [ ] **Step 3: Implement `ping.rs` and `updater.rs`**

Implement Win32 `IcmpCreateFile` / `IcmpSendEcho` (resolving hostname via `tokio::net::lookup_host` when `pingTarget` is a domain, falling back to `None` cleanly on timeout/unreachable) with semaphore-bounded `max_workers = 16`, `timeout_ms = 800`. Implement `updater.rs` reading `version-rust.json` first, falling back to GitHub Releases API for `FreetonVPN-Setup-x64.exe` + `.sha256` companion asset, enforcing fail-closed SHA-256 verification.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core ping updater`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-core/Cargo.toml rust/freeton-core/src/lib.rs rust/freeton-core/src/ping.rs rust/freeton-core/src/updater.rs
git commit -m "feat(core): add native Win32 ICMP pinger, server scorer, and fail-closed updater"
```

---

### Task 5: WireGuard Config Security Validation, Handshake/DNS Verifier & Named Pipe Protocol

**Files:**
- Create: `rust/freeton-core/src/wg.rs`
- Modify: `rust/freeton-core/src/lib.rs`

**Interfaces:**
- Consumes: `crate::api::ServerNode`, `crate::storage::ClientConfig`.
- Produces:
  - `pub const SERVICE_PIPE_NAME: &str = r"\\.\pipe\FreetonVPNService";`
  - `pub const DEFAULT_TUNNEL_NAME: &str = "FreetonVPN";`
  - `pub struct ValidatedTunnelSpec { pub server_name: String, pub country: String, pub domain: String, pub entry_ip: String, pub server_pubkey: String, pub private_key: String, pub address: String, pub dns: String, pub port: u16 }`
  - `pub enum ServiceRequest { Connect(ValidatedTunnelSpec), Disconnect, Status, ShutdownTunnelOnExit }`
  - `pub struct ActiveTunnelInfo { pub server_name: String, pub country: String, pub entry_ip: String, pub x25519_pubkey: String, pub address: String, pub dns: String, pub port: u16, pub connected_at_unix: i64 }`
  - `pub enum TunnelHealthState { Disconnected, Connecting, Verifying(ActiveTunnelInfo), Connected(ActiveTunnelInfo), Unverified { info: ActiveTunnelInfo, reason: String } }`
  - `pub fn validate_and_build_conf(server: &ServerNode, config: &ClientConfig) -> Result<(ValidatedTunnelSpec, String), WgError>`
  - `pub fn parse_uapi_latest_handshake(uapi_output: &str, expected_pubkey_hex_or_b64: &str) -> i64`
  - `pub fn dns_responds_through_tunnel(address: &str, dns: &str, timeout: Duration) -> bool`

- [ ] **Step 1: Write failing unit tests in `rust/freeton-core/src/wg.rs`**

Include tests covering:
1. `test_rejects_conf_injection_and_invalid_fields` (Review Focus #4): newlines or `[Peer]`/`PostUp` in `address`, `dns`, `entry_ip`, or invalid base64/length for `private_key`/`x25519PublicKey`, or port `0` / `70000` all return `Err(WgError::InvalidInput(...))`.
2. `test_ipv6_endpoint_is_bracketed_in_conf` (Review Focus #3): IPv6 `entryIP` (`2001:db8::1`) renders `Endpoint = [2001:db8::1]:51820`; IPv4 renders `Endpoint = 192.0.2.1:51820`.
3. `test_parse_uapi_handshake_matches_expected_peer_only`: parses WireGuard UAPI `get=1` response (`public_key=<hex>`, `last_handshake_time_sec=<unix>`), ignoring other peers and returning `0` when missing or zero.
4. `test_dns_query_packet_and_response_validation` (matching `test_connection.py::HealthChecks`): verifies DNS response validation rejects mismatched query ID, query flag (`0x0100`), RCODE error (`0x8182`), NXDOMAIN (`0x8380`), or zero answers, and accepts valid `0x8180` with `answers >= 1`; binding failure never sends unbound packet.
5. `test_service_ipc_roundtrip_serialization`: `ServiceRequest` and `TunnelHealthState` JSON framing roundtrips cleanly.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core wg`
Expected: FAIL.

- [ ] **Step 3: Implement `rust/freeton-core/src/wg.rs`**

Validate all inputs strictly (32-byte base64 WireGuard keys, valid `IpAddr` / `IpNet` parsing, no control chars/newlines, port `1..=65535`). Implement WireGuard UAPI key/handshake parser (`public_key=` hex conversion from base64 X25519 key) and raw UDP DNS socket bound to parsed tunnel local IP via `std::net::UdpSocket`.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-core wg`
Expected: PASS (all 5 tests pass).

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-core/src/lib.rs rust/freeton-core/src/wg.rs
git commit -m "feat(core): add WireGuard config validation, UAPI handshake, DNS probe, and IPC types"
```

---

### Task 6: `freeton-service` — Privileged Broker & `tunnel.dll` Windows Service

**Files:**
- Modify: `rust/freeton-service/Cargo.toml` (add `freeton-core`, `windows-service`, `windows`, `tokio`, `serde_json`, `tracing`)
- Create: `rust/freeton-service/src/broker.rs`
- Create: `rust/freeton-service/src/tunnel_runner.rs`
- Modify: `rust/freeton-service/src/main.rs`

**Interfaces:**
- Consumes: `freeton_core::wg::{SERVICE_PIPE_NAME, DEFAULT_TUNNEL_NAME, ServiceRequest, TunnelHealthState, ActiveTunnelInfo, validate_and_build_conf, parse_uapi_latest_handshake, dns_responds_through_tunnel}`.
- Produces: `FreetonVPNService.exe` supporting `--service`, `--tunnel <conf_path>`, `--install`, `--uninstall`.

- [ ] **Step 1: Write failing unit/state-machine tests in `rust/freeton-service/src/broker.rs` and `tunnel_runner.rs`**

Using mocked SCM + WireGuard UAPI + DNS traits (mirroring `test_connection.py::TunnelLifecycle`):
1. `test_switch_waits_for_old_tunnel_service_absence_before_install`: `Connect` calls uninstall -> waits state `0` -> writes `.conf` -> installs -> waits `SERVICE_RUNNING` -> polls handshake -> checks DNS.
2. `test_handshake_timeout_and_dns_failure_cleanup_conf_and_service`: failed verification uninstalls tunnel and deletes `.conf`, returning distinct handshake vs DNS error message.
3. `test_uninstall_failure_retains_conf_and_propagates_error`.
4. `test_status_hydrates_active_tunnel_info_and_logoff_triggers_teardown`: verifies `Status` returns `ActiveTunnelInfo` across simulated UI disconnect/reconnect, while `ShutdownTunnelOnExit` or `SessionLogoff` event tears down the tunnel.
5. `test_rejects_conf_path_outside_programdata_tunnels`: `--tunnel` helper refuses paths not canonicalized inside `%ProgramData%\FreetonVPN\tunnels\`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-service`
Expected: FAIL.

- [ ] **Step 3: Implement `tunnel_runner.rs`, `broker.rs`, and `main.rs`**

- `tunnel_runner.rs`: `--tunnel <conf>` checks canonical path inside `%ProgramData%\FreetonVPN\tunnels\`, loads sibling `tunnel.dll` via `LoadLibraryW` (requiring `wireguard.dll` alongside it), invokes `WireGuardTunnelService`, and cleans up cleanly on stop. Also implements SCM operations (`OpenSCManagerW`, `CreateServiceW` with `SERVICE_SID_TYPE_UNRESTRICTED` and `Nsi\0TcpIp\0\0` dependencies, `StartServiceW`, `ControlService(STOP)`, `DeleteService`, `QueryServiceStatusEx`) and reads `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\FreetonVPN` (`get=1\n\n`) for peer handshake timestamps.
- `broker.rs`: `FreetonVPNService` registers `SERVICE_CONTROL_SESSIONCHANGE` (`WTS_SESSION_LOGOFF`), hosts async Named Pipe `\\.\pipe\FreetonVPNService` with SDDL DACL (`D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`), serializes tunnel mutations via mutex, re-validates incoming `ValidatedTunnelSpec` before writing restricted `.conf`, and stores `ActiveTunnelInfo`.
- `main.rs`: handles `--install` / `--uninstall` (with `sc` / Win32 API setup granting `IU` start/query rights on `FreetonVPNService`), `--service`, and `--tunnel`.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-service`
Expected: PASS (all 5 tests pass).

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-service
git commit -m "feat(service): add FreetonVPNService broker and tunnel.dll runner"
```

---

### Task 7: Transient Edge WebView2 CAPTCHA Modal

**Files:**
- Modify: `rust/freeton-app/Cargo.toml` (add `webview2-com`, `windows`)
- Create: `rust/freeton-app/src/captcha.rs`

**Interfaces:**
- Consumes: `freeton_core::api::HumanVerificationChallenge`.
- Produces: `pub fn solve_captcha_blocking(url: &str, timeout: Duration) -> Result<String, CaptchaError>` (validates `https://verify.proton.me` / `account.proton.me` / `account.protonvpn.com` host, injects `CAPTCHA_CAPTURE_SCRIPT` on navigation, listens for `postMessage` token of length `>= 20`, closes popup immediately on capture or timeout).

- [ ] **Step 1: Write failing unit tests in `rust/freeton-app/src/captcha.rs`**

Include tests for:
1. `test_validate_captcha_url_enforces_proton_https_and_force_web_messaging`: rejects `http://` or non-Proton host; appends `ForceWebMessaging=1` preserving existing params.
2. `test_extract_token_from_post_message_variants`: extracts string tokens (`len >= 20`) from raw string or JSON (`Token`, `token`, `verificationToken`, `HumanVerificationToken`, `humanVerificationToken`), ignoring short strings or `http(s)://` URLs.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app captcha`
Expected: FAIL.

- [ ] **Step 3: Implement `rust/freeton-app/src/captcha.rs`**

Implement URL validation, token extraction helper, and a dedicated STA Win32 popup window (`520x720`, centered, dark titlebar) embedding `webview2-com` (`CreateCoreWebView2Environment` + `AddScriptToExecuteOnDocumentCreated` forwarding captured token via `window.chrome.webview.postMessage(...)`), returning the token cleanly or `CaptchaError::Cancelled` / `CaptchaError::Timeout` when closed/expired.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app captcha`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-app/Cargo.toml rust/freeton-app/src/captcha.rs
git commit -m "feat(app): add transient WebView2 CAPTCHA verification modal"
```

---

### Task 8: `freeton-app` State Machine, Tray Icon & Main Flyout Views (Login, SRP, Home, Drawer)

**Files:**
- Modify: `rust/freeton-app/Cargo.toml` (add `freeton-core`, `eframe`, `egui`, `tray-icon`, `tokio`, `windows`, `image`, `rfd`)
- Create: `rust/freeton-app/build.rs`
- Create: `rust/freeton-app/src/state.rs`
- Create: `rust/freeton-app/src/tray.rs`
- Create: `rust/freeton-app/src/ui/mod.rs`
- Create: `rust/freeton-app/src/ui/login.rs`
- Create: `rust/freeton-app/src/ui/home.rs`
- Create: `rust/freeton-app/src/ui/drawer.rs`
- Modify: `rust/freeton-app/src/main.rs`

**Interfaces:**
- Consumes: `freeton-core` (`ProtonClient`, `WindowsCredentialStore`, `ServerCacheManager`, `ping_servers`, `sort_and_filter_servers`, `SERVICE_PIPE_NAME`), `crate::captcha::solve_captcha_blocking`.
- Produces: Complete `AppState` state machine, tray controller, and main 4 views (`Login`, `Srp`, `Home`, `Drawer`) inside a `390x610` borderless rounded dark-glass window.

- [ ] **Step 1: Write failing state-machine tests in `rust/freeton-app/src/state.rs`**

Port UI regression behaviors from `test_connection.py::UIRegressions` and `qa_gui.py`:
1. `test_repeated_connect_ignored_while_connecting_or_disconnecting`.
2. `test_stale_scan_does_not_overwrite_manual_selection_while_connecting`.
3. `test_stale_status_event_from_old_generation_is_discarded`.
4. `test_hydrates_connected_state_from_running_service_on_startup`: receiving `TunnelHealthState::Connected(info)` sets `connected_server`, `vpn_connect_time`, and `selected_server` accurately.
5. `test_drawer_filtering_sorting_and_empty_search_state`: validates `sort_and_filter_servers` integration across country pills, search text, and sort modes.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app state`
Expected: FAIL.

- [ ] **Step 3: Implement `build.rs`, `state.rs`, `tray.rs`, `ui/mod.rs`, `ui/login.rs`, `ui/home.rs`, `ui/drawer.rs`, and `main.rs`**

- `build.rs`: embed `../../freeton_icon.ico` and version info (`3.0.0.0`) via `winresource`.
- `state.rs`: `AppState`, `UiCommand`, `WorkerEvent`, generation-tagged async coordinator (`tokio::runtime::Runtime`) talking to `FreetonVPNService` over Named Pipe (`\\.\pipe\FreetonVPNService`), handling auto-scan + background key refresh (`needs_key_refresh`), CAPTCHA retry loop, public IP resolution (`api.ipify.org`), and clean disconnect on `Thoát`.
- `tray.rs`: programmatic 64x64 RGBA rounded-square status icons (violet idle, amber connecting/unverified, emerald connected) + `Mở Freeton VPN`, `Bật/Tắt VPN`, `Cài đặt`, `Giới thiệu`, `Thoát`.
- `ui/`: dark-glass palette (`#101419`, `#151b22`, `#1b222b`, `#252f3a`, `#8bd5c5`), `Segoe UI` + `Segoe UI Emoji` fallback font loading from `C:\Windows\Fonts\`, draggable top bar, Win11 DWM rounded corners, `show_rows` virtualized server scrolling, animated slide/toggle transitions honoring `animations_enabled`, and `rfd` native file picker for Dev `.conf` export.

- [ ] **Step 4: Run tests and release check**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app state && cargo check --manifest-path rust/Cargo.toml -p freeton-app`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-app
git commit -m "feat(app): add native Rust GUI, tray controller, and async state machine"
```

---

### Task 9: Settings, About, UpdateDialog, Service Repair & Dev Mode

**Files:**
- Create: `rust/freeton-app/src/ui/dialogs.rs`
- Modify: `rust/freeton-app/src/ui/mod.rs`
- Modify: `rust/freeton-app/src/state.rs`

**Interfaces:**
- Consumes: `AppState`, `freeton_core::storage::{StartupManager, ClientConfig}`, `freeton_core::updater::{UpdateInfo, UpdateAction, download_and_verify_update}`.
- Produces: Settings dialog (Startup, Animations, Auto-check update, Service health/repair UAC button `FreetonVPNService.exe --install`, Key status/Fetch API Key/`rfd` Import `.conf`, Private Key/DNS/Port, 750ms middle-mouse hold Dev Mode toggle), About dialog, and UpdateDialog (changelog + progress bar + verified `ShellExecuteW runas` installer launch + clean UI exit, or browser fallback when `.sha256` missing).

- [ ] **Step 1: Write failing unit tests in `rust/freeton-app/src/ui/dialogs.rs` (or `state.rs`)**

Include tests verifying:
1. `test_middle_mouse_hold_750ms_toggles_dev_mode_and_persists`: holding < 750ms does not toggle; holding >= 750ms flips `debug_mode` and emits save command.
2. `test_import_conf_parses_private_key_address_dns_and_sets_static_expiration`: parsing sample `.conf` updates `private_key`, `address`, `dns`, and sets `expiration = 0`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --manifest-path rust/Cargo.toml -p freeton-app dialogs`
Expected: FAIL.

- [ ] **Step 3: Implement `rust/freeton-app/src/ui/dialogs.rs` and wire into `ui/mod.rs` + `state.rs`**

Implement all 3 dialogs + service health check indicator (`FreetonVPNService` reachable vs missing/stopped -> one-click UAC `ShellExecuteW runas` running `FreetonVPNService.exe --install`). Wire Dev Mode `Xuất .conf` buttons on Home and Server Drawer and detailed error modal with raw diagnostic details when `debug_mode == true`.

- [ ] **Step 4: Run full Cargo workspace tests**

Run: `cargo test --manifest-path rust/Cargo.toml --workspace`
Expected: PASS (all unit tests across `freeton-core`, `freeton-service`, `freeton-app` pass).

- [ ] **Step 5: Commit**

```bash
git add rust/freeton-app
git commit -m "feat(app): add Settings, About, UpdateDialog, service repair, and Dev Mode"
```

---

### Task 10: `tunnel.dll` / `wireguard.dll` Build Pipeline, NSIS Installer & Cutover

**Files:**
- Create: `rust/scripts/build_windows.ps1`
- Create: `rust/installer/freeton.nsi`
- Create: `version-rust.json`
- Modify: `README.md` (document Rust build/installer once verified)

**Interfaces:**
- Consumes: Compiled release binaries `FreetonVPN.exe`, `FreetonVPNService.exe`, `freeton_icon.ico`.
- Produces: `dist/FreetonVPN-Setup-x64.exe`, `dist/FreetonVPN-Setup-x64.exe.sha256`, and updated `version-rust.json`.

- [ ] **Step 1: Write `rust/scripts/build_windows.ps1` and `rust/installer/freeton.nsi`**

- `build_windows.ps1`:
  1. Clones/caches pinned `wireguard-windows` tag (e.g. `v0.5.3` or latest verified release tag), invokes `embeddable-dll-service\build.bat`, verifies `amd64\tunnel.dll` exists, and stages it into `rust/assets/bin/tunnel.dll`.
  2. Downloads pinned official `wireguard-nt` archive from `https://download.wireguard.com/wireguard-nt/`, verifies SHA-256 checksum, extracts `bin/amd64/wireguard.dll` into `rust/assets/bin/wireguard.dll`.
  3. Runs `cargo test --manifest-path rust/Cargo.toml --workspace` and `cargo build --manifest-path rust/Cargo.toml --release`.
  4. Runs `makensis` on `rust/installer/freeton.nsi` to output `dist/FreetonVPN-Setup-x64.exe`, computes SHA-256 (`dist/FreetonVPN-Setup-x64.exe.sha256`), and updates `version-rust.json` fields (`version`, `file_size_bytes`, `sha256`, `download_url`).
- `freeton.nsi`:
  1. Requests `admin` execution level, installs into `$PROGRAMFILES64\FreetonVPN\`.
  2. Stops `WireGuardTunnel$FreetonVPN`, stops `FreetonVPNService`, kills running `FreetonVPN.exe` cleanly before overwriting `FreetonVPN.exe`, `FreetonVPNService.exe`, `tunnel.dll`, `wireguard.dll`.
  3. Executes `FreetonVPNService.exe --install` to register/update `FreetonVPNService` + non-admin pipe DACL.
  4. Writes Start Menu + uninstaller registry entries (`FreetonVPNService.exe --uninstall` and removes `$PROGRAMFILES64\FreetonVPN` + `$APPDATA` / `$PROGRAMDATA\FreetonVPN\tunnels` on uninstall).
  5. Relaunches `FreetonVPN.exe` after silent `/S` upgrade (or when checkbox ticked in interactive setup).

- [ ] **Step 2: Run full build script and verify artifacts**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File rust\scripts\build_windows.ps1`
Expected: `cargo test` passes, `tunnel.dll` and `wireguard.dll` staged, `dist/FreetonVPN-Setup-x64.exe` and `.sha256` produced cleanly.

- [ ] **Step 3: Perform end-to-end verification on Windows & legacy cutover cleanup**

1. Install `dist/FreetonVPN-Setup-x64.exe` (or run silent `/S` test), verify `FreetonVPNService` exists and allows non-admin pipe connect/status.
2. Launch `FreetonVPN.exe` as standard user: verify tray icon, login/SRP/2FA (and CAPTCHA if triggered), ping scan speed, VPN connect -> verify `WireGuardTunnel$FreetonVPN` handshake + tunnel-bound DNS + no UAC prompt, disconnect, exit cleanup, and Dev Mode toggle.
3. Once verified and user confirms cutover, archive/remove legacy Python desktop source/spec files (`proton_warp_material_gui.py`, `windows_vpn.py`, `updater.py`, `main.py`, `FreetonVPN.spec`, `build_exe.ps1`, `pyinstaller_hooks/`, `requirements.txt`, `run_*.bat`, `qa_gui.py`, `smoke_windows_gui.py`, `test_connection.py`, `test_updater.py`) and update `README.md`.

- [ ] **Step 4: Commit release pipeline and cutover**

```bash
git add rust/scripts/build_windows.ps1 rust/installer/freeton.nsi version-rust.json README.md
git commit -m "build: add WireGuard DLL staging, NSIS installer, and Rust release pipeline"
```
