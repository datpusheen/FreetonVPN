# Freeton Browser VPN extension

The extension lists active Proton VPN Free servers, shows their current load, and routes browser web traffic through Proton's HTTPS proxy. It protects browser traffic only; it does not create or control a desktop WireGuard tunnel, and it cannot measure ICMP ping.

## Proton sign-in

The popup opens a dedicated extension tab for sign-in. The tab stays open while you move to Proton's CAPTCHA page or an authenticator for 2FA, so its login form and status do not disappear when the popup loses focus. After sign-in, close the tab and use the popup to choose a server and connect. The extension performs Proton's SRP login directly: it verifies Proton's signed SRP modulus, derives the client proof locally, verifies the server proof, and supports a one-time 2FA code. The password is never written to diagnostics or extension storage. If a human-verification challenge appears, it stays temporarily in the sign-in tab's memory for an automatic retry; closing or reloading that tab clears it.

Authenticated Proton tokens are held in `storage.session` and cleared when the browser session ends or when you choose **Đăng xuất**. Proxy credentials are also held in session storage and expire after about 20 minutes. The extension does not fall back to a direct connection when an active proxy token expires; renew or disconnect it in the popup.

If Proton requires CAPTCHA or another human-verification challenge, the extension opens the challenge URL returned by Proton in a small popup window. Complete the challenge there; the window closes after the extension receives Proton's verification response, then the sign-in tab automatically retries SRP with the password already entered. The extension does not solve or bypass the challenge. Security-key-only FIDO2 sign-in is not supported yet.

The Proton API app-version header is endpoint-specific: the browser proxy-token request uses Proton's browser-extension version (`browser-vpn@…`), while the SRP sign-in flow keeps its own compatibility header. This is separate from Freeton's extension package version.

## Build packages

From the repository root, install the pinned JavaScript dependencies once, then build:

```powershell
npm ci --prefix .\browser-extension
.\browser-extension\build.ps1
```

The script creates loadable folders and ZIP archives in `dist\browser-extension\`:

- `chromium\` and `Freeton-Browser-VPN-chromium.zip` — Chromium Manifest V3 package.
- `firefox\` and `Freeton-Browser-VPN-firefox.zip` — Firefox Manifest V3 WebExtension package.

The packages include the bcrypt and OpenPGP license texts as `LICENSE-bcryptjs.txt` and `LICENSE-openpgp.txt` at the package root.

## Install for local use

### Chromium browsers

1. Open `chrome://extensions` or `edge://extensions`.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select `dist\browser-extension\chromium`.

### Firefox and Zen

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on…** and select `dist\browser-extension\firefox\manifest.json`.

Firefox temporary add-ons are removed when Firefox restarts. Publishing an installable Firefox release requires Mozilla signing.

## Diagnostics

The popup's **Tải log** button downloads a JSON diagnostic report. It records extension steps, Proton API status codes, browser proxy mode, and sanitized errors. It does not record full page URLs, cookies, Proton usernames, passwords, sessions, access/refresh tokens, or proxy passwords. Logs remain in this browser's local extension storage until cleared with **Xóa log**; they are not sent anywhere automatically. Attach the downloaded JSON when reporting a problem.
