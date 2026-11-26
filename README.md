# Freeton VPN

Ứng dụng **Desktop Windows x64 (Rust v3.0.0)** và **Browser VPN Extension** mã nguồn mở giúp kết nối nhanh tới hệ thống máy chủ **Proton VPN Free**.

## Ứng dụng Desktop (Rust v3.0.0)

Từ phiên bản **v3.0.0**, ứng dụng desktop được viết lại hoàn toàn bằng **Rust** gốc cho Windows x64 (`FreetonVPN.exe`), đi kèm dịch vụ nền phân quyền riêng (`FreetonVPNService.exe`) và thư viện WireGuard nhúng sẵn (`tunnel.dll` + `wireguard.dll`).

- **Không cần cài thêm phụ thuộc ngoài:** Không cần cài WireGuard for Windows, Python, GPG hay Playwright.
- **Không hỏi UAC khi dùng hàng ngày:** Sau khi cài đặt một lần, việc bật/tắt hoặc đổi máy chủ VPN chạy qua `FreetonVPNService` mà không hiện hộp thoại UAC.
- **Đăng nhập Proton SRP & 2FA thuần Rust:** Xác thực trực tiếp bằng giao thức SRP (kèm kiểm tra chữ ký OpenPGP modulus), hỗ trợ mã 2FA và cửa sổ **WebView2 CAPTCHA** tích hợp (không lấy cookie từ trình duyệt). Token phiên được mã hóa và lưu trong **Windows Credential Manager**, không lưu mật khẩu ra đĩa.
- **Chọn node thông minh & xác minh kết nối thật:** Quét ping ICMP đa luồng (`Win32 IcmpSendEcho`), chấm điểm theo độ trễ/tải (hiển thị màu xanh/vàng/đỏ), giữ cache danh sách máy chủ, và chỉ báo **Đã kết nối** sau khi xác minh đúng WireGuard handshake qua `wireguard.dll` và DNS trả lời qua tunnel.
- **Tự động cập nhật an toàn:** Kiểm tra bản mới từ [`version-rust.json`](version-rust.json) và xác thực **SHA-256** nghiêm ngặt trước khi chạy trình cài đặt nâng cấp im lặng (`/S`).

### Cài đặt & Sử dụng

1. Tải trình cài đặt **`FreetonVPN-Setup-x64.exe`** (và file checksum `.sha256` nếu cần đối chiếu) tại trang [GitHub Releases](https://github.com/datpusheen/FreetonVPN/releases), hoặc tự build ra `dist/FreetonVPN-Setup-x64.exe`.
   - Bộ cài đặt đưa ứng dụng vào `C:\Program Files\FreetonVPN\`.
   - Đăng ký và khởi chạy dịch vụ `FreetonVPNService` với quyền IPC cho người dùng hiện tại.
   - Tạo lối tắt Start Menu (`Freeton VPN` và `Uninstall Freeton VPN`).
   - *Lưu ý SmartScreen:* Vì tệp cài đặt chưa có chữ ký Authenticode, Windows có thể hiện cảnh báo SmartScreen khi mở lần đầu; bạn có thể kiểm tra trước bằng SHA-256 trong `version-rust.json` hoặc tệp `.sha256` đi kèm.
2. Mở **Freeton VPN** từ khay hệ thống (System Tray) hoặc Start Menu, đăng nhập bằng tài khoản Proton (hỗ trợ 2FA và WebView2 CAPTCHA nếu Proton yêu cầu).
3. Chọn máy chủ (hoặc để chế độ tự chọn node tối ưu) và gạt công tắc để kết nối. Trong mục **Cài đặt**, bạn có thể cấp lại khóa WireGuard từ API, nhập tệp `.conf`, tùy chỉnh DNS/Port, bật khởi động cùng Windows hoặc bấm **Sửa dịch vụ** nếu `FreetonVPNService` bị dừng.
4. **Gỡ cài đặt:** Chạy `Uninstall Freeton VPN` trong Start Menu hoặc gỡ từ Windows *Settings → Apps* (bộ gỡ sẽ tự ngắt tunnel, dừng và xóa dịch vụ sạch sẽ).

### Tự build & đóng gói bộ cài Windows

Yêu cầu trên Windows 10/11 x64:

- Rust toolchain (`rustup`, target `stable-x86_64-pc-windows-msvc`) + Visual Studio Build Tools (Desktop development with C++ & Windows 10/11 SDK)
- Go (`C:\Program Files\Go\bin`) và `git`
- NSIS 3 (`C:\Program Files (x86)\NSIS\makensis.exe`)

Chạy pipeline build, kiểm thử và đóng gói toàn bộ từ thư mục gốc repo:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\rust\scripts\build_windows.ps1
```

Các bước mà `build_windows.ps1` thực hiện:

1. Clone và xác minh commit tag `v1.1.1` của `wireguard-windows` vào `rust/build/wireguard-windows/`, chạy `embeddable-dll-service\build.bat` và stage `tunnel.dll` vào `rust/assets/bin/tunnel.dll`.
2. Tải và kiểm tra SHA-256 gói `wireguard-nt-1.1.zip`, giải nén `amd64/wireguard.dll` vào `rust/assets/bin/wireguard.dll`.
3. Chạy `cargo test --manifest-path rust/Cargo.toml --workspace` và `cargo build --manifest-path rust/Cargo.toml --release`.
4. Biên dịch [`rust/installer/freeton.nsi`](rust/installer/freeton.nsi) bằng `makensis.exe` để xuất ra:
   - `dist/FreetonVPN-Setup-x64.exe`
   - `dist/FreetonVPN-Setup-x64.exe.sha256`
   - Cập nhật [`version-rust.json`](version-rust.json) với `file_size_bytes` và `sha256` chính xác.

## Tiện ích trình duyệt (Browser VPN Extension)

Tiện ích mở rộng đi kèm (Chromium & Firefox Manifest V3) liệt kê danh sách máy chủ Proton VPN Free, hiển thị mức tải hiện tại và định tuyến lưu lượng web **chỉ trong trình duyệt** qua Proton HTTPS proxy.

- Tiện ích thực hiện đăng nhập Proton SRP + 2FA trực tiếp trong tab riêng (lưu token trong `storage.session`, không ghi mật khẩu).
- **Giới hạn:** Không tạo tunnel WireGuard cho các ứng dụng khác trên máy và không đo ping ICMP — hãy dùng ứng dụng Desktop nếu cần bảo vệ toàn bộ thiết bị.

Build gói cài đặt cho Chromium và Firefox:

```powershell
npm ci --prefix .\browser-extension
.\browser-extension\build.ps1
```

Thư mục giải nén và file ZIP được xuất ra `dist/browser-extension/`. Xem hướng dẫn cài đặt cục bộ và chi tiết kỹ thuật tại [`browser-extension/README.md`](browser-extension/README.md).

## Cấu trúc dự án

| Thư mục / Tệp | Vai trò |
| --- | --- |
| `rust/freeton-core/` | Xác thực Proton SRP/OpenPGP, API client, ICMP pinger Win32, Windows Credential Manager, auto-updater kiểm tra SHA-256, WireGuard helpers |
| `rust/freeton-service/` | Dịch vụ nền `FreetonVPNService.exe` và runner `WireGuardTunnel$FreetonVPN` (`tunnel.dll` + `wireguard.dll`) |
| `rust/freeton-app/` | Giao diện tray flyout native `eframe`/`egui` và cửa sổ WebView2 CAPTCHA (`FreetonVPN.exe`) |
| `rust/scripts/build_windows.ps1` | Script build Rust, stage WireGuard DLL, đóng gói NSIS và cập nhật manifest |
| `rust/installer/freeton.nsi` | Script cài đặt và gỡ cài đặt NSIS x64 |
| `version-rust.json` | Manifest phát hành cho kênh desktop Rust v3.0.0+ |
| `version.json` | Manifest legacy v2.4.3 (giữ lại cho người dùng v2.x cũ) |
| `browser-extension/` | Mã nguồn chung và script build extension cho Chromium và Firefox |
| `website/` | Trang web tĩnh giới thiệu dự án (tự deploy qua [`.github/workflows/static.yml`](.github/workflows/static.yml)) |
| `CHANGELOG.md`, `RELEASE_NOTES_*.md` | Lịch sử thay đổi và ghi chú phát hành các phiên bản trước |
| `docs/`, `archive/` | Tài liệu thiết kế/kế hoạch kỹ thuật và bản lưu trữ tham khảo cũ |
| `dist/` | Thư mục chứa bộ cài, extension và checksum sau khi build (git-ignored) |

## Tuyên bố pháp lý

Freeton VPN là dự án mã nguồn mở độc lập, không thuộc sở hữu, không liên kết và không được ủy quyền hay tài trợ bởi Proton AG hoặc Proton VPN. Phần mềm được cung cấp nguyên trạng (*as-is*).
