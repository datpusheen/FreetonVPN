# ⚡ Freeton VPN v3.0.0 - Native Rust Desktop Rewrite (Windows x64)

> Bản phát hành lớn **v3.0.0** viết lại hoàn toàn ứng dụng desktop bằng **Rust** gốc cho Windows x64 (`FreetonVPN.exe` + `FreetonVPNService.exe`), tích hợp sẵn thư viện WireGuardNT, loại bỏ hoàn toàn Python, Playwright, GPG và PyInstaller.

---

### 🚀 Điểm Mới & Cải Tiến Nổi Bật (What's New)

* **Viết lại hoàn toàn bằng Rust gốc (Windows x64)**:
  * Giao diện native `eframe` / `egui` (kích thước tray flyout `390×610`) khởi động tức thì, dung lượng bộ cài chỉ ~`8.06 MB` (giảm mạnh so với ~`65.4 MB` ở v2.4.3).
  * Không cần cài thêm Python, GPG, Playwright hay WireGuard for Windows.
* **Dịch vụ nền `FreetonVPNService` & WireGuardNT nhúng sẵn**:
  * Đóng gói kèm `tunnel.dll` (từ `wireguard-windows v1.1.1`) và `wireguard.dll` (`wireguard-nt 1.1`).
  * Bật/tắt hoặc chuyển đổi máy chủ VPN hàng ngày không hiện hộp thoại UAC; đọc thống kê handshake trực tiếp từ driver WireGuardNT.
* **Xác thực Proton SRP, 2FA & WebView2 CAPTCHA**:
  * Triển khai Proton SRP và xác minh chữ ký OpenPGP modulus thuần Rust; loại bỏ việc trích xuất cookie từ trình duyệt Edge.
  * Hỗ trợ mã 2FA và cửa sổ WebView2 CAPTCHA tích hợp (kiểm tra origin Proton nghiêm ngặt).
  * Phiên đăng nhập được mã hóa và lưu trong **Windows Credential Manager**, không lưu mật khẩu ra đĩa.
* **Chọn node thông minh & Xác minh tunnel chặt chẽ**:
  * Quét ping ICMP đa luồng bằng Win32 `IcmpSendEcho`, phân màu chỉ số ping/tải (xanh/vàng/đỏ), giữ cache và giữ lựa chọn thủ công.
  * Chỉ báo **Đã kết nối** sau khi xác minh đúng WireGuard handshake và DNS phản hồi qua tunnel; tự động dọn dẹp tunnel nếu kết nối lỗi.
* **Giao diện & Tiện ích mới**:
  * Gắn logo thương hiệu Freeton VPN ở top bar, màn hình đăng nhập và hộp thoại About; kéo cửa sổ từ toàn bộ vùng trống top bar.
  * Hiệu ứng chuyển cảnh đối xứng giữa các màn hình, hộp thoại, toast và thẻ máy chủ.
  * Cài đặt nâng cao: cấp key WireGuard qua API, nhập tệp `.conf`, tùy chỉnh DNS/Port, khởi động cùng Windows và hộp thoại **Sửa dịch vụ** 1-click.
* **Auto-Updater xác thực SHA-256 & Bộ cài NSIS x64**:
  * Kiểm tra cập nhật qua `version-rust.json` (tách riêng khỏi `version.json` của v2.x) và đối chiếu SHA-256 nghiêm ngặt trước khi chạy trình cài đặt nâng cấp `/S`.

---

### 🛡️ Kiểm Tra An Toàn & Bảo Mật (Security & Checksums)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| 📦 **Bộ cài đặt** | `FreetonVPN-Setup-x64.exe` |
| 📄 **File checksum** | `FreetonVPN-Setup-x64.exe.sha256` |
| 📏 **Kích thước** | `8,453,440 bytes` (~8.06 MB) |
| 🔑 **SHA-256 Checksum** | `b1105c4555fa6e2382d0932d12528ac664df44014b6f5ce7c3aaba50f35ac3a4` |
| 🛡️ **VirusTotal Scan** | [👉 Kiểm tra SHA-256 trên VirusTotal](https://www.virustotal.com/gui/file/b1105c4555fa6e2382d0932d12528ac664df44014b6f5ce7c3aaba50f35ac3a4?nocache=1) — tải tệp lên VirusTotal để tạo kết quả quét nếu chưa có sẵn trong hệ thống. |

> **Lưu ý:** Bộ cài đặt chưa có chữ ký Authenticode; Windows SmartScreen có thể hiển thị cảnh báo Unknown Publisher ở lần chạy đầu tiên. Hãy đối chiếu SHA-256 bên trên (hoặc trong `FreetonVPN-Setup-x64.exe.sha256`) trước khi cài đặt.

---

### 📦 Hướng Dẫn Cài Đặt & Nâng Cấp

* **Người dùng mới hoặc nâng cấp từ v2.x**: Tải **`FreetonVPN-Setup-x64.exe`** ở mục **Assets** bên dưới và chạy để cài đặt vào `C:\Program Files\FreetonVPN\` cùng dịch vụ `FreetonVPNService` (từ v3.0.0 trở đi ứng dụng sẽ tự cập nhật qua `version-rust.json`).
* **Kiểm tra SHA-256 trên Windows (PowerShell)**:
  ```powershell
  Get-FileHash .\FreetonVPN-Setup-x64.exe -Algorithm SHA256
  ```

---

<sub>*Tuyên bố: Freeton VPN là dự án mã nguồn mở độc lập, không thuộc sở hữu, không liên kết hay được ủy quyền bởi Proton AG hoặc Proton VPN.*</sub>
