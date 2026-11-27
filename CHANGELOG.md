# 3.0.2 — sửa cập nhật trực tiếp trong app & render changelog gọn đẹp (2026-11-27)

- Chuyển URL `version-rust.json` mặc định trên ứng dụng và website từ nhánh `main` sang `master`.
- Đọc trực tiếp `asset["digest"]` (`sha256:...`) từ GitHub Releases API trong `parse_github_release_info` và chỉ tải file `.sha256` dự phòng khi `digest` trống (kèm tăng timeout lên 15s và `USER_AGENT`), giúp nút cập nhật tải trực tiếp trong app thay vì đẩy ra trình duyệt.
- Thêm bộ lọc Markdown (`extract_release_changelog_lines`) và nâng cấp UI `render_changelog_items` trong `UpdateDialog` để nhóm tiêu đề, bỏ ký tự Markdown thô/phụ lục và xuống dòng gọn trong popup.

# 3.0.1 — mượt kéo cửa sổ, đối xứng UI và Dev Update URL (2026-11-26)

- Chuyển cơ chế kéo cửa sổ trên thanh tiêu đề sang Win32 trực tiếp (`GetCursorPos` + `SetCapture` + `SetWindowPos`), loại bỏ độ trễ modal loop gây khựng khi di chuyển app.
- Căn chỉnh lại độ đối xứng và khoảng cách trên Top Bar, màn hình Home, form đăng nhập SRP, danh sách máy chủ và toàn bộ các hộp thoại (`Settings`, `About`, `Update`, `ServiceRepair`, `LogoutConfirm`, `ErrorDetail`).
- Bổ sung trường `Update Manifest URL` ẩn trong Dev Mode (`Cài đặt`) cho phép nhập URL local/staging để kiểm thử cập nhật trước khi phát hành production.

# 3.0.0 — viết lại hoàn toàn bằng Rust gốc cho Windows x64 (2026-11-26)

- Viết lại toàn bộ ứng dụng desktop bằng Rust x64 (`FreetonVPN.exe` với `eframe`/`egui` + dịch vụ nền `FreetonVPNService.exe`), loại bỏ Python, GPG, Playwright và PyInstaller.
- Nhúng sẵn thư viện WireGuardNT (`tunnel.dll` v1.1.1 + `wireguard.dll` 1.1), hỗ trợ bật/tắt VPN không cần hỏi UAC và đọc thống kê handshake trực tiếp từ driver.
- Triển khai xác thực Proton SRP + xác minh OpenPGP modulus thuần Rust, hỗ trợ 2FA và modal WebView2 CAPTCHA tích hợp; lưu token trong Windows Credential Manager.
- Quét ping ICMP đa luồng bằng Win32 `IcmpSendEcho`, phân màu chỉ số ping/tải xanh-vàng-đỏ, xác minh handshake + DNS qua tunnel trước khi báo Đã kết nối.
- Bổ sung giao diện cài đặt nâng cao (cấp key API, nhập `.conf`, tùy chỉnh DNS/Port, chạy cùng Windows, sửa dịch vụ), logo thương hiệu, hiệu ứng chuyển cảnh đối xứng và bộ cài NSIS x64 (`FreetonVPN-Setup-x64.exe`).
- Tách kênh tự động cập nhật sang `version-rust.json` và đối chiếu SHA-256 nghiêm ngặt trước khi chạy trình cài đặt nâng cấp `/S`.

# 2.4.3 — bản Windows đã xác nhận kết nối (2026-10-12)

- Đóng gói lại client Windows hiện tại thành v2.4.3 sau khi xác nhận kết nối WireGuard thành công.
- Cập nhật version resource, thông tin tự cập nhật và metadata tải xuống đồng bộ với asset phát hành mới.
- Giữ xác minh handshake đúng peer và DNS qua tunnel trước khi báo kết nối thành công.

# 2.4.2 — ổn định kết nối Windows (2026-09-10)

- Chỉ báo kết nối thành công sau khi xác minh handshake đúng peer và DNS trả lời qua địa chỉ WireGuard. Service RUNNING đơn thuần không còn được coi là đã kết nối.
- Chờ phản hồi tối đa khoảng 20 giây sau khi service chạy; phân biệt lỗi handshake và lỗi DNS. Dọn tunnel khi kết nối thất bại, hiển thị lỗi nếu không dọn được.
- Đọc trạng thái dịch vụ bằng Windows Service Control Manager API ở luồng nền; bỏ gọi `sc.exe` trong vòng animation/timer. Chỉ vẽ lại đồng hồ khi nội dung đổi.
- Tuần tự hóa thao tác tunnel, chặn bấm lặp khi đang kết nối/ngắt, chờ dịch vụ cũ được xóa trước khi cài lại. Không nuốt lỗi uninstall và không xóa cấu hình khi dịch vụ chưa ngắt.
- Bỏ các khoảng chờ cố định trong giao diện kết nối; bỏ kết quả kiểm tra/IP cũ sau khi đổi kết nối.
- Gộp ping trùng IP, giới hạn cập nhật tiến độ và giữ lựa chọn server thủ công khi quét nền. Sửa tính điểm server có tải 0%.
- Đóng ứng dụng sẽ chờ thao tác tunnel hiện tại và dọn dịch vụ ở luồng nền. Import module để kiểm thử không còn tự ngắt VPN khi tiến trình kết thúc.
- Bản dựng Windows dùng phiên bản tệp 2.4.2.0. Script build dừng nếu cài thư viện, khởi tạo Tcl/Tk hoặc PyInstaller thất bại; hỗ trợ `-PythonPath` và `-SkipDependencyInstall`.

## Kiểm tra

```powershell
.\.venv-windows\Scripts\python.exe -m unittest discover -v
.\build_exe.ps1 -SkipDependencyInstall
```

Kiểm thử kết nối mô phỏng mạng, Credential Manager và thao tác dịch vụ; không tự bật/ngắt VPN thật. Bộ test bao gồm dịch vụ chạy nhưng không handshake, handshake thành công nhưng DNS lỗi, lỗi ngắt, đổi server, bấm trùng và kết quả nền cũ.

Tham khảo giao thức: [WireGuard Windows enterprise usage](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md), [wg command reference](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8), [Windows QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex).
