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
