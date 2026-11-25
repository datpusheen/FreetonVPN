# ⚡ Freeton VPN v2.4.2 - WireGuard Connection Reliability

> Bản cập nhật **v2.4.2** tập trung cải thiện độ chính xác khi xác minh kết nối WireGuard, độ ổn định của tunnel và trải nghiệm sử dụng trên Windows.

---

### 🛠️ Cải Tiến & Sửa Lỗi (Improvements & Bug Fixes)

* **Xác minh kết nối chính xác hơn**:
  * Chỉ báo kết nối thành công sau khi xác minh handshake đúng peer và DNS trả lời qua địa chỉ WireGuard.
  * Phân biệt rõ lỗi handshake và lỗi DNS, tự động dọn tunnel khi kết nối thất bại.
  * Không còn coi trạng thái service `RUNNING` đơn thuần là đã kết nối thành công.
* **Ổn định hóa thao tác VPN trên Windows**:
  * Đọc trạng thái Windows Service ở luồng nền, không làm giật animation/timer giao diện.
  * Tuần tự hóa thao tác tunnel, chặn bấm lặp và chờ service cũ được xóa trước khi cài lại.
  * Không xóa cấu hình khi dịch vụ chưa ngắt thành công; dọn dẹp an toàn hơn khi đóng ứng dụng.
* **Tối ưu chọn server & giao diện**:
  * Gộp ping trùng IP, giới hạn cập nhật tiến độ và sửa tính điểm server có tải 0%.
  * Giữ lựa chọn server thủ công khi quá trình quét nền hoàn tất.
  * Cải thiện animation, trạng thái kết nối và chuyển đổi giữa các màn hình.
* **Bản dựng độc lập**:
  * File EXE Windows 64-bit đã kèm đầy đủ Tcl/Tk, không cần cài Python để chạy.

---

### 🛡️ Kiểm Tra An Toàn & Bảo Mật (Security & Checksums)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| 📦 **Tệp thực thi** | `FreetonVPN.exe` |
| 📏 **Kích thước** | `68,533,168 bytes` (~65.36 MB) |
| 🔑 **SHA-256 Checksum** | `CC41541A17FCAACD49191FA5E624571445513CA20C7E37C9633C9D643A8872E3` |
| 🛡️ **VirusTotal Scan** | [👉 Mở trang kiểm tra VirusTotal](https://www.virustotal.com/gui/file/CC41541A17FCAACD49191FA5E624571445513CA20C7E37C9633C9D643A8872E3?nocache=1) |

> Lưu ý: VirusTotal chỉ hiển thị kết quả sau khi file đã được upload hoặc có sẵn trong cơ sở dữ liệu của VirusTotal.

---

### 📦 Hướng Dẫn Cập Nhật

* **Người dùng từ v2.4.1**: Mở ứng dụng và bấm nút **"⚡ Cập nhật & Khởi động lại"** trên hộp thoại thông báo để tự động cập nhật lên v2.4.2.
* **Người dùng mới**: Tải file **`FreetonVPN.exe`** ở mục **Assets** bên dưới và chạy trực tiếp.

---

<sub>*Tuyên bố: Freeton VPN là dự án mã nguồn mở độc lập, không liên kết hay ủy quyền bởi Proton AG.*</sub>
