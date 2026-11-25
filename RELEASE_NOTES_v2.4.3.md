# ⚡ Freeton VPN v2.4.3 - WireGuard Connection Reliability

> Bản cập nhật **v2.4.3** đóng gói bản Windows đã được xác nhận kết nối thành công, đồng thời giữ các cải tiến về xác minh WireGuard, độ ổn định tunnel và trải nghiệm sử dụng trên Windows.

---

### 🛠️ Cải Tiến & Sửa Lỗi (Improvements & Bug Fixes)

* **Xác minh kết nối WireGuard chính xác hơn**:
  * Chỉ báo kết nối thành công sau khi xác minh handshake đúng peer và DNS trả lời qua địa chỉ WireGuard.
  * Phân biệt lỗi handshake với lỗi DNS; tự động dọn tunnel khi kết nối thất bại.
  * Không coi trạng thái service `RUNNING` đơn thuần là kết nối thành công.
* **Ổn định thao tác VPN trên Windows**:
  * Đọc trạng thái Windows Service ở luồng nền để giao diện và animation không bị khựng.
  * Tuần tự hóa thao tác tunnel, chặn bấm lặp và chờ service cũ được xóa trước khi cài lại.
  * Chỉ xóa cấu hình sau khi dịch vụ ngắt thành công; dọn dẹp an toàn hơn khi đóng ứng dụng.
* **Tối ưu chọn server & giao diện**:
  * Gộp ping trùng IP, giới hạn cập nhật tiến độ và sửa tính điểm server có tải 0%.
  * Giữ lựa chọn server thủ công khi quá trình quét nền hoàn tất.
  * Cải thiện animation, trạng thái kết nối và chuyển đổi giữa các màn hình.
* **Bản dựng độc lập**:
  * File EXE Windows 64-bit đã kèm Tcl/Tk, không cần cài Python để chạy.

---

### 🛡️ Kiểm Tra An Toàn & Bảo Mật (Security & Checksums)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| 📦 **Tệp thực thi** | `FreetonVPN.exe` |
| 📏 **Kích thước** | `68,524,108 bytes` (~65.37 MB) |
| 🔑 **SHA-256 Checksum** | `212536DE099D5D0D2AFC9928D214E098CC3FF1462111B6F06F320241089F1C99` |
| 🛡️ **VirusTotal Scan** | [👉 Tra cứu SHA-256 trên VirusTotal](https://www.virustotal.com/gui/file/212536DE099D5D0D2AFC9928D214E098CC3FF1462111B6F06F320241089F1C99) — chưa có kết quả scan được xác minh. |

> **Lưu ý:** Tệp chưa có chữ ký Authenticode; Windows có thể hiển thị cảnh báo SmartScreen hoặc Unknown Publisher.

---

### 📦 Hướng Dẫn Cập Nhật

* **Người dùng từ v2.4.2**: Mở ứng dụng và bấm nút **"⚡ Cập nhật & Khởi động lại"** trên hộp thoại thông báo để cập nhật lên v2.4.3.
* **Người dùng mới**: Tải file **`FreetonVPN.exe`** ở mục **Assets** bên dưới và chạy trực tiếp.

---

<sub>*Tuyên bố: Freeton VPN là dự án mã nguồn mở độc lập, không liên kết hay ủy quyền bởi Proton AG.*</sub>
