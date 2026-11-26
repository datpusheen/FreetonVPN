# ⚡ Freeton VPN v3.0.1 - Smooth Drag, UI Alignment & Dev Update URL

> Bản cập nhật nhỏ **v3.0.1** tối ưu trải nghiệm kéo thả cửa sổ, căn chỉnh đối xứng toàn bộ giao diện và bổ sung tùy chọn kiểm thử cập nhật trong Dev Mode.

---

### 🛠️ Cải Tiến & Sửa Lỗi (Improvements & Bug Fixes)

* **Kéo thả cửa sổ mượt mà hơn**:
  * Chuyển cơ chế kéo trên thanh tiêu đề sang Win32 trực tiếp (`GetCursorPos` + `SetCapture` + `SetWindowPos`), bỏ vòng lặp modal `WM_NCLBUTTONDOWN` gây khựng khi mới nắm kéo và khi di chuyển cửa sổ.
* **Căn chỉnh đối xứng giao diện (UI Polish)**:
  * Đồng bộ khoảng cách các nút và tiêu đề trên Top Bar.
  * Cân bằng lề trên/dưới ở màn hình **Home**, căn giữa dọc cụm công tắc `50/50` và chuẩn hóa khoảng cách badge `Ping` / `Tải`.
  * Căn thẳng mép trái 3 ô nhập liệu (`Email`, `Mật khẩu`, `2FA`) trên màn hình đăng nhập SRP và đồng bộ padding card đăng nhập.
  * Căn chỉnh chiều cao thẻ gợi ý tối ưu ở **Danh sách máy chủ** (`72px`) và chuẩn hóa hàng nút đáy trải đều chiều rộng trên toàn bộ các hộp thoại (`Settings`, `About`, `Update`, `ServiceRepair`, `LogoutConfirm`, `ErrorDetail`), chừa khoảng scrollbar cho Settings khi cuộn.
* **Tiện ích kiểm thử cập nhật trong Dev Mode**:
  * Bổ sung trường **`Update Manifest URL`** ẩn trong Dev Mode (*Cài đặt*, giữ chuột giữa 750ms) để nhập URL JSON local/staging (`https://` hoặc `http://127.0.0.1` / `localhost`) và kiểm thử cập nhật mà không cần đụng tới production.

---

### 🛡️ Kiểm Tra An Toàn & Bảo Mật (Security & Checksums)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| 📦 **Bộ cài đặt** | `FreetonVPN-Setup-x64.exe` |
| 📄 **File checksum** | `FreetonVPN-Setup-x64.exe.sha256` |
| 📏 **Kích thước** | `8,445,772 bytes` (~8.05 MB) |
| 🔑 **SHA-256 Checksum** | `eaebc63a54dd3fa55ea9ec6dca34d4297ab634b8cb9efcc136f28254a59abda5` |
| 🛡️ **VirusTotal Scan** | [👉 Kiểm tra SHA-256 trên VirusTotal](https://www.virustotal.com/gui/file/eaebc63a54dd3fa55ea9ec6dca34d4297ab634b8cb9efcc136f28254a59abda5?nocache=1) — tải tệp lên VirusTotal để tạo kết quả quét nếu chưa có sẵn trong hệ thống. |

> **Lưu ý:** Bộ cài đặt chưa có chữ ký Authenticode; Windows SmartScreen có thể hiển thị cảnh báo Unknown Publisher ở lần chạy đầu tiên. Hãy đối chiếu SHA-256 bên trên (hoặc trong `FreetonVPN-Setup-x64.exe.sha256`) trước khi cài đặt.

---

### 📦 Hướng Dẫn Cập Nhật

* **Người dùng từ v3.0.0**: Mở app → **Cài đặt** / **Giới thiệu** → bấm **"🔄 Kiểm tra bản mới"** (hoặc chờ tự động kiểm tra) để cập nhật lên **v3.0.1** (xác thực SHA-256 tự động).
* **Người dùng mới**: Tải **`FreetonVPN-Setup-x64.exe`** ở mục **Assets** bên dưới và chạy để cài đặt.

---

<sub>*Tuyên bố: Freeton VPN là dự án mã nguồn mở độc lập, không thuộc sở hữu, không liên kết hay được ủy quyền bởi Proton AG hoặc Proton VPN.*</sub>
