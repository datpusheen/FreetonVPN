# ⚡ Freeton VPN v3.0.2 - In-App Auto-Update, Clean Changelog & 10-Tap Dev Mode

> Bản cập nhật **v3.0.2** khắc phục lỗi tải cập nhật đẩy ra trình duyệt, chuyển manifest mặc định sang nhánh `master`, làm đẹp bộ lọc & hiển thị changelog, và đổi thao tác bật Dev Mode sang bấm liên tục 10 lần.

---

### 🛠️ Cải Tiến & Sửa Lỗi (Improvements & Bug Fixes)

* **Tự động cập nhật trực tiếp trong app**:
  * Chuyển URL `version-rust.json` mặc định trên cả ứng dụng và website từ `refs/heads/main` sang `refs/heads/master`.
  * Đọc trực tiếp trường `digest` (`sha256:...`) trên asset installer từ GitHub Releases API để xác thực SHA-256 tức thì và tải ngay trong app; chỉ fallback tải file `.sha256` rời khi thiếu `digest` (tăng timeout lên 15s và bổ sung `User-Agent`).
* **Làm sạch & render Changelog gọn đẹp hơn**:
  * Bổ sung bộ lọc `extract_release_changelog_lines` tự động loại bỏ tiêu đề `#`/`##`, trích dẫn `>`, gạch ngang `---`, bảng Markdown, khối code, HTML phụ chú và phần phụ lục kỹ thuật khi đọc release notes từ GitHub.
  * Nâng cấp giao diện hộp thoại cập nhật với nhóm tiêu đề `▸` nổi bật, dấu chấm `•` căn lề trên, phân cấp tiêu đề ngắn và tự xuống dòng chuẩn trong khung popup.
* **Thao tác bật Dev Mode không cần chuột giữa**:
  * Thay thao tác giữ chuột giữa bằng **bấm chuột trái liên tục 10 lần** vào tiêu đề **`⚙️ Cài Đặt Hệ Thống`** trong **Cài đặt** (hoặc dòng **`by pishun • v3.0.2`** trong **Giới thiệu**).

---

### 🛡️ Kiểm Tra An Toàn & Bảo Mật (Security & Checksums)

| Thuộc tính | Chi tiết |
| :--- | :--- |
| 📦 **Bộ cài đặt** | `FreetonVPN-Setup-x64.exe` |
| 📄 **File checksum** | `FreetonVPN-Setup-x64.exe.sha256` |
| 📏 **Kích thước** | `8,451,352 bytes` (~8.06 MB) |
| 🔑 **SHA-256 Checksum** | `b243104c82d7c6b080e9aae596f3fb8c3e503949be19ff38eb64451b9597f3be` |
| 🛡️ **VirusTotal Scan** | [👉 Kiểm tra SHA-256 trên VirusTotal](https://www.virustotal.com/gui/file/b243104c82d7c6b080e9aae596f3fb8c3e503949be19ff38eb64451b9597f3be?nocache=1) — tải tệp lên VirusTotal để tạo kết quả quét nếu chưa có sẵn trong hệ thống. |

> **Lưu ý:** Bộ cài đặt chưa có chữ ký Authenticode; Windows SmartScreen có thể hiển thị cảnh báo Unknown Publisher ở lần chạy đầu tiên. Hãy đối chiếu SHA-256 bên trên (hoặc trong `FreetonVPN-Setup-x64.exe.sha256`) trước khi cài đặt.

---

### 📦 Hướng Dẫn Cập Nhật

* **Người dùng từ v3.0.0 / v3.0.1**: Mở app → **Cài đặt** / **Giới thiệu** → bấm **"🔄 Kiểm tra bản mới"** (hoặc tải thủ công từ **Assets** bên dưới đối với các bản trước v3.0.2 nếu chưa thấy tự cập nhật) để nâng cấp lên **v3.0.2**.
* **Người dùng mới**: Tải **`FreetonVPN-Setup-x64.exe`** ở mục **Assets** bên dưới và chạy để cài đặt.

---

<sub>*Tuyên bố: Freeton VPN là dự án mã nguồn mở độc lập, không thuộc sở hữu, không liên kết hay được ủy quyền bởi Proton AG hoặc Proton VPN.*</sub>
