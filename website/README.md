# Freeton VPN - Trang chủ tĩnh

Trang web tĩnh chính thức cho **Freeton VPN by pishun**.

---

## 📁 Cấu trúc thư mục

```text
website/
├── index.html              # Trang chủ HTML5 ngữ nghĩa
├── assets/
│   ├── css/
│   │   └── style.css       # Graphite UI đồng bộ với desktop client
│   ├── js/
│   │   └── main.js         # JavaScript tương tác Mockup & metadata
│   ├── site.json           # Metadata UI/build dùng cho website
│   └── images/
│       ├── logo.png        # Icon ứng dụng Freeton VPN (256x256)
│       └── favicon.ico     # Favicon website
└── README.md               # Hướng dẫn deploy
```

---

## 🚀 Hướng dẫn Deploy lên Web (Miễn Phí 100%)

### Cách 1: Deploy bằng GitHub Pages (Tạo Repo riêng cho web)

1. Tạo một repository mới trên GitHub (ví dụ: `freeton-vpn-web` hoặc `datpusheen.github.io`).
2. Tải toàn bộ nội dung trong thư mục `website/` này lên repository đó.
3. Vào **Settings** của repository trên GitHub -> chọn **Pages** -> ở mục **Branch** chọn `main` (hoặc `master`) và thư mục `/(root)` -> bấm **Save**.
4. Trang web sẽ trực tiếp hoạt động tại: `https://<your-username>.github.io/<repo-name>/`.

---

### Cách 2: Deploy lên Vercel / Cloudflare Pages / Netlify (Khuyên dùng - Cực nhanh)

1. **Vercel**: Kéo thả thư mục `website/` vào [vercel.com](https://vercel.com) hoặc kết nối qua GitHub repo.
2. **Cloudflare Pages**: Chọn **Direct Upload** hoặc kết nối Git, chọn thư mục `website/`.
3. **Netlify**: Kéo thả thẳng thư mục `website/` vào [app.netlify.com/drop](https://app.netlify.com/drop).
