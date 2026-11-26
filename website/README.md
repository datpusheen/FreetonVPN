# Freeton VPN - Trang chủ tĩnh

Trang web tĩnh chính thức cho **Freeton VPN by pishun** (đồng bộ với **Desktop Client Rust v3.0.0**).

---

## Cấu trúc thư mục

```text
website/
├── index.html                  # Trang chủ HTML5 ngữ nghĩa
├── assets/
│   ├── css/
│   │   └── style.css           # Graphite + Mint UI đồng bộ với desktop client
│   ├── js/
│   │   └── main.js             # Tương tác Mockup, copy SHA-256 & đồng bộ release metadata
│   ├── site.json               # Metadata fallback dùng khi chưa lấy được dữ liệu từ GitHub
│   └── images/
│       ├── logo.png            # Icon ứng dụng Freeton VPN (256x256)
│       ├── logo.svg            # Logo vector
│       ├── favicon.ico         # Favicon website
│       ├── bank-qr.svg         # QR hỗ trợ (tham khảo)
│       ├── crypto-qr.svg       # QR hỗ trợ (tham khảo)
│       └── momo-qr.svg         # QR hỗ trợ (tham khảo)
└── README.md                   # Tài liệu thư mục web
```

---

## Deploy lên Web

### Cách 1: GitHub Pages tự động từ repo chính (Khuyên dùng)

Repo đã cấu hình workflow [`.github/workflows/static.yml`](../.github/workflows/static.yml) để tự động xuất bản thư mục `website/` lên GitHub Pages mỗi khi push vào nhánh `main` hoặc `master`.

1. Vào **Settings → Pages** trên GitHub repository.
2. Ở mục **Build and deployment → Source**, chọn **GitHub Actions**.
3. Push code hoặc chạy workflow **Deploy static content to Pages** trong tab **Actions**.

### Cách 2: Vercel / Cloudflare Pages / Netlify

- **Vercel / Cloudflare Pages / Netlify:** Trỏ Root Directory / Publish Directory vào `website/` (hoặc kéo thả thư mục `website/` khi upload trực tiếp).
