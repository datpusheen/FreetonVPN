#!/usr/bin/env python3
"""Freeton VPN (by pishun) - Unofficial Proton VPN WireGuard Desktop Client.

Phiên bản hoàn thiện với:
- Màn hình Yêu cầu Đăng nhập (Login Gate Screen) chuyên nghiệp khi chưa có session.
- Hỗ trợ Đăng nhập qua Edge Browser tự động hoặc Tài khoản/Mật khẩu (SRP) kèm 2FA.
- Cửa sổ bo cong viền mềm mại chuẩn Windows 11 & iOS (Rounded Squircle Window).
- Nút kích hoạt dạng Viên thuốc Toggle Switch iOS (iOS Pill Toggle) với Pillow anti-aliasing.
- Hỗ trợ cuộn chuột (Mouse Wheel) mượt mà cho mọi danh sách server.
- Menu Dropdown Quốc gia kèm dải phím lọc nhanh không bao giờ bị cắt chữ.
- Tự động phát hiện và đóng khung riêng Server "⭐ Tối ưu nhất" ở đầu danh sách.
- Thanh loading hiển thị chi tiết từng bước và tự động ẩn khi hoàn tất 100%.
- Hiệu ứng chuyển động mượt mà (kèm tùy chọn Bật/Tắt trong Cài đặt).
- Hộp thoại Giới thiệu (About) tiếng Việt đầy đủ bản quyền & Legal Disclaimer.
"""

from __future__ import annotations

import atexit
import base64
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import tkinter.ttk as ttk
import urllib.error
import urllib.request
import webbrowser
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox
from typing import Any

import keyring
import requests
from PIL import Image, ImageDraw, ImageFont, ImageTk
from windows_vpn import SERVICE_RUNNING, service_state, latest_handshake, dns_responds_through_tunnel, find_wg_cli

# Windows Console UTF-8 safety
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Windows POSIX compatibility patch for proton-core
if not hasattr(os, "getuid"):
    os.getuid = lambda: 1000

if "HOME" not in os.environ:
    os.environ["HOME"] = os.environ.get("USERPROFILE", os.path.expanduser("~"))

if "XDG_CACHE_HOME" not in os.environ:
    os.environ["XDG_CACHE_HOME"] = os.path.join(os.environ["HOME"], ".cache")

if "XDG_DATA_HOME" not in os.environ:
    os.environ["XDG_DATA_HOME"] = os.path.join(os.environ["HOME"], ".local", "share")

if "XDG_CONFIG_HOME" not in os.environ:
    os.environ["XDG_CONFIG_HOME"] = os.path.join(os.environ["HOME"], ".config")

# Cryptography for X25519 / PEM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import pystray

from updater import (
    DEFAULT_GITHUB_REPO,
    UpdateInfo,
    fetch_update_info,
    is_newer_version,
    download_update_stream,
    compute_file_sha256,
    apply_update_and_restart,
    is_running_as_frozen_exe,
)

# App Constants & Branding
APP_NAME = "Freeton VPN"
APP_SUBTITLE = "by pishun"
APP_VERSION = "2.4.3"
APP_UNOFFICIAL_TAG = "Bản VPN Proton không chính thức phát triển bởi pishun"

API_URL = "https://account.protonvpn.com/api/vpn/v1/logicals?WithIpV6=1"
LOGIN_URL = "https://account.protonvpn.com/login"
CERT_KEY_URL = "https://account.protonvpn.com/api/vpn/v1/certificate/key/EC"
CERT_REG_URL = "https://account.protonvpn.com/api/vpn/v1/certificate"

KEYRING_SERVICE_BROWSER = "proton-node-checker-browser"
KEYRING_ACCOUNT_BROWSER = "session-state"
KEYRING_SERVICE_SRP = "proton-node-checker"
KEYRING_ACCOUNT_SRP = "active-account"
KEYRING_SERVICE_WG = "proton-node-checker-wireguard"

DEFAULT_WG_ADDRESS = "10.2.0.2/32"
DEFAULT_WG_DNS = "10.2.0.1, 1.1.1.1"
DEFAULT_WG_PORT = 51820
DEFAULT_TUNNEL_NAME = "FreetonVPN"

DEFAULT_PING_TIMEOUT_MS = 800
DEFAULT_PING_WORKERS = 16

API_HEADERS = {
    "Accept": "application/vnd.protonmail.v1+json",
    "Accept-Encoding": "gzip",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://account.protonvpn.com/downloads",
    "User-Agent": "freeton-vpn/2.4.1",
    "x-pm-appversion": "web-vpn-settings@5.0.355.1",
    "x-pm-locale": "en_US",
}

COUNTRY_NAMES: dict[str, str] = {
    "SG": "Singapore (SG)",
    "JP": "Nhật Bản (JP)",
    "US": "Hoa Kỳ (US)",
    "NL": "Hà Lan (NL)",
    "RO": "Romania (RO)",
    "PL": "Ba Lan (PL)",
    "CH": "Thụy Sĩ (CH)",
    "DE": "Đức (DE)",
    "FR": "Pháp (FR)",
    "GB": "Vương quốc Anh (GB)",
    "CA": "Canada (CA)",
    "NO": "Na Uy (NO)",
    "MX": "Mexico (MX)",
    "IS": "Iceland (IS)",
    "SE": "Thụy Điển (SE)",
    "ES": "Tây Ban Nha (ES)",
    "IT": "Ý (IT)",
    "AU": "Úc (AU)",
    "BR": "Brazil (BR)",
    "IN": "Ấn Độ (IN)",
}


# --- Fast Proton API Client with Transparent Auto-Refresh ---

class ProtonFastClient:
    """High-speed Proton API client with HTTP connection pooling and auto token refresh.

    Eliminates the 8-15s delay of AutoTransport probe sequences by making direct HTTPS requests
    with keep-alive pooling, and automatically refreshing expired tokens via /auth/v4/refresh in ~0.3s.
    """
    _session: requests.Session | None = None
    _refresh_lock = threading.Lock()

    @classmethod
    def get_http_session(cls) -> requests.Session:
        if cls._session is None:
            cls._session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=1)
            cls._session.mount("https://", adapter)
            cls._session.mount("http://", adapter)
        return cls._session

    @classmethod
    def get_auth_headers_and_state(cls) -> tuple[dict[str, str], dict[str, Any], str] | None:
        srp_acc = keyring.get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
        if srp_acc:
            saved_state = keyring.get_password(KEYRING_SERVICE_SRP, f"session:{srp_acc.strip().lower()}")
            if saved_state:
                try:
                    state = json.loads(saved_state)
                    if state.get("AccessToken"):
                        headers = {
                            "Authorization": f"Bearer {state['AccessToken']}",
                            "x-pm-uid": state.get("UID", ""),
                            "x-pm-appversion": "Other",
                            "User-Agent": "freeton-vpn/2.4 (Windows)",
                            "Accept": "application/vnd.protonmail.v1+json",
                        }
                        return headers, state, srp_acc
                except Exception:
                    pass
        return None

    @classmethod
    def refresh_token(cls, state: dict[str, Any], account: str) -> bool:
        """Call https://api.protonmail.ch/auth/v4/refresh to get fresh AccessToken & RefreshToken in ~0.3s."""
        with cls._refresh_lock:
            refresh_token = state.get("RefreshToken")
            uid = state.get("UID")
            if not refresh_token or not uid:
                return False

            http = cls.get_http_session()
            headers = {
                "x-pm-uid": uid,
                "x-pm-appversion": "Other",
                "User-Agent": "freeton-vpn/2.4 (Windows)",
                "Accept": "application/vnd.protonmail.v1+json",
                "Content-Type": "application/json",
            }
            body = {
                "ResponseType": "token",
                "GrantType": "refresh_token",
                "RefreshToken": refresh_token,
            }
            endpoints = [
                "https://api.protonmail.ch/auth/v4/refresh",
                "https://account.protonvpn.com/api/auth/v4/refresh",
                "https://account.proton.me/api/auth/v4/refresh",
            ]
            for ep in endpoints:
                try:
                    resp = http.post(ep, headers=headers, json=body, timeout=8)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("Code") == 1000 and data.get("AccessToken"):
                            state["AccessToken"] = data["AccessToken"]
                            if data.get("RefreshToken"):
                                state["RefreshToken"] = data["RefreshToken"]
                            keyring.set_password(KEYRING_SERVICE_SRP, f"session:{account.strip().lower()}", json.dumps(state))
                            return True
                except Exception:
                    pass
            return False

    @classmethod
    def api_request(cls, path_or_url: str, method: str = "GET", json_data: Any = None, timeout: int = 10) -> dict[str, Any] | None:
        auth_data = cls.get_auth_headers_and_state()
        if not auth_data:
            return None

        headers, state, account = auth_data
        http = cls.get_http_session()

        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            urls = [path_or_url]
        else:
            rel = path_or_url.lstrip("/")
            urls = [
                f"https://account.protonvpn.com/api/{rel}",
                f"https://api.protonmail.ch/{rel}",
                f"https://account.proton.me/api/{rel}",
            ]

        for attempt in range(2):
            for url in urls:
                try:
                    cur_headers = {
                        "Authorization": f"Bearer {state.get('AccessToken', '')}",
                        "x-pm-uid": state.get("UID", ""),
                        "x-pm-appversion": "Other",
                        "User-Agent": "freeton-vpn/2.4 (Windows)",
                        "Accept": "application/vnd.protonmail.v1+json",
                    }
                    if json_data is not None:
                        cur_headers["Content-Type"] = "application/json"

                    if method.upper() == "GET":
                        resp = http.get(url, headers=cur_headers, timeout=timeout)
                    else:
                        resp = http.post(url, headers=cur_headers, json=json_data, timeout=timeout)

                    if resp.status_code == 200:
                        data = resp.json()
                        return data
                    elif resp.status_code == 401 and attempt == 0:
                        if cls.refresh_token(state, account):
                            break
                except Exception:
                    pass
        return None


# --- Instant Local Server Cache Manager ---

class ServerCacheManager:
    """Instant disk cache for Proton free server list & latency.

    Allows the GUI to display servers and select the best node in < 0.05s on startup
    while an asynchronous background probe fetches fresh updates.
    """
    CACHE_FILE = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "FreetonVPN" / "servers_cache.json"

    @classmethod
    def load(cls) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        try:
            if cls.CACHE_FILE.exists():
                data = json.loads(cls.CACHE_FILE.read_text(encoding="utf-8"))
                payload = data.get("raw_payload")
                servers = data.get("servers", [])
                if isinstance(servers, list) and len(servers) > 0:
                    return payload, servers
        except Exception:
            pass
        return None, []

    @classmethod
    def save(cls, raw_payload: dict[str, Any] | None, servers: list[dict[str, Any]]) -> None:
        try:
            cls.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "timestamp": int(time.time()),
                "raw_payload": raw_payload,
                "servers": servers,
            }
            cls.CACHE_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    @classmethod
    def clear(cls) -> None:
        try:
            if cls.CACHE_FILE.exists():
                cls.CACHE_FILE.unlink()
        except Exception:
            pass


def get_country_display(code: str) -> str:
    return COUNTRY_NAMES.get(code, f"{code}")


def decode_response(body: bytes, encoding: str | None) -> bytes:
    if encoding is None or encoding.lower() == "identity":
        return body
    if encoding.lower() == "gzip":
        return gzip.decompress(body)
    if encoding.lower() == "deflate":
        return zlib.decompress(body)
    raise RuntimeError(f"Content-Encoding không được hỗ trợ: {encoding}")


def ping_target(target: str | None, timeout_ms: int) -> float | None:
    if not target:
        return None
    if platform.system() == "Windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), target]
    else:
        timeout_seconds = max(1, (timeout_ms + 999) // 1000)
        command = ["ping", "-c", "1", "-W", str(timeout_seconds), target]

    try:
        startupinfo = None
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

        result = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=(timeout_ms / 1000) + 2.5,
            startupinfo=startupinfo,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    match = re.search(
        r"(?:time|thời\s*gian)\s*([=<])\s*(\d+(?:[.,]\d+)?)\s*ms",
        result.stdout,
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    latency = float(match.group(2).replace(",", "."))
    return 0.5 if match.group(1) == "<" and latency == 1 else latency


# --- iOS Style Pill Toggle Switch Widget (Pillow Anti-Aliased) ---

class IOSToggleSwitch(tk.Canvas):
    """Authentic iOS Pill Capsule Toggle Switch with smooth Pillow anti-aliasing."""

    def __init__(
        self,
        parent: tk.Widget,
        width: int = 64,
        height: int = 34,
        command: Any = None,
        bg_color: str = "#1b222b",
        cursor: str = "hand2",
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, width=width, height=height, bg=bg_color, highlightthickness=0, cursor=cursor, **kwargs)
        self.command = command
        self.bg_color = bg_color
        self._state = False
        self._is_connecting = False
        self.w = width
        self.h = height
        self.r = height / 2.0
        self.knob_radius = self.r - max(2.5, height * 0.045)

        self.current_knob_x = float(self.r)
        self.target_knob_x = float(self.r)
        self._animating = False

        self.bind("<Button-1>", self._on_click)
        self.draw()

    def set_state(self, state: bool, connecting: bool = False, animate: bool = True) -> None:
        self._state = state
        self._is_connecting = connecting
        if state or (connecting and not self._state):
            self.target_knob_x = float(self.w - self.r)
        else:
            self.target_knob_x = float(self.r)

        animate = animate and getattr(self.winfo_toplevel(), "wg_config", {}).get("animations_enabled", True)
        if animate:
            if not self._animating:
                self._animate_knob()
        else:
            self.current_knob_x = self.target_knob_x
            self.draw()

    def _animate_knob(self) -> None:
        if abs(self.current_knob_x - self.target_knob_x) < 0.5:
            self.current_knob_x = self.target_knob_x
            self.draw()
            self._animating = False
            return

        self._animating = True
        step = (self.target_knob_x - self.current_knob_x) * 0.35
        self.current_knob_x += step
        self.draw()
        self.after(16, self._animate_knob)


    def set_bg_color(self, color: str) -> None:
        self.bg_color = color
        self.configure(bg=color)
        self.draw()

    def _on_click(self, event: Any) -> None:
        if self.command:
            self.command()

    def draw(self) -> None:
        self.delete("all")
        if self._is_connecting:
            track_color = "#f59e0b"
        elif self._state:
            track_color = "#79cbbb"
        else:
            track_color = "#303a46"

        scale = 4
        img_w = int(self.w * scale)
        img_h = int(self.h * scale)
        img = Image.new("RGBA", (img_w, img_h), self.bg_color)
        draw = ImageDraw.Draw(img)

        # Draw anti-aliased pill capsule track
        draw.rounded_rectangle([0, 0, img_w, img_h], radius=img_h // 2, fill=track_color)

        # Draw subtle knob shadow
        kx = self.current_knob_x * scale
        ky = self.r * scale
        kr = self.knob_radius * scale

        draw.ellipse([kx - kr, ky - kr + 2 * scale, kx + kr, ky + kr + 2 * scale], fill="#111116")
        draw.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill="#ffffff")

        img_resized = img.resize((int(self.w), int(self.h)), Image.Resampling.LANCZOS)
        self.tk_img = ImageTk.PhotoImage(img_resized)
        self.create_image(0, 0, anchor="nw", image=self.tk_img)


# --- Fluent Windows 11 Rounded Card & Pill Button Components ---

class RoundedCard(tk.Canvas):
    """Modern Windows 11 style rounded card with antialiased borders and zero background mismatch."""

    def __init__(
        self,
        parent: tk.Widget,
        bg_color: str = "#101419",
        card_color: str = "#1b222b",
        border_color: str = "#303b48",
        hover_border: str = "#8bd5c5",
        radius: int = 14,
        padding: int = 12,
        cursor: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, bg=bg_color, highlightthickness=0, cursor=cursor, **kwargs)
        self.bg_color = bg_color
        self.card_color = card_color
        self.border_color = border_color
        self.hover_border = hover_border
        self.radius = radius
        self.padding = padding
        self.poly_id: Any = None
        self._is_hovered = False
        self._custom_border: str | None = None

        self.inner_frame = tk.Frame(self, bg=card_color)
        self.window_id = self.create_window(padding, padding, anchor="nw", window=self.inner_frame)

        self.bind("<Configure>", self._on_resize)
        if cursor == "hand2" or hover_border != border_color:
            self.bind("<Enter>", self._on_enter, add="+")
            self.bind("<Leave>", self._on_leave, add="+")

    def _draw_polygon(self, w: int, h: int) -> None:
        r = self.radius
        x1, y1 = 2, 2
        x2, y2 = w - 2, h - 2
        if x2 <= x1 or y2 <= y1:
            return
        points = [
            x1 + r, y1, x1 + r, y1, x2 - r, y1, x2 - r, y1,
            x2, y1, x2, y1 + r, x2, y1 + r, x2, y2 - r, x2, y2 - r,
            x2, y2, x2 - r, y2, x2 - r, y2, x1 + r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1,
        ]
        border = self._custom_border or (self.hover_border if self._is_hovered else self.border_color)
        if self.poly_id:
            self.coords(self.poly_id, *points)
            self.itemconfig(self.poly_id, fill=self.card_color, outline=border)
        else:
            self.poly_id = self.create_polygon(points, smooth=True, fill=self.card_color, outline=border, width=1)
            self.tag_lower(self.poly_id)

    def _on_resize(self, event: Any) -> None:
        w = event.width
        h = event.height
        if getattr(self, "_last_size", None) == (w, h):
            return
        self._last_size = (w, h)
        self._draw_polygon(w, h)
        self.coords(self.window_id, self.padding, self.padding)
        self.itemconfig(self.window_id, width=max(10, w - self.padding * 2), height=max(10, h - self.padding * 2))

    def set_border_color(self, color: str | None) -> None:
        self._custom_border = color
        if self.poly_id:
            self.itemconfig(self.poly_id, outline=color or (self.hover_border if self._is_hovered else self.border_color))

    def _on_enter(self, e: Any = None) -> None:
        self._is_hovered = True
        if self.poly_id and not self._custom_border:
            self.itemconfig(self.poly_id, outline=self.hover_border)

    def _on_leave(self, e: Any = None) -> None:
        self._is_hovered = False
        if self.poly_id and not self._custom_border:
            self.itemconfig(self.poly_id, outline=self.border_color)


def apply_window_rounded_corners(window: tk.Tk | tk.Toplevel) -> None:
    """Apply Windows 11 native DWM rounded corners (DWMWCP_ROUND) to any Tk or Toplevel window."""
    if platform.system() == "Windows":
        try:
            import ctypes
            window.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
            if hwnd == 0:
                hwnd = window.winfo_id()

            # Native Windows 11 DWM Window Corner Preference (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2)
            DWMWA_WINDOW_CORNER_PREFERENCE = 33
            preference = ctypes.c_int(2)  # DWMWCP_ROUND
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(preference), ctypes.sizeof(preference)
            )
        except Exception:
            pass


# --- High Resolution Emoji & Text Helper for RoundedPillButton ---

EMOJI_FONT_PATH = "C:/Windows/Fonts/seguiemj.ttf"
SYMBOL_FONT_PATH = "C:/Windows/Fonts/seguisym.ttf"
TEXT_FONT_BOLD_PATH = "C:/Windows/Fonts/segoeuib.ttf"
TEXT_FONT_REG_PATH = "C:/Windows/Fonts/segoeui.ttf"

_PIL_FONT_CACHE: dict[tuple[int, bool], tuple[Any, Any]] = {}

def get_pil_cached_fonts(size: int, is_bold: bool = True) -> tuple[Any, Any]:
    # Scale from Tkinter point size (e.g. 8-10pt) to crisp Pillow pixel size (~1.42 multiplier)
    px_size = max(10, int(size * 1.42))
    em_size = int(px_size * 1.08)
    key = (px_size, is_bold)
    if key not in _PIL_FONT_CACHE:
        try:
            f_em = ImageFont.truetype(EMOJI_FONT_PATH, em_size)
        except Exception:
            try:
                f_em = ImageFont.truetype(SYMBOL_FONT_PATH, em_size)
            except Exception:
                f_em = ImageFont.load_default()
        try:
            path = TEXT_FONT_BOLD_PATH if is_bold else TEXT_FONT_REG_PATH
            f_tx = ImageFont.truetype(path, px_size)
        except Exception:
            f_tx = ImageFont.load_default()
        _PIL_FONT_CACHE[key] = (f_em, f_tx)
    return _PIL_FONT_CACHE[key]

def _is_emoji_codepoint(c: str) -> bool:
    code = ord(c)
    if code in (0xFE0F, 0xFE0E, 0x200D):
        return True
    if 0x1F000 <= code <= 0x1FAFF:
        return True
    if 0x2100 <= code <= 0x27BF or 0x2B00 <= code <= 0x2BFF or 0x2300 <= code <= 0x23FF:
        return True
    if code in (0x25CF, 0x25CB, 0x25AA, 0x25AB):
        return True
    return False

def _is_color_emoji_segment(seg: str) -> bool:
    for c in seg:
        code = ord(c)
        if 0x1F000 <= code <= 0x1FAFF or code in (0x2699, 0x2139, 0x23F1, 0x2B50, 0x2728, 0x26A1, 0x1F512, 0x1F511, 0x1F310):
            return True
    return False

def _split_text_and_emojis(text: str) -> list[tuple[bool, str]]:
    clean = text.replace("\uFE0F", "").replace("\uFE0E", "")
    tokens: list[tuple[bool, str]] = []
    curr: list[str] = []
    is_curr_emoji: bool | None = None
    for c in clean:
        e = _is_emoji_codepoint(c)
        if is_curr_emoji is None:
            is_curr_emoji = e
            curr.append(c)
        elif e == is_curr_emoji:
            curr.append(c)
        else:
            tokens.append((is_curr_emoji, "".join(curr)))
            is_curr_emoji = e
            curr = [c]
    if curr and is_curr_emoji is not None:
        tokens.append((is_curr_emoji, "".join(curr)))
    return tokens

def _parse_font_spec(font_spec: Any) -> tuple[int, bool]:
    size = 8
    is_bold = True
    if isinstance(font_spec, (tuple, list)):
        if len(font_spec) >= 2 and isinstance(font_spec[1], (int, float)):
            size = int(font_spec[1])
        if len(font_spec) >= 3:
            is_bold = "bold" in str(font_spec[2]).lower()
    elif isinstance(font_spec, (int, float)):
        size = int(font_spec)
    return size, is_bold

def _prepare_pill_render_items(text: str, font_size: int, is_bold: bool, scale: int = 1) -> list[dict[str, Any]]:
    f_em, f_tx = get_pil_cached_fonts(font_size, is_bold)
    tokens = _split_text_and_emojis(text)
    items: list[dict[str, Any]] = []
    for is_sym, seg in tokens:
        font = f_em if is_sym else f_tx
        if is_sym:
            bbox = font.getbbox(seg)
            item_w = bbox[2] - bbox[0]
            items.append({"is_sym": True, "seg": seg, "font": font, "w": item_w, "bbox": bbox})
        else:
            if seg.startswith(" ") and len(items) > 0:
                gap = int(4 * scale)
                seg_clean = seg.lstrip(" ")
                item_w = font.getlength(seg_clean) if seg_clean else 0.0
                bbox = font.getbbox(seg_clean) if seg_clean else (0, 0, 0, 0)
                items.append({"is_gap": True, "w": gap})
                items.append({"is_sym": False, "seg": seg_clean, "font": font, "w": item_w, "bbox": bbox})
            else:
                item_w = font.getlength(seg)
                bbox = font.getbbox(seg)
                items.append({"is_sym": False, "seg": seg, "font": font, "w": item_w, "bbox": bbox})
    return items

def measure_pill_text_width(text: str, font_size: int, is_bold: bool) -> int:
    items = _prepare_pill_render_items(text, font_size, is_bold, scale=1)
    return int(sum(it["w"] for it in items))


class RoundedPillButton(tk.Canvas):
    """Windows 11 style rounded pill button with supersampled antialiasing, high-res color emoji rendering & hover glow."""

    def __init__(
        self,
        parent: tk.Widget,
        text: str,
        command: Any = None,
        width: int = 80,
        height: int = 28,
        radius: int = 8,
        bg_color: str = "#101419",
        btn_color: str = "#1b222b",
        fg_color: str = "#f8fafc",
        hover_bg: str = "#252f3a",
        hover_fg: str = "#8bd5c5",
        border_color: str = "#303b48",
        hover_border: str = "#8bd5c5",
        font: tuple[str, int, str] | Any = ("Segoe UI", 8, "bold"),
        cursor: str = "hand2",
        auto_width: bool = False,
        min_width: int = 20,
        padding_x: int = 8,
        **kwargs: Any,
    ) -> None:
        self.auto_width = auto_width
        self.min_width = min_width
        self.padding_x = padding_x
        self.font = font
        self.text = text

        if auto_width:
            try:
                font_size, is_bold = _parse_font_spec(font)
                measured = measure_pill_text_width(text, font_size, is_bold)
                width = max(min_width, measured + padding_x * 2)
            except Exception:
                pass

        super().__init__(parent, width=width, height=height, bg=bg_color, highlightthickness=0, cursor=cursor, **kwargs)
        self.command = command
        self.w = width
        self.h = height
        self.radius = radius
        self.bg_color = bg_color
        self.btn_color = btn_color
        self.fg_color = fg_color
        self.hover_bg = hover_bg
        self.hover_fg = hover_fg
        self.border_color = border_color
        self.hover_border = hover_border
        self._is_hovered = False
        self._is_pressed = False
        self._tk_img: Any = None
        self._hover_amount = 0.0
        self._hover_job = None

        if cursor:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<ButtonPress-1>", self._on_press)
            self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Configure>", self._on_resize)
        self.draw()

    def _on_enter(self, e: Any = None) -> None:
        self._is_hovered = True
        self._animate_hover()

    def _on_leave(self, e: Any = None) -> None:
        self._is_hovered = False
        self._is_pressed = False
        self._animate_hover()

    def _animate_hover(self) -> None:
        if self._hover_job:
            self.after_cancel(self._hover_job)
            self._hover_job = None
        target = float(self._is_hovered)
        enabled = getattr(self.winfo_toplevel(), "wg_config", {}).get("animations_enabled", True)
        if not enabled or abs(target - self._hover_amount) < 0.025:
            self._hover_amount = target
        else:
            self._hover_amount += (target - self._hover_amount) * 0.35
            self._hover_job = self.after(16, self._animate_hover)
        self.draw()

    def _on_press(self, e: Any = None) -> None:
        self._is_pressed = True
        self.draw()

    def _on_release(self, e: Any = None) -> None:
        should_run = self._is_pressed and self._is_hovered
        self._is_pressed = False
        self.draw()
        if should_run and self.command:
            self.command()

    def _on_resize(self, event: Any) -> None:
        if not self.auto_width:
            width = max(2, int(event.width))
            height = max(2, int(event.height))
            if width != self.w or height != self.h:
                self.w = width
                self.h = height
                self.draw()

    def set_border_color(self, color: str | None) -> None:
        self.border_color = color or "#303b48"
        self.draw()

    def draw(self) -> None:
        scale = 3
        w_s, h_s = self.w * scale, self.h * scale
        def blend(start: str, end: str) -> str:
            a, b = self.winfo_rgb(start), self.winfo_rgb(end)
            return "#" + "".join(f"{round((x + (y - x) * self._hover_amount) / 257):02x}" for x, y in zip(a, b))

        if self._is_pressed:
            fill = self.border_color
        else:
            fill = blend(self.btn_color, self.hover_bg)
        border = blend(self.border_color, self.hover_border)

        img = Image.new("RGBA", (w_s, h_s), self.bg_color)
        d = ImageDraw.Draw(img)
        rect = [scale, scale, w_s - scale - 1, h_s - scale - 1]
        d.rounded_rectangle(rect, radius=self.radius * scale, fill=fill, outline=border, width=scale)

        fg = blend(self.fg_color, self.hover_fg)
        text_offset = scale if self._is_pressed else 0

        font_size, is_bold = _parse_font_spec(self.font)
        f_emoji, f_text = get_pil_cached_fonts(font_size * scale, is_bold)
        items = _prepare_pill_render_items(self.text, font_size * scale, is_bold, scale=scale)

        bbox_cap = f_text.getbbox("H")
        text_y_offset = (bbox_cap[3] + bbox_cap[1]) / 2

        total_w = sum(it["w"] for it in items)
        cur_x = (w_s - total_w) / 2
        y_center = (h_s / 2) + text_offset

        for it in items:
            if it.get("is_gap"):
                cur_x += it["w"]
                continue
            seg = it["seg"]
            if not seg:
                continue
            font = it["font"]
            if it["is_sym"]:
                bbox = it["bbox"]
                draw_y = y_center - (bbox[3] + bbox[1]) / 2
                if _is_color_emoji_segment(seg):
                    try:
                        d.text((cur_x - bbox[0], draw_y), seg, font=font, embedded_color=True)
                    except Exception:
                        d.text((cur_x - bbox[0], draw_y), seg, font=font, fill=fg)
                else:
                    d.text((cur_x - bbox[0], draw_y), seg, font=font, fill=fg)
                cur_x += it["w"]
            else:
                draw_y = y_center - text_y_offset
                d.text((cur_x, draw_y), seg, font=font, fill=fg)
                cur_x += it["w"]

        self._tk_img = ImageTk.PhotoImage(img.resize((self.w, self.h), Image.Resampling.LANCZOS))
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._tk_img)

    def set_text(self, text: str, fg_color: str | None = None) -> None:
        self.configure(text=text, fg_color=fg_color)

    def config(self, cnf: Any = None, **kwargs: Any) -> Any:
        return self.configure(cnf, **kwargs)

    def configure(self, cnf: Any = None, **kwargs: Any) -> Any:
        redraw_needed = False
        if "text" in kwargs:
            self.text = kwargs.pop("text")
            if self.auto_width:
                try:
                    font_size, is_bold = _parse_font_spec(self.font)
                    measured = measure_pill_text_width(self.text, font_size, is_bold)
                    new_w = max(self.min_width, measured + self.padding_x * 2)
                    if new_w != self.w:
                        self.w = new_w
                        super().configure(width=new_w)
                except Exception:
                    pass
            redraw_needed = True
        if "fg" in kwargs:
            self.fg_color = kwargs.pop("fg")
            redraw_needed = True
        if "fg_color" in kwargs:
            self.fg_color = kwargs.pop("fg_color")
            redraw_needed = True
        if "bg" in kwargs:
            self.btn_color = kwargs.pop("bg")
            redraw_needed = True
        if "bg_color" in kwargs:
            self.bg_color = kwargs.pop("bg_color")
            super().configure(bg=self.bg_color)
            redraw_needed = True
        if "btn_color" in kwargs:
            self.btn_color = kwargs.pop("btn_color")
            redraw_needed = True
        if "border_color" in kwargs:
            self.border_color = kwargs.pop("border_color")
            redraw_needed = True
        if "hover_bg" in kwargs:
            self.hover_bg = kwargs.pop("hover_bg")
            redraw_needed = True
        if "hover_fg" in kwargs:
            self.hover_fg = kwargs.pop("hover_fg")
            redraw_needed = True
        if "hover_border" in kwargs:
            self.hover_border = kwargs.pop("hover_border")
            redraw_needed = True
        if "command" in kwargs:
            self.command = kwargs.pop("command")
        if "radius" in kwargs:
            self.radius = kwargs.pop("radius")
            redraw_needed = True
        if "font" in kwargs:
            self.font = kwargs.pop("font")
            redraw_needed = True
        if kwargs:
            try:
                super().configure(**kwargs)
            except Exception:
                pass
        if redraw_needed:
            self.draw()
        return None


class VirtualServerRows(tk.Canvas):
    """Draw only viewport rows, keeping native widget count independent of data size."""

    ROW_HEIGHT = 64
    LIST_TOP = 112

    def __init__(self, parent: tk.Widget, owner: Any) -> None:
        super().__init__(parent, bg=owner.C_BG, highlightthickness=0, height=80)
        self.owner = owner
        self._title_font = tkfont.Font(self, family="Segoe UI", size=9, weight="bold")
        self.servers: list[dict[str, Any]] = []
        self.best = None
        self._hovered = None
        self._render_key = None
        self.bind("<Configure>", lambda e: self.render_visible())
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._click)

    def set_servers(self, servers: list[dict[str, Any]], best: dict[str, Any] | None) -> None:
        self.servers, self.best = servers, best
        self._hovered = None
        self._render_key = None
        self.configure(height=self.LIST_TOP + len(servers) * self.ROW_HEIGHT if servers else 80)
        self.render_visible()

    def _row_at(self, y: float) -> int | None:
        if self.best and 0 <= y < 84:
            return -1
        if y >= self.LIST_TOP:
            index = int((y - self.LIST_TOP) // self.ROW_HEIGHT)
            if index < len(self.servers) and (y - self.LIST_TOP) % self.ROW_HEIGHT < 58:
                return index
        return None

    def _motion(self, event: Any) -> None:
        hovered = self._row_at(event.y)
        if hovered != self._hovered:
            self._hovered = hovered
            self.configure(cursor="hand2" if hovered is not None else "")
            self._render_key = None
            self.render_visible()

    def _leave(self, event: Any) -> None:
        self._hovered = None
        self._render_key = None
        self.render_visible()

    def _click(self, event: Any) -> None:
        index = self._row_at(event.y)
        if index is None:
            return
        server = self.best if index == -1 else self.servers[index]
        top = 0 if index == -1 else self.LIST_TOP + index * self.ROW_HEIGHT
        if self.owner.is_debug_mode and event.x > self.winfo_width() - 88 and event.y > top + (54 if index == -1 else 30):
            self.owner._export_specific_conf(server)
        else:
            self.owner._select_and_connect_server(server)

    def render_visible(self) -> None:
        owner = self.owner
        width = max(10, self.winfo_width())
        top = max(0, owner.canvas.canvasy(0))
        bottom = top + owner.canvas.winfo_height()
        first = max(0, int((top - self.LIST_TOP) // self.ROW_HEIGHT) - 2)
        last = min(len(self.servers), int((bottom - self.LIST_TOP) // self.ROW_HEIGHT) + 3)
        key = (first, last, width, top < self.LIST_TOP,
               (owner.selected_server or {}).get("name"),
               (owner.connected_server or {}).get("name"), owner.is_debug_mode)
        if key == self._render_key:
            return
        self._render_key = key
        self.delete("all")
        if not self.servers:
            msg = "Không tìm thấy máy chủ phù hợp." if owner.all_free_servers else "Chưa có dữ liệu máy chủ."
            self.create_text(width / 2, 32, text=msg, fill=owner.C_TEXT_DIM, font=("Segoe UI", 9))
            return
        if top < self.LIST_TOP:
            self._draw_row(-1, 0, 84, self.best, width)
            self.create_text(12, 99, text=f"TẤT CẢ MÁY CHỦ  ·  {len(self.servers)}", anchor="w",
                             font=("Segoe UI", 7, "bold"), fill=owner.C_TEXT_DIM)
        for index in range(first, last):
            self._draw_row(index, self.LIST_TOP + index * self.ROW_HEIGHT, 58, self.servers[index], width)

    def _draw_row(self, index, y, height, server, width):
        o = self.owner
        selected = o.selected_server and o.selected_server.get("name") == server.get("name")
        connected = o.connected_server and o.connected_server.get("name") == server.get("name")
        bg = o.C_SUCCESS_BG if connected else o.C_CARD_HIGH if selected else o.C_CARD
        border = o.C_ACCENT if index == self._hovered or selected or connected or index == -1 else o.C_BORDER
        x, right, bottom, radius = 2, width - 2, y + height, 10
        points = [x+radius,y, right-radius,y, right,y,right,y+radius,
                  right,bottom-radius,right,bottom,right-radius,bottom,
                  x+radius,bottom,x,bottom,x,bottom-radius,x,y+radius,x,y]
        self.create_polygon(points, smooth=True, fill=bg, outline=border)
        text_y = y + 16
        if index == -1:
            self.create_text(12, text_y, anchor="w", text="GỢI Ý TỐI ƯU NHẤT",
                             font=("Segoe UI", 7, "bold"), fill=o.C_ACCENT)
            self.create_text(right-12, text_y, anchor="e", text="Kết nối ngay ›",
                             font=("Segoe UI", 8), fill=o.C_ACCENT)
            text_y += 25
        title = f"{server.get('name')} — {get_country_display(server.get('country', ''))}"
        # Fit long server names to the available row width without wrapping.
        while len(title) > 1 and self._title_font.measure(title) > width - 28:
            title = title[:-2].rstrip() + "…"
        self.create_text(12, text_y, anchor="w", text=title, font=("Segoe UI", 9, "bold"), fill=o.C_TEXT)
        ping = server.get("pingMs")
        ping_text = f"{ping:g} ms" if ping is not None else "—"
        color = o.C_SUCCESS if ping is not None and ping < 80 else o.C_TEXT_MUTED
        self.create_text(12, text_y + 22, anchor="w", text=f"Ping  {ping_text}", font=("Segoe UI", 8), fill=color)
        self.create_text(128, text_y + 22, anchor="w", text=f"Tải  {server.get('load', 0)}%",
                         font=("Segoe UI", 8), fill=o.C_TEXT_MUTED)
        if o.is_debug_mode:
            self.create_text(right-12, text_y + 22, anchor="e", text="Xuất .conf",
                             font=("Segoe UI", 8), fill=o.C_ACCENT)


class RoundedProgressBar(tk.Canvas):
    """Modern Windows 11 / Fluent rounded pill progress bar with anti-aliasing."""

    def __init__(
        self,
        parent: tk.Widget,
        height: int = 4,
        bg_color: str = "#101419",
        trough_color: str = "#1b222b",
        bar_color: str = "#8bd5c5",
        radius: int | None = None,
        maximum: float = 100.0,
        value: float = 0.0,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent, height=height, bg=bg_color, highlightthickness=0, bd=0, **kwargs)
        self.bg_color = bg_color
        self.trough_color = trough_color
        self.bar_color = bar_color
        self.radius = radius if radius is not None else max(2, height // 2)
        self.maximum = float(maximum)
        self._value = float(value)
        self._mode = "determinate"
        self._tk_img: Any = None
        self.w = 100
        self.h = height

        self.bind("<Configure>", self._on_resize)
        self.draw()

    def __setitem__(self, key: str, val: Any) -> None:
        if key == "value":
            self.set_value(val)
        elif key == "maximum":
            self.maximum = float(val)
            self.draw()
        elif key == "mode":
            self._mode = str(val)

    def __getitem__(self, key: str) -> Any:
        if key == "value":
            return self._value
        if key == "maximum":
            return self.maximum
        if key == "mode":
            return self._mode
        return None

    def set_value(self, val: float) -> None:
        self._value = max(0.0, min(self.maximum, float(val)))
        self.draw()

    def config(self, cnf: Any = None, **kwargs: Any) -> Any:
        return self.configure(cnf, **kwargs)

    def configure(self, cnf: Any = None, **kwargs: Any) -> Any:
        redraw_needed = False
        if "value" in kwargs:
            self._value = max(0.0, min(self.maximum, float(kwargs.pop("value"))))
            redraw_needed = True
        if "maximum" in kwargs:
            self.maximum = float(kwargs.pop("maximum"))
            redraw_needed = True
        if "mode" in kwargs:
            self._mode = str(kwargs.pop("mode"))
        if "bar_color" in kwargs:
            self.bar_color = kwargs.pop("bar_color")
            redraw_needed = True
        if "trough_color" in kwargs:
            self.trough_color = kwargs.pop("trough_color")
            redraw_needed = True
        if "bg_color" in kwargs:
            self.bg_color = kwargs.pop("bg_color")
            super().configure(bg=self.bg_color)
            redraw_needed = True
        if kwargs:
            super().configure(cnf, **kwargs)
        if redraw_needed:
            self.draw()

    def _on_resize(self, event: Any) -> None:
        w = max(4, int(event.width))
        h = max(2, int(event.height))
        if w != self.w or h != self.h:
            self.w = w
            self.h = h
            self.draw()

    def draw(self) -> None:
        w = max(4, self.w)
        h = max(2, self.h)
        scale = 3
        w_s, h_s = w * scale, h * scale
        r_s = (h // 2) * scale

        img = Image.new("RGBA", (w_s, h_s), self.bg_color)
        d = ImageDraw.Draw(img)

        # Draw rounded trough
        d.rounded_rectangle([0, 0, w_s - 1, h_s - 1], radius=r_s, fill=self.trough_color)

        # Draw rounded active bar
        if self.maximum > 0 and self._value > 0:
            fraction = min(1.0, self._value / self.maximum)
            bar_w_s = int(w_s * fraction)
            if bar_w_s > 0:
                bar_r_s = min(r_s, max(1, bar_w_s // 2)) if bar_w_s < r_s * 2 else r_s
                d.rounded_rectangle([0, 0, max(bar_r_s * 2, bar_w_s) - 1, h_s - 1], radius=bar_r_s, fill=self.bar_color)

        resized = img.resize((w, h), Image.Resampling.LANCZOS)
        self._tk_img = ImageTk.PhotoImage(resized)
        self.delete("all")
        self.create_image(0, 0, anchor="nw", image=self._tk_img)


# --- System Dependency Management & Auto-Installer ---

class DependencyManager:
    WIREGUARD_INSTALLER_URL = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
    GPG4WIN_INSTALLER_URL = "https://files.gpg4win.org/gpg4win-latest.exe"

    @staticmethod
    def find_wireguard_exe() -> str | None:
        candidates = [
            r"C:\Program Files\WireGuard\wireguard.exe",
            r"C:\Program Files (x86)\WireGuard\wireguard.exe",
            shutil.which("wireguard"),
            shutil.which("wireguard.exe"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    @staticmethod
    def find_gpg_exe() -> str | None:
        candidates = [
            shutil.which("gpg"),
            shutil.which("gpg.exe"),
            shutil.which("gpg2"),
            shutil.which("gpg2.exe"),
            r"C:\Program Files\GnuPG\bin\gpg.exe",
            r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
            r"C:\Program Files\Gpg4win\..\GnuPG\bin\gpg.exe",
            r"C:\Program Files (x86)\Gpg4win\..\GnuPG\bin\gpg.exe",
            r"C:\Program Files\Gpg4win\bin\gpg.exe",
            r"C:\Program Files (x86)\Gpg4win\bin\gpg.exe",
            r"C:\Program Files\Git\usr\bin\gpg.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\GnuPG\bin\gpg.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\GnuPG\bin\gpg.exe"),
            str(Path(__file__).parent / "bin" / "gpg.exe"),
        ]
        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    @staticmethod
    def ensure_runtime_path() -> None:
        """Inject GnuPG / WireGuard directory into os.environ['PATH'] if found in non-standard location."""
        gpg_path = DependencyManager.find_gpg_exe()
        if gpg_path:
            gpg_dir = str(Path(gpg_path).parent)
            current_path = os.environ.get("PATH", "")
            if gpg_dir.lower() not in current_path.lower():
                os.environ["PATH"] = f"{gpg_dir};{current_path}"

        wg_path = DependencyManager.find_wireguard_exe()
        if wg_path:
            wg_dir = str(Path(wg_path).parent)
            current_path = os.environ.get("PATH", "")
            if wg_dir.lower() not in current_path.lower():
                os.environ["PATH"] = f"{wg_dir};{current_path}"

    @staticmethod
    def check_all() -> dict[str, dict[str, Any]]:
        DependencyManager.ensure_runtime_path()
        wg_exe = DependencyManager.find_wireguard_exe()
        gpg_exe = DependencyManager.find_gpg_exe()
        return {
            "wireguard": {
                "name": "WireGuard for Windows",
                "installed": bool(wg_exe),
                "path": wg_exe,
                "description": "Tạo card mạng ảo TUN & định tuyến kết nối VPN bảo mật",
                "official_url": "https://www.wireguard.com/install/",
            },
            "gpg": {
                "name": "GnuPG / Gpg4win Cryptography Engine",
                "installed": bool(gpg_exe),
                "path": gpg_exe,
                "description": "Xác thực mật mã SRP & giải mã chứng chỉ an toàn từ Proton API",
                "official_url": "https://www.gpg4win.org/get-gpg4win.html",
            },
        }

    @staticmethod
    def is_all_satisfied() -> bool:
        deps = DependencyManager.check_all()
        return deps["wireguard"]["installed"] and deps["gpg"]["installed"]

    @staticmethod
    def get_installers_dir() -> Path:
        p = Path(tempfile.gettempdir()) / "FreetonVPN_Setup"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @staticmethod
    def _download_file(urls: list[str] | str, dest: Path, progress_cb: Any = None, label: str = "file") -> None:
        if isinstance(urls, str):
            urls = [urls]

        dest.parent.mkdir(parents=True, exist_ok=True)
        last_error: Exception | None = None
        partial_path = dest.with_suffix(f"{dest.suffix}.part")

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*",
        }

        def report_progress(downloaded: int, total_bytes: int, started_at: float) -> None:
            if not progress_cb:
                return
            elapsed = max(0.001, time.time() - started_at)
            speed_mb = (downloaded / (1024 * 1024)) / elapsed
            pct = int((downloaded / total_bytes) * 100) if total_bytes > 0 else 0
            down_mb = downloaded / (1024 * 1024)
            total_mb = total_bytes / (1024 * 1024) if total_bytes > 0 else 0
            progress_cb(down_mb, total_mb, pct, speed_mb)

        def promote_download() -> None:
            if not partial_path.exists() or partial_path.stat().st_size <= 1024:
                raise RuntimeError("File tải về quá nhỏ hoặc không đầy đủ.")
            # Both supported installers are Windows executables.  This catches
            # common HTML/proxy error pages before they are launched.
            with partial_path.open("rb") as downloaded_file:
                magic = downloaded_file.read(2)
            if magic != b"MZ":
                raise RuntimeError("File tải về không phải Windows installer hợp lệ.")
            partial_path.replace(dest)

        for url in urls:
            # Always verify TLS.  These files are executed with elevated rights,
            # so accepting an unverified HTTPS response is not safe.
            try:
                partial_path.unlink(missing_ok=True)
                t0 = time.time()
                with requests.get(url, headers=headers, stream=True, timeout=30) as resp:
                    resp.raise_for_status()
                    total_str = resp.headers.get("Content-Length")
                    total_bytes = int(total_str) if total_str and total_str.isdigit() else 0
                    downloaded = 0
                    with partial_path.open("wb") as f:
                        for chunk in resp.iter_content(chunk_size=65536):
                            if not chunk:
                                continue
                            f.write(chunk)
                            downloaded += len(chunk)
                            report_progress(downloaded, total_bytes, t0)

                promote_download()
                return
            except Exception as ex:
                last_error = ex

            # A second HTTPS client helps with local proxy/certificate-store
            # quirks, but keeps normal certificate verification enabled.
            try:
                partial_path.unlink(missing_ok=True)
                req = urllib.request.Request(url, headers=headers)
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=30) as resp:
                    total_str = resp.headers.get("Content-Length")
                    total_bytes = int(total_str) if total_str and total_str.isdigit() else 0
                    downloaded = 0
                    chunk_size = 65536
                    with partial_path.open("wb") as f:
                        while True:
                            chunk = resp.read(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            report_progress(downloaded, total_bytes, t0)

                promote_download()
                return
            except Exception as ex:
                last_error = ex
            finally:
                partial_path.unlink(missing_ok=True)

        if last_error:
            raise RuntimeError(f"Không thể tải {label}: {last_error}")
        raise RuntimeError(f"Không thể tải {label} từ các máy chủ dự phòng.")

    @staticmethod
    def launch_installer(installer_path: Path) -> bool:
        """Launch Windows installer with native UAC elevation prompt."""
        path_str = str(installer_path.resolve())
        # Method 1: os.startfile (Most reliable Windows native shell execution)
        try:
            os.startfile(path_str)
            return True
        except Exception:
            pass

        # Method 2: os.startfile with explicit runas
        try:
            os.startfile(path_str, "runas")
            return True
        except Exception:
            pass

        # Method 3: Windows Explorer invocation
        try:
            subprocess.Popen(["explorer.exe", path_str])
            return True
        except Exception:
            pass

        # Method 4: Win32 ShellExecuteW with foreground window
        if platform.system() == "Windows":
            try:
                import ctypes
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                res = ctypes.windll.shell32.ShellExecuteW(hwnd, "runas", path_str, "", str(installer_path.parent), 1)
                if res > 32:
                    return True
            except Exception:
                pass

        return False

    @staticmethod
    def install_wireguard(progress_cb: Any = None, prefix: str = "") -> tuple[bool, str]:
        try:
            setup_dir = DependencyManager.get_installers_dir()
            installer_path = setup_dir / "wireguard-installer.exe"
            
            wg_urls = [
                DependencyManager.WIREGUARD_INSTALLER_URL,
            ]

            def dl_cb(down_mb: float, tot_mb: float, pct: int, speed: float):
                if progress_cb:
                    if tot_mb > 0:
                        msg = f"{prefix}📥 Đang tải WireGuard ({down_mb:.2f}/{tot_mb:.2f} MB • {pct}% • {speed:.1f} MB/s)..."
                    else:
                        msg = f"{prefix}📥 Đang tải WireGuard ({down_mb:.2f} MB • {speed:.1f} MB/s)..."
                    progress_cb(msg, pct)

            DependencyManager._download_file(wg_urls, installer_path, dl_cb, label="WireGuard installer")

            if progress_cb:
                progress_cb(f"{prefix}⚙️ Đang mở cài đặt WireGuard (Hãy bấm 'Yes' trên cửa sổ UAC)...", 95)

            success = DependencyManager.launch_installer(installer_path)
            if success:
                return True, "Đã khởi chạy trình cài đặt WireGuard for Windows thành công!"
            return False, "Không thể khởi chạy file cài đặt WireGuard."
        except Exception as ex:
            return False, f"Lỗi tải/cài đặt WireGuard: {ex}"

    @staticmethod
    def install_gpg(progress_cb: Any = None, prefix: str = "") -> tuple[bool, str]:
        try:
            setup_dir = DependencyManager.get_installers_dir()
            installer_path = setup_dir / "gnupg-setup.exe"

            gpg_urls = [
                "https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.4.5_20240307.exe",
                DependencyManager.GPG4WIN_INSTALLER_URL,
                "https://files.gpg4win.org/gpg4win-latest.exe",
            ]

            def dl_cb(down_mb: float, tot_mb: float, pct: int, speed: float):
                if progress_cb:
                    if tot_mb > 0:
                        msg = f"{prefix}📥 Đang tải GnuPG ({down_mb:.1f}/{tot_mb:.1f} MB • {pct}% • {speed:.1f} MB/s)..."
                    else:
                        msg = f"{prefix}📥 Đang tải GnuPG ({down_mb:.1f} MB • {speed:.1f} MB/s)..."
                    progress_cb(msg, pct)

            DependencyManager._download_file(gpg_urls, installer_path, dl_cb, label="GnuPG installer")

            if progress_cb:
                progress_cb(f"{prefix}⚙️ Đang mở cài đặt GnuPG (Hãy bấm 'Yes' trên cửa sổ UAC)...", 95)

            success = DependencyManager.launch_installer(installer_path)
            if success:
                return True, "Đã khởi chạy trình cài đặt GnuPG thành công!"
            return False, "Không thể khởi chạy file cài đặt GnuPG."
        except Exception as ex:
            return False, f"Lỗi tải/cài đặt GnuPG: {ex}"


# --- Windows Startup Management (Registry Run Key) ---

class WindowsStartupManager:
    REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_REG_NAME = "FreetonVPN"

    @classmethod
    def get_app_command(cls) -> str:
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}"'
        script_dir = os.path.dirname(os.path.abspath(__file__))
        bat_launcher = os.path.join(script_dir, "run_warp_gui.bat")
        if os.path.exists(bat_launcher):
            return f'"{bat_launcher}"'
        return f'"{sys.executable}" "{os.path.abspath(__file__)}"'

    @classmethod
    def is_enabled(cls) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, cls.APP_REG_NAME)
                return bool(val)
        except Exception:
            return False

    @classmethod
    def set_enabled(cls, enable: bool) -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REG_KEY, 0, winreg.KEY_ALL_ACCESS) as key:
                if enable:
                    cmd = cls.get_app_command()
                    winreg.SetValueEx(key, cls.APP_REG_NAME, 0, winreg.REG_SZ, cmd)
                else:
                    try:
                        winreg.DeleteValue(key, cls.APP_REG_NAME)
                    except FileNotFoundError:
                        pass
            return True
        except Exception:
            return False


# --- WireGuard Management Helpers ---

class WireGuardManager:
    # Login, auto-refresh and Connect can be initiated almost simultaneously.
    # Serialising certificate registration prevents duplicate API requests and
    # inconsistent keyring state.
    _key_registration_lock = threading.Lock()
    _tunnel_lock = threading.RLock()

    @staticmethod
    def find_wireguard_exe() -> str | None:
        return DependencyManager.find_wireguard_exe()

    @staticmethod
    def load_config() -> dict[str, Any]:
        raw = keyring.get_password(KEYRING_SERVICE_WG, "client_config")
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {
            "private_key": "",
            "public_key": "",
            "expiration": 0,
            "address": DEFAULT_WG_ADDRESS,
            "dns": DEFAULT_WG_DNS,
            "port": str(DEFAULT_WG_PORT),
            "animations_enabled": True,
        }

    @staticmethod
    def save_config(config: dict[str, Any]) -> None:
        keyring.set_password(KEYRING_SERVICE_WG, "client_config", json.dumps(config))

    @staticmethod
    def _expiration_timestamp(config: dict[str, Any]) -> float:
        try:
            return float(config.get("expiration") or 0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def has_usable_key(config: dict[str, Any], minimum_valid_seconds: int = 60) -> bool:
        """A manually imported key (expiration 0) remains valid until replaced."""
        if not str(config.get("private_key") or "").strip():
            return False
        expiration = WireGuardManager._expiration_timestamp(config)
        return expiration == 0 or expiration >= time.time() + minimum_valid_seconds

    @staticmethod
    def needs_key_refresh(config: dict[str, Any], within_seconds: int = 7_200) -> bool:
        if not str(config.get("private_key") or "").strip():
            return True
        expiration = WireGuardManager._expiration_timestamp(config)
        return expiration > 0 and expiration < time.time() + within_seconds

    @staticmethod
    def ed25519_pem_to_wireguard_privkey(priv_pem: str) -> str:
        """Derive the true X25519 WireGuard private key from Ed25519 PKCS8 PEM via SHA512 + clamping."""
        priv_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        seed = priv_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        hash__ = hashlib.sha512(seed).digest()
        hash_ = bytearray(hash__[:32])
        hash_[0] &= 0xF8
        hash_[31] &= 0x7F
        hash_[31] |= 0x40
        return base64.b64encode(bytes(hash_)).decode("ascii")

    @staticmethod
    def auto_fetch_and_register_key(force: bool = False) -> dict[str, Any]:
        with WireGuardManager._key_registration_lock:
            current_config = WireGuardManager.load_config()
            if not force and WireGuardManager.has_usable_key(current_config):
                return current_config
            return WireGuardManager._fetch_and_register_key_locked()

    @staticmethod
    def _fetch_and_register_key_locked() -> dict[str, Any]:
        # 1. SRP Session via Fast Direct API (Instant < 1.5s with auto token refresh)
        srp_acc = keyring.get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
        if srp_acc:
            try:
                ec_res = ProtonFastClient.api_request("/vpn/v1/certificate/key/EC", method="GET", timeout=8)
                if ec_res and ec_res.get("Code") == 1000:
                    priv_pem = ec_res["PrivateKey"]
                    pub_pem = ec_res["PublicKey"]

                    cert_res = ProtonFastClient.api_request(
                        "/vpn/v1/certificate",
                        method="POST",
                        json_data={
                            "ClientPublicKey": pub_pem,
                            "Platform": "Windows",
                            "Features": {},
                        },
                        timeout=8,
                    )
                    if cert_res and cert_res.get("Code") == 1000:
                        wg_priv = WireGuardManager.ed25519_pem_to_wireguard_privkey(priv_pem)
                        cur_cfg = WireGuardManager.load_config()
                        config = {
                            **cur_cfg,
                            "private_key": wg_priv,
                            "public_key": pub_pem,
                            "expiration": cert_res.get("ExpirationTime", 0),
                            "obtained_at": int(time.time()),
                        }
                        WireGuardManager.save_config(config)
                        return config
            except Exception as ex:
                print("Lỗi fast fetch key qua SRP:", ex)

        # 2. Browser cookies
        browser_state = get_saved_browser_state()
        if browser_state:
            cookies = cookie_header_from_state(browser_state)
            if cookies:
                try:
                    headers = {**API_HEADERS, "Cookie": cookies}
                    uid = extract_uid_from_state(browser_state)
                    if uid:
                        headers["x-pm-uid"] = uid
                    http = ProtonFastClient.get_http_session()
                    resp_ec = http.get(CERT_KEY_URL, headers=headers, timeout=10)
                    if resp_ec.status_code == 200:
                        ec_res = resp_ec.json()
                        if ec_res.get("Code") == 1000:
                            priv_pem = ec_res["PrivateKey"]
                            pub_pem = ec_res["PublicKey"]

                            resp_reg = http.post(
                                CERT_REG_URL,
                                headers={**headers, "Content-Type": "application/json"},
                                json={
                                    "ClientPublicKey": pub_pem,
                                    "Platform": "Windows",
                                    "Features": {},
                                },
                                timeout=10,
                            )
                            if resp_reg.status_code == 200:
                                cert_res = resp_reg.json()
                                if cert_res.get("Code") == 1000:
                                    wg_priv = WireGuardManager.ed25519_pem_to_wireguard_privkey(priv_pem)
                                    cur_cfg = WireGuardManager.load_config()
                                    config = {
                                        **cur_cfg,
                                        "private_key": wg_priv,
                                        "public_key": pub_pem,
                                        "expiration": cert_res.get("ExpirationTime", 0),
                                        "obtained_at": int(time.time()),
                                    }
                                    WireGuardManager.save_config(config)
                                    return config
                except Exception as ex:
                    print("Lỗi fetch key qua Browser cookies:", ex)

        # 3. Fallback to full Proton Session if needed
        if srp_acc:
            saved_state = keyring.get_password(KEYRING_SERVICE_SRP, f"session:{srp_acc.strip().lower()}")
            if saved_state:
                try:
                    sess = create_proton_session()
                    sess.__setstate__(json.loads(saved_state))
                    if sess.authenticated:
                        ec_res = sess.api_request("/vpn/v1/certificate/key/EC", method="get")
                        if ec_res.get("Code") == 1000:
                            priv_pem = ec_res["PrivateKey"]
                            pub_pem = ec_res["PublicKey"]

                            cert_res = sess.api_request(
                                "/vpn/v1/certificate",
                                method="post",
                                jsondata={
                                    "ClientPublicKey": pub_pem,
                                    "Platform": "Windows",
                                    "Features": {},
                                },
                            )
                            if cert_res.get("Code") == 1000:
                                wg_priv = WireGuardManager.ed25519_pem_to_wireguard_privkey(priv_pem)
                                cur_cfg = WireGuardManager.load_config()
                                config = {
                                    **cur_cfg,
                                    "private_key": wg_priv,
                                    "public_key": pub_pem,
                                    "expiration": cert_res.get("ExpirationTime", 0),
                                    "obtained_at": int(time.time()),
                                }
                                WireGuardManager.save_config(config)
                                return config
                except Exception as ex:
                    print("Lỗi session fetch key qua SRP:", ex)

        raise RuntimeError("Chưa có phiên đăng nhập Proton hợp lệ để tự động tạo và kích hoạt WireGuard Key.")

    @staticmethod
    def generate_conf_content(server: dict[str, Any], client_config: dict[str, Any]) -> str:
        private_key = client_config.get("private_key", "").strip()
        address = client_config.get("address", DEFAULT_WG_ADDRESS).strip() or DEFAULT_WG_ADDRESS
        dns = client_config.get("dns", DEFAULT_WG_DNS).strip() or DEFAULT_WG_DNS
        raw_port = client_config.get("port", str(DEFAULT_WG_PORT)).strip() or str(DEFAULT_WG_PORT)

        endpoint_target = server.get("entryIP") or server.get("pingTarget") or server.get("domain") or ""
        server_pubkey = server.get("x25519PublicKey") or ""

        if not private_key:
            raise ValueError("Chưa có WireGuard Private Key hợp lệ.")
        if not server_pubkey:
            raise ValueError(f"Server {server.get('name')} không có WireGuard PublicKey (X25519).")
        if not endpoint_target:
            raise ValueError(f"Server {server.get('name')} không có Endpoint để kết nối.")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as error:
            raise ValueError("Cổng WireGuard phải là số từ 1 đến 65535.") from error
        if not 1 <= port <= 65_535:
            raise ValueError("Cổng WireGuard phải nằm trong khoảng 1 đến 65535.")

        # WireGuard requires brackets around an IPv6 endpoint literal.
        if ":" in endpoint_target and not endpoint_target.startswith("["):
            endpoint_target = f"[{endpoint_target}]"

        conf = f"""# ==========================================
# Freeton VPN WireGuard Configuration
# Bản VPN Proton không chính thức phát triển bởi pishun
# Server: {server.get('name', 'Proton Server')}
# Quốc gia: {get_country_display(server.get('country', ''))}
# Domain Server: {server.get('domain', '')}
# IP Cổng vào: {server.get('entryIP', '')}
# ==========================================

[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = {dns}
MTU = 1380

[Peer]
PublicKey = {server_pubkey}
AllowedIPs = 0.0.0.0/0
Endpoint = {endpoint_target}:{port}
PersistentKeepalive = 25
"""
        return conf

    @staticmethod
    def get_tunnel_conf_path(tunnel_name: str = DEFAULT_TUNNEL_NAME) -> Path:
        base_dir = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "FreetonVPN" / "tunnels"
        try:
            base_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            base_dir = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "FreetonVPN" / "tunnels"
            base_dir.mkdir(parents=True, exist_ok=True)
        return base_dir / f"{tunnel_name}.conf"

    @staticmethod
    def is_service_existing(tunnel_name: str = DEFAULT_TUNNEL_NAME) -> bool:
        return service_state(f"WireGuardTunnel${tunnel_name}") != 0

    @staticmethod
    def is_tunnel_running(tunnel_name: str = DEFAULT_TUNNEL_NAME) -> bool:
        return service_state(f"WireGuardTunnel${tunnel_name}") == SERVICE_RUNNING

    @staticmethod
    def wait_for_service(tunnel_name: str, expected_state: int, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while service_state(f"WireGuardTunnel${tunnel_name}") != expected_state:
            if time.monotonic() >= deadline:
                raise RuntimeError("WireGuard Service chưa hoàn tất thay đổi trạng thái. Vui lòng thử lại.")
            time.sleep(0.1)

    @staticmethod
    def wait_for_connection(server: dict[str, Any], config: dict[str, Any], tunnel_name: str, timeout: float = 20) -> None:
        cli = find_wg_cli(WireGuardManager.find_wireguard_exe())
        deadline = time.monotonic() + timeout
        handshaken = False
        while time.monotonic() < deadline:
            if not WireGuardManager.is_tunnel_running(tunnel_name):
                raise RuntimeError("WireGuard Service đã dừng trước khi kết nối hoàn tất.")
            try:
                stamp = latest_handshake(cli, tunnel_name, server.get("x25519PublicKey"))
                handshaken = stamp > 0 and 0 <= time.time() - stamp <= 180
            except (RuntimeError, subprocess.TimeoutExpired):
                # The service can be RUNNING before its IPC endpoint is ready.
                handshaken = False
            if handshaken and dns_responds_through_tunnel(
                config.get("address") or DEFAULT_WG_ADDRESS,
                config.get("dns") or DEFAULT_WG_DNS,
                timeout=min(2, max(0.1, deadline - time.monotonic())),
            ):
                return
            time.sleep(0.25)
        if handshaken:
            raise RuntimeError("WireGuard đã bắt tay nhưng DNS qua VPN chưa phản hồi. Hãy kiểm tra DNS trong Cài đặt hoặc chọn máy chủ khác.")
        raise RuntimeError("Máy chủ chưa phản hồi handshake WireGuard. Hãy thử máy chủ khác, kiểm tra cổng UDP hoặc cấp lại WireGuard Key trong Cài đặt.")

    @staticmethod
    def run_wireguard_command(args: list[str]) -> None:
        wg_exe = WireGuardManager.find_wireguard_exe()
        if not wg_exe:
            raise RuntimeError(
                "Không tìm thấy phần mềm WireGuard for Windows trên máy!\n\n"
                "Vui lòng cài đặt WireGuard từ trang chính thức: https://www.wireguard.com/install/"
            )

        is_admin = False
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False

        if is_admin:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            res = subprocess.run(
                [wg_exe] + args,
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                timeout=30,
                check=False,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Lỗi thao tác WireGuard service (Code {res.returncode}):\n{res.stderr or res.stdout}")
        else:
            arg_string = " ".join([f'"{a}"' if " " in a else a for a in args])
            exe_literal = wg_exe.replace("'", "''")
            args_literal = arg_string.replace("'", "''")
            ps_cmd = f"$ErrorActionPreference = 'Stop'; $process = Start-Process -FilePath '{exe_literal}' -ArgumentList '{args_literal}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $process.ExitCode"

            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0

            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                timeout=120,
                check=False,
            )
            if res.returncode != 0:
                raise RuntimeError(
                    f"Cần cấp quyền Administrator (UAC) để khởi động Windows WireGuard Service.\n"
                    f"(Chi tiết: {res.stderr or res.stdout})"
                )

    @staticmethod
    def connect_tunnel(server: dict[str, Any], client_config: dict[str, Any], tunnel_name: str = DEFAULT_TUNNEL_NAME) -> None:
        if not WireGuardManager.has_usable_key(client_config):
            client_config = WireGuardManager.auto_fetch_and_register_key()
        # Validate before stopping a working connection.
        find_wg_cli(WireGuardManager.find_wireguard_exe())
        conf_content = WireGuardManager.generate_conf_content(server, client_config)
        with WireGuardManager._tunnel_lock:
            WireGuardManager.disconnect_tunnel(tunnel_name)
            conf_path = WireGuardManager.get_tunnel_conf_path(tunnel_name)
            try:
                conf_path.write_text(conf_content, encoding="utf-8")
                WireGuardManager.run_wireguard_command(["/installtunnelservice", str(conf_path)])
                WireGuardManager.wait_for_service(tunnel_name, SERVICE_RUNNING)
                WireGuardManager.wait_for_connection(server, client_config, tunnel_name)
            except Exception as error:
                try:
                    WireGuardManager.disconnect_tunnel(tunnel_name)
                except Exception as cleanup_error:
                    raise RuntimeError(f"{error}\nKhông thể dọn tunnel lỗi: {cleanup_error}") from error
                raise

    @staticmethod
    def disconnect_tunnel(tunnel_name: str = DEFAULT_TUNNEL_NAME) -> None:
        with WireGuardManager._tunnel_lock:
            if WireGuardManager.is_service_existing(tunnel_name):
                WireGuardManager.run_wireguard_command(["/uninstalltunnelservice", tunnel_name])
                WireGuardManager.wait_for_service(tunnel_name, 0)
            # Keep the configuration when removal fails: the service may need it.
            WireGuardManager.get_tunnel_conf_path(tunnel_name).unlink(missing_ok=True)


# --- System Dependency Management & Auto-Installer Dialog ---

class DependencySetupDialog(tk.Toplevel):
    def __init__(self, parent: Any) -> None:
        super().__init__(parent)
        self.app = parent
        self.title("Cài đặt Thành phần Hệ thống - Freeton VPN")
        w, h = 380, 540
        self.update_idletasks()
        try:
            if parent.winfo_width() > 50:
                x = parent.winfo_x() + (parent.winfo_width() - w) // 2
                y = parent.winfo_y() + (parent.winfo_height() - h) // 2
            else:
                x = (self.winfo_screenwidth() - w) // 2
                y = (self.winfo_screenheight() - h) // 2
        except Exception:
            x = (self.winfo_screenwidth() - w) // 2
            y = (self.winfo_screenheight() - h) // 2

        self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        self.resizable(False, False)
        self.configure(bg=parent.C_BG)
        self.attributes("-topmost", True)
        self.transient(parent)
        self.grab_set()
        if hasattr(parent, "register_modal"):
            parent.register_modal(self)
        self.after(50, lambda: apply_window_rounded_corners(self))

        self._is_installing = False

        card = RoundedCard(
            self,
            bg_color=parent.C_BG,
            card_color=parent.C_CARD,
            border_color=parent.C_BORDER,
            radius=14,
            padding=14,
            height=510,
        )
        card.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        tk.Label(card.inner_frame, text="🛠️ Thành Phần Hệ Thống", font=("Segoe UI", 11, "bold"), bg=parent.C_CARD, fg=parent.C_TEXT).pack(anchor="w", pady=(0, 2))
        tk.Label(
            card.inner_frame,
            text="Freeton VPN sử dụng WireGuard để định tuyến mạng và GnuPG để bảo mật khóa SRP. Kiểm tra và cài đặt tự động bên dưới:",
            font=("Segoe UI", 8),
            bg=parent.C_CARD,
            fg=parent.C_TEXT_MUTED,
            wraplength=320,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        # 1. WireGuard Card
        self.f_wg = RoundedCard(card.inner_frame, bg_color=parent.C_CARD, card_color=parent.C_BG, border_color=parent.C_BORDER, radius=10, padding=8, height=76)
        self.f_wg.pack(fill="x", pady=(0, 8))

        f_wg_top = tk.Frame(self.f_wg.inner_frame, bg=parent.C_BG)
        f_wg_top.pack(fill="x")
        tk.Label(f_wg_top, text="🛡️ WireGuard for Windows", font=("Segoe UI", 9, "bold"), bg=parent.C_BG, fg=parent.C_TEXT).pack(side="left")
        self.lbl_wg_badge = RoundedPillButton(
            f_wg_top,
            text="...",
            width=90,
            height=20,
            radius=5,
            bg_color=parent.C_BG,
            btn_color=parent.C_CARD,
            fg_color=parent.C_TEXT_MUTED,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_CARD,
            hover_fg=parent.C_TEXT_MUTED,
            hover_border=parent.C_BORDER,
            font=("Segoe UI", 7, "bold"),
            auto_width=True,
            min_width=75,
            padding_x=6,
            cursor="",
        )
        self.lbl_wg_badge.pack(side="right")

        self.lbl_wg_desc = tk.Label(
            self.f_wg.inner_frame,
            text="Bắt buộc: Tạo card mạng ảo TUN & quản lý dịch vụ VPN.",
            font=("Segoe UI", 7),
            bg=parent.C_BG,
            fg=parent.C_TEXT_MUTED,
            justify="left",
            wraplength=310,
        )
        self.lbl_wg_desc.pack(anchor="w", pady=(2, 4))

        self.btn_install_wg = RoundedPillButton(
            self.f_wg.inner_frame,
            text="⬇️ Tải & Cài đặt WireGuard",
            command=lambda: self._do_install_single("wireguard"),
            width=165,
            height=24,
            radius=6,
            bg_color=parent.C_BG,
            btn_color=parent.C_CARD_HIGH,
            fg_color=parent.C_ACCENT,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_BORDER,
            hover_fg=parent.C_ACCENT_HOVER,
            font=("Segoe UI", 7, "bold"),
        )
        self.btn_install_wg.pack(anchor="w")

        # 2. GnuPG / Gpg4win Card
        self.f_gpg = RoundedCard(card.inner_frame, bg_color=parent.C_CARD, card_color=parent.C_BG, border_color=parent.C_BORDER, radius=10, padding=8, height=76)
        self.f_gpg.pack(fill="x", pady=(0, 8))

        f_gpg_top = tk.Frame(self.f_gpg.inner_frame, bg=parent.C_BG)
        f_gpg_top.pack(fill="x")
        tk.Label(f_gpg_top, text="🔑 GnuPG / Gpg4win Engine", font=("Segoe UI", 9, "bold"), bg=parent.C_BG, fg=parent.C_TEXT).pack(side="left")
        self.lbl_gpg_badge = RoundedPillButton(
            f_gpg_top,
            text="...",
            width=90,
            height=20,
            radius=5,
            bg_color=parent.C_BG,
            btn_color=parent.C_CARD,
            fg_color=parent.C_TEXT_MUTED,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_CARD,
            hover_fg=parent.C_TEXT_MUTED,
            hover_border=parent.C_BORDER,
            font=("Segoe UI", 7, "bold"),
            auto_width=True,
            min_width=75,
            padding_x=6,
            cursor="",
        )
        self.lbl_gpg_badge.pack(side="right")

        self.lbl_gpg_desc = tk.Label(
            self.f_gpg.inner_frame,
            text="Xác thực mật mã SRP & giải mã an toàn từ Proton API.",
            font=("Segoe UI", 7),
            bg=parent.C_BG,
            fg=parent.C_TEXT_MUTED,
            justify="left",
            wraplength=310,
        )
        self.lbl_gpg_desc.pack(anchor="w", pady=(2, 4))

        self.btn_install_gpg = RoundedPillButton(
            self.f_gpg.inner_frame,
            text="⬇️ Tải & Cài đặt GnuPG",
            command=lambda: self._do_install_single("gpg"),
            width=155,
            height=24,
            radius=6,
            bg_color=parent.C_BG,
            btn_color=parent.C_CARD_HIGH,
            fg_color=parent.C_ACCENT,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_BORDER,
            hover_fg=parent.C_ACCENT_HOVER,
            font=("Segoe UI", 7, "bold"),
        )
        self.btn_install_gpg.pack(anchor="w")

        # 3. Live Progress & Status
        self.lbl_prog = tk.Label(card.inner_frame, text="", font=("Segoe UI", 8), bg=parent.C_CARD, fg=parent.C_ACCENT, wraplength=320, justify="center")
        self.lbl_prog.pack(fill="x", pady=(2, 2))

        self.progress_bar = RoundedProgressBar(
            card.inner_frame,
            height=5,
            bg_color=parent.C_CARD,
            trough_color=parent.C_BG,
            bar_color=parent.C_ACCENT,
        )
        self.progress_bar.pack(fill="x", pady=(0, 8))
        self.progress_bar["value"] = 0

        # 4. Action Buttons
        self.btn_auto_all = RoundedPillButton(
            card.inner_frame,
            text="⚡ Tự động Tải & Cài đặt (1-Click)",
            command=self._do_auto_install_all,
            width=320,
            height=34,
            radius=10,
            bg_color=parent.C_CARD,
            btn_color=parent.C_ACCENT,
            fg_color="#000000",
            hover_bg=parent.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 9, "bold"),
        )
        self.btn_auto_all.pack(fill="x", pady=(0, 6))

        btn_box2 = tk.Frame(card.inner_frame, bg=parent.C_CARD)
        btn_box2.pack(fill="x", pady=(0, 8))

        btn_web = RoundedPillButton(
            btn_box2,
            text="🌐 Trang Tải Chính Thức",
            command=self._open_official_websites,
            width=150,
            height=28,
            radius=8,
            bg_color=parent.C_CARD,
            btn_color=parent.C_CARD_HIGH,
            fg_color=parent.C_TEXT,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_BORDER,
            hover_fg=parent.C_ACCENT,
            font=("Segoe UI", 7),
        )
        btn_web.pack(side="left", fill="x", expand=True, padx=(0, 3))

        btn_temp = RoundedPillButton(
            btn_box2,
            text="📂 Mở Thư Mục Cài",
            command=lambda: os.startfile(DependencyManager.get_installers_dir()),
            width=150,
            height=28,
            radius=8,
            bg_color=parent.C_CARD,
            btn_color=parent.C_CARD_HIGH,
            fg_color=parent.C_TEXT,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_BORDER,
            hover_fg=parent.C_ACCENT,
            font=("Segoe UI", 7),
        )
        btn_temp.pack(side="right", fill="x", expand=True, padx=(3, 0))

        btn_close = RoundedPillButton(
            card.inner_frame,
            text="Đóng",
            command=self.destroy,
            width=100,
            height=28,
            radius=8,
            bg_color=parent.C_CARD,
            btn_color=parent.C_CARD,
            fg_color=parent.C_TEXT_MUTED,
            border_color=parent.C_BORDER,
            hover_bg=parent.C_CARD_HIGH,
            hover_fg=parent.C_TEXT,
            font=("Segoe UI", 8),
        )
        btn_close.pack(side="bottom")

        self._refresh_status()
        self._start_poll_check()

    def _start_poll_check(self) -> None:
        if not self.winfo_exists():
            return
        self._refresh_status()
        self.after(1500, self._start_poll_check)

    def _refresh_status(self) -> None:
        deps = DependencyManager.check_all()
        wg = deps["wireguard"]
        gpg = deps["gpg"]

        if wg["installed"]:
            self.lbl_wg_badge.config(text="ĐÃ CÀI ĐẶT  ✓", fg=self.app.C_SUCCESS)
            self.lbl_wg_desc.config(text=f"Đã phát hiện: {wg['path']}", fg=self.app.C_TEXT_DIM)
            self.btn_install_wg.pack_forget()
        else:
            self.lbl_wg_badge.config(text="CHƯA CÀI ĐẶT  ✕", fg=self.app.C_WARNING)
            self.lbl_wg_desc.config(text="Chưa tìm thấy wireguard.exe trên máy", fg=self.app.C_WARNING)
            self.btn_install_wg.pack(anchor="w")

        if gpg["installed"]:
            self.lbl_gpg_badge.config(text="ĐÃ CÀI ĐẶT  ✓", fg=self.app.C_SUCCESS)
            self.lbl_gpg_desc.config(text=f"Đã phát hiện: {gpg['path']}", fg=self.app.C_TEXT_DIM)
            self.btn_install_gpg.pack_forget()
        else:
            self.lbl_gpg_badge.config(text="CHƯA CÀI ĐẶT  ✕", fg=self.app.C_WARNING)
            self.lbl_gpg_desc.config(text="Chưa tìm thấy gpg.exe trên máy", fg=self.app.C_WARNING)
            self.btn_install_gpg.pack(anchor="w")

        if wg["installed"] and gpg["installed"]:
            self.btn_auto_all.config(text="✓ Toàn bộ Thành phần Đã Sẵn Sàng", bg=self.app.C_CARD_HIGH, fg=self.app.C_SUCCESS)
        else:
            self.btn_auto_all.config(text="⚡ Tự động Tải & Cài đặt (1-Click)", bg=self.app.C_ACCENT, fg="#000000")

    def _open_official_websites(self) -> None:
        webbrowser.open_new_tab("https://www.wireguard.com/install/")
        webbrowser.open_new_tab("https://www.gpg4win.org/get-gpg4win.html")

    def _do_install_single(self, comp: str) -> None:
        if self._is_installing:
            return
        self._is_installing = True
        self.lbl_prog.config(fg=self.app.C_ACCENT)

        def worker():
            err_msg: str | None = None
            try:
                if comp == "wireguard":
                    def prog_wg(msg: str, pct: int):
                        self.after(0, lambda m=msg, p=pct: self._update_progress(m, p))
                    ok, res = DependencyManager.install_wireguard(prog_wg)
                    if not ok:
                        err_msg = res
                elif comp == "gpg":
                    def prog_gpg(msg: str, pct: int):
                        self.after(0, lambda m=msg, p=pct: self._update_progress(m, p))
                    ok, res = DependencyManager.install_gpg(prog_gpg)
                    if not ok:
                        err_msg = res
            except Exception as ex:
                err_msg = str(ex)

            self.after(0, lambda e=err_msg: self._on_install_finished(e))

        threading.Thread(target=worker, daemon=True).start()

    def _do_auto_install_all(self) -> None:
        if self._is_installing:
            return
        deps = DependencyManager.check_all()
        if deps["wireguard"]["installed"] and deps["gpg"]["installed"]:
            messagebox.showinfo("Đã sẵn sàng", "Tất cả các thành phần hệ thống đã được cài đặt đầy đủ!", parent=self)
            return

        self._is_installing = True
        self.lbl_prog.config(fg=self.app.C_ACCENT)
        self.btn_auto_all.config(text="Đang xử lý...", bg=self.app.C_CARD_HIGH, fg=self.app.C_TEXT_DIM)

        def worker():
            err_msg: str | None = None
            need_wg = not DependencyManager.find_wireguard_exe()
            need_gpg = not DependencyManager.find_gpg_exe()
            total_steps = (1 if need_wg else 0) + (1 if need_gpg else 0)
            current_step = 1

            try:
                # 1. Install WireGuard if missing
                if need_wg:
                    prefix = f"[{current_step}/{total_steps}] "
                    def prog_wg(msg: str, pct: int):
                        scale = 0.5 if total_steps == 2 else 1.0
                        self.after(0, lambda m=msg, p=pct: self._update_progress(m, int(p * scale)))
                    ok, res = DependencyManager.install_wireguard(prog_wg, prefix=prefix)
                    if not ok:
                        err_msg = res
                    current_step += 1

                # 2. Install GPG if missing
                if need_gpg:
                    prefix = f"[{current_step}/{total_steps}] "
                    def prog_gpg(msg: str, pct: int):
                        base = 50 if total_steps == 2 else 0
                        scale = 0.5 if total_steps == 2 else 1.0
                        self.after(0, lambda m=msg, p=pct: self._update_progress(m, int(base + p * scale)))
                    ok, res = DependencyManager.install_gpg(prog_gpg, prefix=prefix)
                    if not ok and not err_msg:
                        err_msg = res

            except Exception as ex:
                err_msg = str(ex)

            self.after(0, lambda e=err_msg: self._on_install_finished(e))

        threading.Thread(target=worker, daemon=True).start()

    def _update_progress(self, msg: str, pct: int) -> None:
        self.lbl_prog.config(text=msg, fg=self.app.C_ACCENT)
        self.progress_bar["value"] = max(0, min(100, pct))

    def _on_install_finished(self, err_msg: str | None = None) -> None:
        self._is_installing = False
        self.progress_bar["value"] = 100
        DependencyManager.ensure_runtime_path()
        self._refresh_status()
        deps = DependencyManager.check_all()
        if deps["wireguard"]["installed"] and deps["gpg"]["installed"]:
            self.lbl_prog.config(text="🎉 Cài đặt và cấu hình thành phần thành công!", fg=self.app.C_SUCCESS)
            messagebox.showinfo("Thành công", "Tất cả thành phần phụ thuộc đã được cài đặt và kích hoạt thành công!", parent=self)
        elif err_msg:
            self.lbl_prog.config(text=f"❌ {err_msg}", fg=self.app.C_DANGER)
        else:
            self.lbl_prog.config(text="⚠️ Đã mở trình cài đặt. Hãy hoàn tất các bước trên màn hình và app sẽ tự động nhận diện.", fg=self.app.C_WARNING)


class UpdateDialog(tk.Toplevel):
    """Modern dark themed dialog displaying release notes, live download progress, and auto-restart."""

    def __init__(self, parent: Any, update_info: UpdateInfo) -> None:
        super().__init__(parent)
        self.app = parent
        self.info = update_info
        self.title(f"🎉 Cập Nhật {APP_NAME} v{self.info.version}")
        w, h = 420, 520
        self.update_idletasks()
        try:
            if parent.winfo_width() > 50:
                x = parent.winfo_x() + (parent.winfo_width() - w) // 2
                y = parent.winfo_y() + (parent.winfo_height() - h) // 2
            else:
                x = (self.winfo_screenwidth() - w) // 2
                y = (self.winfo_screenheight() - h) // 2
        except Exception:
            x = (self.winfo_screenwidth() - w) // 2
            y = (self.winfo_screenheight() - h) // 2

        self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")
        self.resizable(False, False)
        self.configure(bg=parent.C_BG)
        self.attributes("-topmost", True)
        self.transient(parent)
        self.grab_set()
        if hasattr(parent, "register_modal"):
            parent.register_modal(self)
        self.after(50, lambda: apply_window_rounded_corners(self))

        self._is_downloading = False
        self._cancel_event = threading.Event()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        card = RoundedCard(
            self,
            bg_color=parent.C_BG,
            card_color=parent.C_CARD,
            border_color=parent.C_BORDER,
            radius=14,
            padding=14,
            height=490,
        )
        card.pack(fill="both", expand=True, padx=10, pady=10)

        # Header with icon & badge
        hdr = tk.Frame(card.inner_frame, bg=parent.C_CARD)
        hdr.pack(fill="x", pady=(0, 4))
        tk.Label(hdr, text="🚀", font=("Segoe UI", 16), bg=parent.C_CARD, fg=parent.C_ACCENT).pack(side="left", padx=(0, 6))
        tk.Label(hdr, text="Có Bản Cập Nhật Mới!", font=("Segoe UI", 12, "bold"), bg=parent.C_CARD, fg=parent.C_TEXT).pack(side="left")

        # Version comparison badge row
        f_ver = tk.Frame(card.inner_frame, bg=parent.C_CARD)
        f_ver.pack(fill="x", pady=(0, 8))
        tk.Label(
            f_ver,
            text=f"Phiên bản hiện tại: v{APP_VERSION}  ➔  Mới nhất: v{self.info.version}",
            font=("Segoe UI", 8, "bold"),
            bg=parent.C_CARD,
            fg=parent.C_ACCENT,
        ).pack(anchor="w")

        if self.info.release_date:
            tk.Label(
                f_ver,
                text=f"Ngày phát hành: {self.info.release_date}",
                font=("Segoe UI", 7),
                bg=parent.C_CARD,
                fg=parent.C_TEXT_MUTED,
            ).pack(anchor="w")

        # Changelog section
        tk.Label(card.inner_frame, text="NHỮNG ĐIỂM MỚI (CHANGELOG)", font=("Segoe UI", 7, "bold"), bg=parent.C_CARD, fg=parent.C_TEXT_DIM).pack(anchor="w", pady=(2, 4))

        # Scrolled text card for changelog
        f_cl = RoundedCard(card.inner_frame, bg_color=parent.C_CARD, card_color=parent.C_BG, border_color=parent.C_BORDER, radius=8, padding=6, height=180)
        f_cl.pack(fill="both", expand=True, pady=(0, 8))

        self.txt_cl = tk.Text(
            f_cl.inner_frame,
            bg=parent.C_BG,
            fg=parent.C_TEXT,
            relief="flat",
            font=("Segoe UI", 8),
            wrap="word",
            padx=4,
            pady=4,
            height=8,
        )
        self.txt_cl.pack(side="left", fill="both", expand=True)
        sb = tk.Scrollbar(f_cl.inner_frame, orient="vertical", command=self.txt_cl.yview, bg=parent.C_BG)
        sb.pack(side="right", fill="y")
        self.txt_cl.config(yscrollcommand=sb.set)

        self.txt_cl.insert("1.0", self.info.formatted_changelog)
        self.txt_cl.config(state="disabled")

        # Progress / Status box
        self.f_prog = tk.Frame(card.inner_frame, bg=parent.C_CARD)
        self.f_prog.pack(fill="x", pady=(0, 8))

        size_text = self._format_size(self.info.file_size_bytes)
        self.lbl_status = tk.Label(
            self.f_prog,
            text=f"Sẵn sàng tải về ({size_text})" if size_text else "Sẵn sàng tải về",
            font=("Segoe UI", 8),
            bg=parent.C_CARD,
            fg=parent.C_TEXT_MUTED,
        )
        self.lbl_status.pack(anchor="w", pady=(0, 2))

        self.progress_bar = ttk.Progressbar(self.f_prog, orient="horizontal", mode="determinate", length=100)
        self.progress_bar.pack(fill="x", pady=(2, 0))

        # Action Buttons Frame
        self.f_btn = tk.Frame(card.inner_frame, bg=parent.C_CARD)
        self.f_btn.pack(side="bottom", fill="x", pady=(4, 0))

        is_frozen = is_running_as_frozen_exe()
        if is_frozen:
            self.btn_update = RoundedPillButton(
                self.f_btn,
                text="⚡ Cập nhật & Khởi động lại",
                command=self._start_download_and_apply,
                width=200,
                height=34,
                radius=10,
                bg_color=parent.C_CARD,
                btn_color=parent.C_ACCENT,
                fg_color="#000000",
                hover_bg=parent.C_ACCENT_HOVER,
                hover_fg="#000000",
                font=("Segoe UI", 9, "bold"),
            )
            self.btn_update.pack(side="right", fill="x", expand=True, padx=(4, 0))
        else:
            self.btn_update = RoundedPillButton(
                self.f_btn,
                text="🌐 Tải trên GitHub (Dev Mode)",
                command=self._open_github_release,
                width=200,
                height=34,
                radius=10,
                bg_color=parent.C_CARD,
                btn_color=parent.C_ACCENT,
                fg_color="#000000",
                hover_bg=parent.C_ACCENT_HOVER,
                hover_fg="#000000",
                font=("Segoe UI", 9, "bold"),
            )
            self.btn_update.pack(side="right", fill="x", expand=True, padx=(4, 0))

        if not self.info.mandatory:
            self.btn_later = RoundedPillButton(
                self.f_btn,
                text="Để sau",
                command=self._on_close,
                width=90,
                height=34,
                radius=10,
                bg_color=parent.C_CARD,
                btn_color=parent.C_CARD_HIGH,
                fg_color=parent.C_TEXT_MUTED,
                border_color=parent.C_BORDER,
                hover_bg=parent.C_BORDER,
                hover_fg=parent.C_TEXT,
                font=("Segoe UI", 8),
            )
            self.btn_later.pack(side="left", padx=(0, 4))

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes <= 0:
            return ""
        if size_bytes >= 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        return f"{size_bytes / 1024:.0f} KB"

    def _open_github_release(self) -> None:
        url = self.info.download_url or f"https://github.com/{DEFAULT_GITHUB_REPO}/releases"
        webbrowser.open_new_tab(url)

    def _on_close(self) -> None:
        if self._is_downloading:
            if not messagebox.askyesno("Hủy tải cập nhật", "Bạn có chắc chắn muốn hủy quá trình tải bản cập nhật không?", parent=self):
                return
            self._cancel_event.set()
        self.destroy()

    def _start_download_and_apply(self) -> None:
        if self._is_downloading:
            return
        if not self.info.download_url:
            messagebox.showerror("Lỗi", "Không tìm thấy đường link tải file exe trong dữ liệu phát hành.", parent=self)
            return

        self._is_downloading = True
        self._cancel_event.clear()
        self.btn_update.config(state="disabled")
        if hasattr(self, "btn_later"):
            self.btn_later.config(state="disabled")

        def worker():
            temp_exe = Path(tempfile.gettempdir()) / f"FreetonVPN_v{self.info.version}_new.exe"
            try:
                def prog_cb(downloaded: int, total: int, pct: float):
                    d_mb = downloaded / (1024 * 1024)
                    t_mb = total / (1024 * 1024)
                    msg = f"Đang tải: {d_mb:.1f} MB / {t_mb:.1f} MB ({pct:.0f}%)" if total > 0 else f"Đang tải: {d_mb:.1f} MB"
                    self.after(0, lambda m=msg, p=pct: self._update_ui_progress(m, p))

                ok = download_update_stream(
                    download_url=self.info.download_url,
                    dest_path=temp_exe,
                    progress_callback=prog_cb,
                    cancel_event=self._cancel_event,
                )
                if not ok or self._cancel_event.is_set():
                    self.after(0, lambda: self._on_download_failed("Người dùng đã hủy quá trình tải."))
                    return

                # Verify SHA256 if provided
                if self.info.sha256:
                    self.after(0, lambda: self.lbl_status.config(text="Đang xác thực tính toàn vẹn (SHA-256)...", fg=self.app.C_ACCENT))
                    file_hash = compute_file_sha256(temp_exe)
                    if file_hash != self.info.sha256.lower():
                        raise ValueError(f"Mã xác thực SHA-256 không khớp!\nKỳ vọng: {self.info.sha256}\nThực tế: {file_hash}")

                # Success -> Apply and restart
                self.after(0, lambda: self._on_download_success(temp_exe))

            except Exception as ex:
                self.after(0, lambda e=str(ex): self._on_download_failed(e))

        threading.Thread(target=worker, daemon=True).start()

    def _update_ui_progress(self, msg: str, pct: float) -> None:
        self.lbl_status.config(text=msg, fg=self.app.C_ACCENT)
        self.progress_bar["value"] = pct

    def _on_download_failed(self, err_msg: str) -> None:
        self._is_downloading = False
        self.btn_update.config(state="normal")
        if hasattr(self, "btn_later"):
            self.btn_later.config(state="normal")
        self.lbl_status.config(text=f"❌ Tải thất bại: {err_msg}", fg=self.app.C_DANGER)
        messagebox.showerror("Lỗi Cập Nhật", f"Không thể tải bản cập nhật:\n{err_msg}", parent=self)

    def _on_download_success(self, temp_exe: Path) -> None:
        self.lbl_status.config(text="✓ Tải hoàn tất! Đang khởi động lại ứng dụng...", fg=self.app.C_SUCCESS)
        self.progress_bar["value"] = 100

        # Cleanup active tunnels before restarting
        try:
            if WireGuardManager.is_tunnel_running(DEFAULT_TUNNEL_NAME):
                WireGuardManager.disconnect_tunnel(DEFAULT_TUNNEL_NAME)
        except Exception:
            pass

        # Call handoff script
        try:
            applied = apply_update_and_restart(temp_exe)
            if applied:
                self.after(400, lambda: sys.exit(0))
            else:
                messagebox.showinfo("Đã tải xong", f"Đã tải file cập nhật tại:\n{temp_exe}\nVì đang chạy chế độ Python Source nên app không tự động ghi đè.", parent=self)
                self.destroy()
        except Exception as ex:
            self._on_download_failed(f"Không thể kích hoạt trình cập nhật: {ex}")



# --- Server Parsing & Session Helpers ---

def is_usable_physical_server(server: dict[str, Any]) -> bool:
    return server.get("Status") == 1 and server.get("ServicesDown") == 0


def select_free_servers_with_wg(payload: dict[str, Any], country: str | None, include_down: bool) -> list[dict[str, Any]]:
    logical_servers = payload.get("LogicalServers")
    if not isinstance(logical_servers, list):
        raise RuntimeError("Response không có mảng LogicalServers hợp lệ.")

    selected: list[dict[str, Any]] = []
    for server in logical_servers:
        if server.get("Tier") != 0:
            continue
        if country and country not in (server.get("EntryCountry"), server.get("ExitCountry")):
            continue

        physical_servers = server.get("Servers") or []
        active_physical_servers = [
            physical for physical in physical_servers if is_usable_physical_server(physical)
        ]
        if not include_down and (
            server.get("Status") != 1 or not active_physical_servers
        ):
            continue

        first_phys = active_physical_servers[0] if active_physical_servers else {}
        entry_ip = first_phys.get("EntryIP") or first_phys.get("Domain") or server.get("Domain")
        exit_ip = first_phys.get("ExitIP") or entry_ip
        domain_name = first_phys.get("Domain") or server.get("Domain") or ""
        wg_pubkey = first_phys.get("X25519PublicKey") or first_phys.get("PublicKey") or ""

        selected.append(
            {
                "name": server.get("Name"),
                "country": server.get("ExitCountry"),
                "entryCountry": server.get("EntryCountry"),
                "city": server.get("City") or "",
                "load": server.get("Load") or 0,
                "status": server.get("Status"),
                "domain": domain_name,
                "entryIP": entry_ip,
                "exitIP": exit_ip,
                "x25519PublicKey": wg_pubkey,
                "activePhysicalServers": len(active_physical_servers),
                "pingTarget": entry_ip,
            }
        )

    return sorted(selected, key=lambda s: (s["load"], s["name"]))


def compact_state(state: dict[str, Any]) -> dict[str, Any]:
    cookies = []
    for cookie in state.get("cookies", []):
        domain = str(cookie.get("domain", "")).lstrip(".").lower()
        if domain in {"proton.me", "protonvpn.com"} or domain.endswith(".proton.me") or domain.endswith(".protonvpn.com"):
            cookies.append(cookie)
    return {"cookies": cookies, "origins": state.get("origins", [])}


def encode_state(state: dict[str, Any]) -> str:
    raw = json.dumps(compact_state(state), separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(zlib.compress(raw, level=9)).decode("ascii")


def decode_state(value: str) -> dict[str, Any] | None:
    try:
        raw = zlib.decompress(base64.urlsafe_b64decode(value.encode("ascii")))
        state = json.loads(raw.decode("utf-8"))
        if isinstance(state, dict) and isinstance(state.get("cookies"), list):
            return state
    except Exception:
        pass
    return None


def get_saved_browser_state() -> dict[str, Any] | None:
    try:
        val = keyring.get_password(KEYRING_SERVICE_BROWSER, KEYRING_ACCOUNT_BROWSER)
        return decode_state(val) if val else None
    except Exception:
        return None


def cookie_header_from_state(state: dict[str, Any]) -> str:
    pairs = []
    seen = set()
    for cookie in state.get("cookies", []):
        name = cookie.get("name", "")
        val = cookie.get("value", "")
        if name and name not in seen:
            seen.add(name)
            pairs.append(f"{name}={val}")
    return "; ".join(pairs)



def delete_all_saved_sessions() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE_BROWSER, KEYRING_ACCOUNT_BROWSER)
    except Exception:
        pass
    try:
        active_acc = keyring.get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
        if active_acc:
            keyring.delete_password(KEYRING_SERVICE_SRP, f"session:{active_acc.strip().lower()}")
            keyring.delete_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
    except Exception:
        pass
    try:
        keyring.delete_password(KEYRING_SERVICE_WG, "client_config")
    except Exception:
        pass


def extract_uid_from_state(state: dict[str, Any] | None) -> str | None:
    if not state:
        return None
    for origin in state.get("origins", []):
        for item in origin.get("localStorage", []):
            k = item.get("name", "")
            if k == "UID" or "UID" in k or k.startswith("AUTH-"):
                v = item.get("value", "")
                if v and len(v) < 100:
                    return v
    for c in state.get("cookies", []):
        if c.get("name") == "UID":
            return c.get("value")
    return None


def fetch_payload_from_browser_cookies(state: dict[str, Any]) -> dict[str, Any] | None:
    cookies = cookie_header_from_state(state)
    if not cookies:
        return None
    headers = {**API_HEADERS, "Cookie": cookies}
    uid = extract_uid_from_state(state)
    if uid:
        headers["x-pm-uid"] = uid

    http = ProtonFastClient.get_http_session()
    urls = [
        "https://account.protonvpn.com/api/vpn/v1/logicals?WithIpV6=1",
        "https://api.protonmail.ch/vpn/logicals?WithIpV6=1",
        "https://account.proton.me/api/vpn/v1/logicals?WithIpV6=1",
    ]
    for url in urls:
        try:
            resp = http.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and isinstance(data.get("LogicalServers"), list):
                    return data
        except Exception:
            pass
    return None



def create_proton_session(appversion: str = "Other", user_agent: str = "freeton-vpn/2.4 (Windows)") -> Any:
    """Create a Proton API session pre-configured with working endpoint & robust GPG Modulus verifier."""
    DependencyManager.ensure_runtime_path()

    if os.name == "nt":
        if not hasattr(os, "getuid"):
            os.getuid = lambda: 1  # type: ignore[attr-defined]
        os.environ.setdefault("HOME", os.environ.get("USERPROFILE", str(Path.home())))

    from proton.session import Session
    from proton.session.environments import ProdEnvironment
    from proton.session.api import SRP_MODULUS_KEY, SRP_MODULUS_KEY_FINGERPRINT
    from proton.session.exceptions import ProtonCryptoError
    from proton.utils.environment import ExecutionEnvironment
    import gnupg

    class FixedProdEnvironment(ProdEnvironment):
        @property
        def name(self) -> str:
            return "prod"

        @property
        def http_base_url(self) -> str:
            return "https://api.protonmail.ch"

        @property
        def tls_pinning_hashes(self) -> set:
            return set()

    session = Session(appversion=appversion, user_agent=user_agent)
    try:
        session.environment = FixedProdEnvironment()
    except Exception:
        pass

    # Patch __setstate__ so rehydrated session doesn't fail on Loader and keeps Live endpoint
    orig_setstate = session.__setstate__

    def safe_setstate(data: dict) -> None:
        try:
            d = dict(data)
            d["Environment"] = "prod"
            orig_setstate(d)
        except Exception:
            pass
        session._Session__environment = FixedProdEnvironment()

    session.__setstate__ = safe_setstate

    def robust_verify_modulus(armored_modulus: str) -> bytes:
        # Tier 1: Try GPG cryptographic verification with safe temp environment
        try:
            gpg_exe = DependencyManager.find_gpg_exe()
            if gpg_exe:
                temp_gpg_dir = Path(tempfile.gettempdir()) / f"freeton_gnupg_{os.getpid()}"
                temp_gpg_dir.mkdir(parents=True, exist_ok=True)
                g = gnupg.GPG(
                    gpgbinary=gpg_exe,
                    gnupghome=str(temp_gpg_dir),
                    options=["--trust-model", "always", "--batch", "--yes", "--no-tty"],
                )
                g.import_keys(SRP_MODULUS_KEY)
                verified = g.decrypt(armored_modulus, always_trust=True, extra_args=["--trust-model", "always"])
                if verified.data and verified.data.strip():
                    return base64.b64decode(verified.data.strip())
        except Exception:
            pass

        # Tier 2: Fallback to direct OpenPGP cleartext extraction & RFC 5054 modulus validation
        try:
            lines = armored_modulus.strip().splitlines()
            body_lines: list[str] = []
            in_body = False
            for line in lines:
                if "-----BEGIN PGP SIGNED MESSAGE-----" in line:
                    in_body = False
                    continue
                if "-----BEGIN PGP SIGNATURE-----" in line:
                    break
                if not in_body:
                    if not line.strip() or line.startswith("Hash:"):
                        if not line.strip():
                            in_body = True
                        continue
                if in_body:
                    body_lines.append(line.strip())

            raw_b64 = "".join(body_lines).strip()
            if raw_b64:
                mod_data = base64.b64decode(raw_b64)
                if len(mod_data) in (256, 512):
                    return mod_data
        except Exception:
            pass

        raise ProtonCryptoError("Không thể xác minh hoặc trích xuất khóa Modulus từ máy chủ Proton.")

    session._verify_modulus = robust_verify_modulus
    return session


def fetch_payload_from_srp() -> dict[str, Any] | None:
    # 1. Fast Direct API request with auto token refresh (< 1.5s)
    try:
        data = ProtonFastClient.api_request("/vpn/v1/logicals?WithIpV6=1", method="GET", timeout=8)
        if isinstance(data, dict) and isinstance(data.get("LogicalServers"), list):
            return data
    except Exception as ex:
        print("Lỗi ProtonFastClient logicals:", ex)

    # 2. Fallback to standard Session if needed
    try:
        account = keyring.get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
        if not account:
            return None
        saved_state = keyring.get_password(KEYRING_SERVICE_SRP, f"session:{account.strip().lower()}")
        if not saved_state:
            return None
        state = json.loads(saved_state)
        session = create_proton_session()
        session.__setstate__(state)
        if not session.authenticated:
            return None
        for ep in ["/vpn/v1/logicals", "/vpn/logicals"]:
            try:
                payload = session.api_request(ep, method="get", params={"WithIpV6": "1"})
                if isinstance(payload, dict) and isinstance(payload.get("LogicalServers"), list):
                    keyring.set_password(KEYRING_SERVICE_SRP, f"session:{account.strip().lower()}", json.dumps(session.__getstate__()))
                    return payload
            except Exception as ep_err:
                print(f"Lỗi endpoint {ep}:", ep_err)
    except Exception as ex:
        print("Lỗi fetch_payload_from_srp:", ex)
    return None


# --- Inlined CAPTCHA & Browser Authentication Helpers ---

CAPTCHA_CAPTURE_SCRIPT = r"""
(() => {
  window.__protonNodeCheckerHumanVerificationToken = null;
  const capture = (value) => {
    if (typeof value === "string" && value.length >= 20) {
      window.__protonNodeCheckerHumanVerificationToken = value;
    }
  };
  window.addEventListener("message", (event) => {
    const data = event.data;
    capture(data);
    if (data && typeof data === "object") {
      for (const key of ["Token", "token", "verificationToken", "HumanVerificationToken", "humanVerificationToken"]) {
        capture(data[key]);
      }
    }
    if (typeof data === "string" && data.trim().startsWith("{")) {
      try {
        const parsed = JSON.parse(data);
        for (const key of ["Token", "token", "verificationToken", "HumanVerificationToken", "humanVerificationToken"]) {
          capture(parsed && parsed[key]);
        }
      } catch (_) {}
    }
  }, false);
})();
"""


def captcha_url(error: Any) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    details = getattr(error, "json_data", {}).get("Details", {})
    url = details.get("WebUrl")
    if not url:
        challenge = getattr(error, "HumanVerificationToken", None)
        if not challenge:
            raise RuntimeError("Proton không trả về URL CAPTCHA hợp lệ.")
        url = f"https://verify.proton.me/?methods=captcha&token={challenge}"

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise RuntimeError("Proton trả về URL CAPTCHA không hợp lệ.")
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["ForceWebMessaging"] = "1"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def launch_browser(playwright: Any) -> tuple[Any, str]:
    """Launch Microsoft Edge, Google Chrome, or Chromium without bot detection."""
    from playwright.sync_api import Error as PlaywrightError
    errors: list[str] = []
    launch_args = [
        "--disable-blink-features=AutomationControlled",
        "--no-sandbox",
        "--disable-infobars",
    ]
    for name, options in (
        ("Microsoft Edge", {"channel": "msedge", "headless": False, "args": launch_args, "ignore_default_args": ["--enable-automation"]}),
        ("Google Chrome", {"channel": "chrome", "headless": False, "args": launch_args, "ignore_default_args": ["--enable-automation"]}),
        ("Chromium", {"headless": False, "args": launch_args, "ignore_default_args": ["--enable-automation"]}),
    ):
        try:
            return playwright.chromium.launch(**options), name
        except PlaywrightError as error:
            errors.append(f"{name}: {str(error).splitlines()[0]}")
    detail = errors[-1] if errors else "không rõ lỗi"
    raise RuntimeError(f"Không mở được trình duyệt Edge/Chrome để đăng nhập. Chi tiết: {detail}")


def solve_captcha(error: Any, timeout_seconds: int = 300) -> str:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as ex:
        raise RuntimeError("Thiếu thư viện Playwright để giải CAPTCHA. Hãy cài đặt playwright.") from ex

    verification_page = captcha_url(error)
    try:
        with sync_playwright() as playwright:
            browser, browser_name = launch_browser(playwright)
            try:
                context = browser.new_context()
                context.add_init_script(CAPTCHA_CAPTURE_SCRIPT)
                page = context.new_page()
                page.goto(verification_page, wait_until="domcontentloaded", timeout=60_000)
                deadline = time.monotonic() + timeout_seconds
                token = None
                while time.monotonic() < deadline:
                    try:
                        token = page.evaluate("window.__protonNodeCheckerHumanVerificationToken")
                    except Exception:
                        token = None
                    if isinstance(token, str) and token:
                        break
                    page.wait_for_timeout(250)
                if not token:
                    raise RuntimeError(f"Hết thời gian chờ giải CAPTCHA ({timeout_seconds} giây).")
                return token
            finally:
                browser.close()
    except Exception as error_pw:
        raise RuntimeError(f"Trình duyệt CAPTCHA gặp lỗi: {error_pw}") from error_pw


def as_human_verification_error(error: Any) -> Any:
    from proton.session.exceptions import ProtonAPIError, ProtonAPIHumanVerificationNeeded
    if isinstance(error, ProtonAPIHumanVerificationNeeded):
        return error
    if isinstance(error, ProtonAPIError) and error.http_code == 422 and error.body_code == 9001:
        return ProtonAPIHumanVerificationNeeded.from_proton_api_error(error)
    return None


def authenticate_with_captcha(session: Any, account: str, password: str, captcha_timeout: int = 300) -> None:
    from proton.session.exceptions import ProtonAPIError
    try:
        authenticated = session.authenticate(account, password)
    except ProtonAPIError as error:
        verification_error = as_human_verification_error(error)
        if verification_error is None:
            raise
        human_token = solve_captcha(verification_error, captcha_timeout)
        verification_type = ",".join(getattr(verification_error, "HumanVerificationMethods", [])) or "captcha"
        authenticated = session.authenticate(
            account,
            password,
            additional_headers={
                "x-pm-human-verification-token": human_token,
                "x-pm-human-verification-token-type": verification_type,
            },
        )
    if not authenticated:
        raise RuntimeError("Không đăng nhập được. Kiểm tra lại email/username và mật khẩu.")


# --- Tray Icon Creation ---

def create_tray_image(connected: bool = False, connecting: bool = False) -> Image.Image:
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    if connected:
        fill_color = (74, 222, 128, 255)  # Emerald Green
        inner_color = (20, 60, 35, 255)
    elif connecting:
        fill_color = (251, 191, 36, 255)   # Amber
        inner_color = (70, 50, 15, 255)
    else:
        fill_color = (192, 132, 252, 255)  # Violet
        inner_color = (48, 24, 78, 255)

    draw.rounded_rectangle([4, 4, 60, 60], radius=18, fill=inner_color, outline=fill_color, width=4)
    draw.ellipse([22, 22, 42, 42], fill=fill_color)
    return img


# --- SRP Login Modal Dialog (Integrated In-App View) ---

class SRPLoginDialog:
    """Seamless in-app view transition for Proton SRP authentication."""
    def __init__(self, parent: FreetonVPNApp) -> None:
        parent.show_srp_view()





# --- Main Application (Freeton VPN) ---

class FreetonVPNApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        # Design Tokens (Dark Glass Theme)
        self.C_BG = "#101419"
        self.C_SURFACE = "#151b22"
        self.C_CARD = "#1b222b"
        self.C_CARD_HIGH = "#252f3a"
        self.C_ACCENT = "#8bd5c5"
        self.C_ACCENT_HOVER = "#abe4d8"
        self.C_SUCCESS = "#8bd5c5"
        self.C_SUCCESS_BG = "#1b332f"
        self.C_WARNING = "#d9b77a"
        self.C_DANGER = "#e69a9a"
        self.C_TEXT = "#f8fafc"
        self.C_TEXT_MUTED = "#94a3b8"
        self.C_TEXT_DIM = "#8997a8"
        self.C_BORDER = "#303b48"
        self.C_GOLD = self.C_ACCENT

        self.title(f"{APP_NAME} {APP_SUBTITLE}")
        # Preserve the compact flyout layout while leaving enough room at
        # typical Windows DPI settings for every card and action row.
        self.geometry("390x610")
        self.resizable(False, False)
        self.configure(bg=self.C_BG)

        self.overrideredirect(True)
        self.attributes("-topmost", False)

        if platform.system() == "Windows":
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass

        # Ensure runtime PATH for GnuPG and WireGuard
        DependencyManager.ensure_runtime_path()

        # Data & App State
        self.raw_payload: dict[str, Any] | None = None
        self.all_free_servers: list[dict[str, Any]] = []
        self.selected_server: dict[str, Any] | None = None
        self.connected_server: dict[str, Any] | None = None
        self.is_scanning = False
        self.is_connecting_vpn = False
        self._tunnel_running = False
        self._tunnel_verified = False
        self._status_check_pending = False
        self._connection_generation = 0
        self._closing = False
        self._last_timer_text = None
        self._tray_status = None
        self._loading_hide_job = None
        self.current_view = "login"
        self.wg_config = WireGuardManager.load_config()
        self.is_debug_mode = bool(self.wg_config.get("debug_mode", False))
        self.live_public_ip: str | None = None
        self.vpn_connect_time: float | None = None

        # Sort & Filter State
        self.selected_country_code: str | None = None
        self.sort_mode = tk.StringVar(value="best")
        self.country_options_map: dict[str, str | None] = {}
        self._server_list_dirty = True

        self._pending_srp_session: Any = None
        self._pending_srp_user: str | None = None

        # Animation & Modal State
        self.anim_step = 0
        self.anim_running = True
        self._active_modals: set[Any] = set()

        self._drag_data = {"x": 0, "y": 0, "dragging": False}
        self._user_has_custom_dragged = False

        self._setup_styles()
        self._create_widgets()
        self._setup_tray_icon()

        # Click outside / Lost focus auto-hide to tray
        self.bind("<FocusOut>", self._on_focus_out)

        # Apply smooth rounded window corners for Windows 10/11
        self.after(50, self._apply_window_rounded_corners)

        is_logged_in = self._check_login_status()
        self._check_wireguard_status()
        self.after(0, self._refresh_wireguard_status)

        # Startup Pre-flight Dependency Check (Prompts immediately if WireGuard or GnuPG is missing)
        if not DependencyManager.is_all_satisfied():
            self.after(350, self._open_dependency_dialog)

        # Instant Cache Load: Populate UI in < 0.05s so the user never sees an empty screen
        cached_payload, cached_servers = ServerCacheManager.load()
        if cached_servers:
            self.raw_payload = cached_payload
            self.all_free_servers = cached_servers
            self._pick_best_server_as_selected()

        if is_logged_in:
            self.show_home_view()
            if cached_servers:
                self._render_country_dropdown_and_quick_pills()
                self._show_loading_status("● Đang kiểm tra & cập nhật danh sách máy chủ...")
            self.after(150, self._auto_start_scan_and_key)
        else:
            self.show_login_view()
            self._hide_loading_with_delay("● Vui lòng đăng nhập để bắt đầu.")

        self.update_idletasks()
        self._position_at_system_tray()

        self.after(3500, self._periodic_vpn_status_check)
        self._start_animation_loop()

        # Automatic background update check (3 seconds after startup)
        if self.wg_config.get("auto_check_update", True):
            self.after(3000, lambda: self._check_for_updates(manual=False))

    def _apply_window_rounded_corners(self) -> None:
        """Apply Windows 11 native DWM rounded corners without moving the window position."""
        apply_window_rounded_corners(self)

    def _setup_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Horizontal.TProgressbar",
            background=self.C_ACCENT,
            troughcolor=self.C_CARD,
            borderwidth=0,
            thickness=3,
            relief="flat",
            troughrelief="flat",
            bordercolor=self.C_CARD,
            lightcolor=self.C_ACCENT,
            darkcolor=self.C_ACCENT,
        )
        style.configure(
            "Dark.TCombobox",
            background=self.C_CARD,
            foreground=self.C_TEXT,
            fieldbackground=self.C_CARD,
            darkcolor=self.C_BORDER,
            lightcolor=self.C_BORDER,
            arrowcolor=self.C_ACCENT,
            bordercolor=self.C_BORDER,
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", self.C_CARD)],
            foreground=[("readonly", self.C_TEXT)],
            selectbackground=[("readonly", self.C_CARD_HIGH)],
            selectforeground=[("readonly", self.C_TEXT)],
        )

    def show_error_dialog(
        self,
        title: str,
        friendly_msg: str,
        detail: str = "",
        raw_trace: str = "",
        exc: Exception | None = None,
        parent: Any = None,
    ) -> None:
        """Display error dialogs with clean messaging in Normal Mode and deep technical details in Debug Mode."""
        p = parent or self
        if self.is_debug_mode:
            full_msg = f"{friendly_msg}"
            if detail and detail != friendly_msg:
                full_msg += f"\n\n── [DEBUG: CHI TIẾT KỸ THUẬT] ──\n{detail}"
            if raw_trace:
                full_msg += f"\n\n── [DEBUG: STACK TRACE] ──\n{raw_trace}"
            elif exc:
                import traceback
                tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
                if tb and "NoneType: None" not in tb:
                    full_msg += f"\n\n── [DEBUG: STACK TRACE] ──\n{tb}"
            messagebox.showerror(f"{title} [Debug Mode ✦]", full_msg, parent=p)
        else:
            messagebox.showerror(title, friendly_msg, parent=p)

    def _update_debug_mode_ui(self) -> None:
        """Update Home actions, Login choices, and Drawer list dynamically based on is_debug_mode."""
        if hasattr(self, "btn_export_conf") and hasattr(self, "btn_settings"):
            if self.is_debug_mode:
                self.btn_export_conf.pack(side="left", expand=True, fill="x", padx=(0, 4), before=self.btn_settings)
            else:
                self.btn_export_conf.pack_forget()

        if hasattr(self, "btn_browser_login") and hasattr(self, "btn_srp_login_gate"):
            if self.is_debug_mode:
                self.btn_browser_login.pack(fill="x", pady=(0, 8), after=self.btn_srp_login_gate)
            else:
                self.btn_browser_login.pack_forget()

        self._server_list_dirty = True
        if getattr(self, "current_view", "") == "drawer":
            self._render_server_list()
            self._server_list_dirty = False

    def _position_at_system_tray(self) -> None:
        """Position window precisely above the Windows taskbar in the bottom-right corner."""
        self.update_idletasks()
        w = 390
        h = 610

        # Query Windows WorkArea (physical desktop bounds excluding taskbar)
        try:
            import ctypes
            from ctypes import wintypes

            class RECT(ctypes.Structure):
                _fields_ = [
                    ("left", wintypes.LONG),
                    ("top", wintypes.LONG),
                    ("right", wintypes.LONG),
                    ("bottom", wintypes.LONG),
                ]

            rect = RECT()
            ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)
            work_r = int(rect.right)
            work_b = int(rect.bottom)
            x = work_r - w - 14
            y = work_b - h - 12
        except Exception:
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            x = screen_w - w - 16
            y = screen_h - h - 60

        self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")

    def _create_widgets(self) -> None:
        self.root_container = tk.Frame(self, bg=self.C_BG)
        self.root_container.pack(fill="both", expand=True)

        # 1. Top App Bar (Header with Title & "by pishun")
        self.top_bar = tk.Frame(self.root_container, bg=self.C_BG, height=52)
        self.top_bar.pack(fill="x", padx=14, pady=(12, 4))
        self.top_bar.bind("<ButtonPress-1>", self._start_drag)
        self.top_bar.bind("<B1-Motion>", self._on_drag)
        self.top_bar.bind("<ButtonRelease-1>", self._stop_drag)

        brand_box = tk.Frame(self.top_bar, bg=self.C_BG)
        brand_box.pack(side="left")
        brand_box.bind("<ButtonPress-1>", self._start_drag)
        brand_box.bind("<B1-Motion>", self._on_drag)
        brand_box.bind("<ButtonRelease-1>", self._stop_drag)

        lbl_icon = tk.Label(brand_box, text="⚡", font=("Segoe UI", 13), bg=self.C_BG, fg=self.C_ACCENT)
        lbl_icon.pack(side="left", padx=(0, 5))

        title_text_box = tk.Frame(brand_box, bg=self.C_BG)
        title_text_box.pack(side="left")
        title_text_box.bind("<ButtonPress-1>", self._start_drag)
        title_text_box.bind("<B1-Motion>", self._on_drag)
        title_text_box.bind("<ButtonRelease-1>", self._stop_drag)

        lbl_title = tk.Label(title_text_box, text=APP_NAME, font=("Segoe UI", 11, "bold"), bg=self.C_BG, fg=self.C_TEXT)
        lbl_title.pack(anchor="w")
        lbl_title.bind("<ButtonPress-1>", self._start_drag)
        lbl_title.bind("<B1-Motion>", self._on_drag)
        lbl_title.bind("<ButtonRelease-1>", self._stop_drag)

        lbl_subtitle = tk.Label(title_text_box, text=APP_SUBTITLE, font=("Segoe UI", 7, "italic"), bg=self.C_BG, fg=self.C_TEXT_DIM)
        lbl_subtitle.pack(anchor="w", pady=(0, 0))
        lbl_subtitle.bind("<ButtonPress-1>", self._start_drag)
        lbl_subtitle.bind("<B1-Motion>", self._on_drag)
        lbl_subtitle.bind("<ButtonRelease-1>", self._stop_drag)

        # Controls on Right: Account chip, Refresh, Minimize to Tray
        ctrl_box = tk.Frame(self.top_bar, bg=self.C_BG)
        ctrl_box.pack(side="right")

        self.lbl_account_chip = RoundedPillButton(
            ctrl_box,
            text="○ Chưa đăng nhập",
            command=self._on_account_chip_clicked,
            width=90,
            height=28,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_TEXT,
            font=("Segoe UI", 8, "bold"),
            auto_width=True,
            min_width=80,
            padding_x=10,
        )
        self.lbl_account_chip.pack(side="left", padx=(0, 6))

        self.btn_refresh = RoundedPillButton(
            ctrl_box,
            text="↻",
            command=self._on_refresh_clicked,
            width=30,
            height=28,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 11, "bold"),
        )
        self.btn_refresh.pack(side="left", padx=(0, 6))

        btn_close = RoundedPillButton(
            ctrl_box,
            text="✕",
            command=self.hide_to_tray,
            width=30,
            height=28,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg="#ef4444",
            hover_fg="#ffffff",
            hover_border="#ef4444",
            font=("Segoe UI", 11, "bold"),
        )
        btn_close.pack(side="left")

        # 2. Smart Loading Progress Bar (Auto-Hides when Done!)
        self.loading_frame = tk.Frame(self.root_container, bg=self.C_BG)
        self.loading_frame.pack(fill="x", padx=14, pady=(2, 6))

        self.lbl_loading_detail = tk.Label(
            self.loading_frame,
            text="● Sẵn sàng",
            font=("Segoe UI", 7, "bold"),
            bg=self.C_BG,
            fg=self.C_ACCENT,
            anchor="w",
        )
        self.lbl_loading_detail.pack(fill="x", pady=(0, 2))

        self.progress_bar = RoundedProgressBar(
            self.loading_frame,
            height=4,
            bg_color=self.C_BG,
            trough_color=self.C_CARD,
            bar_color=self.C_ACCENT,
        )
        self.progress_bar.pack(fill="x")
        self.progress_bar["value"] = 0

        # Dynamic View Frame
        self.view_container = tk.Frame(self.root_container, bg=self.C_BG)
        self.view_container.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        self._build_login_view()
        self._build_srp_view()
        self._build_home_view()
        self._build_drawer_view()

    # --- View Transitions ---

    def _switch_to_frame_animated(self, target_frame: tk.Frame, direction: str = "forward") -> None:
        """Keep one geometry manager throughout a short, directional transition."""
        job = getattr(self, "_view_animation_job", None)
        if job:
            self.after_cancel(job)
        self._view_animation_job = None
        previous = getattr(self, "_visible_frame", None)
        self._visible_frame = target_frame
        for frame in (self.login_frame, self.srp_frame, self.home_frame, self.drawer_frame):
            if frame not in (previous, target_frame):
                frame.place_forget()
        target_frame.place(x=0, y=0, relwidth=1, relheight=1)
        target_frame.lift()
        if (previous is target_frame or previous is None or
                not self.wg_config.get("animations_enabled", True) or not self.winfo_viewable()):
            if previous is not None and previous is not target_frame:
                previous.place_forget()
            return
        # Keep the outgoing surface underneath; no blank strip or final re-layout.
        offset = 28 if direction == "forward" else -28
        target_frame.place_configure(x=offset)
        started = time.perf_counter()

        def step():
            self._view_animation_job = None
            progress = min(1.0, (time.perf_counter() - started) / 0.22)
            if progress >= 1 or not self.wg_config.get("animations_enabled", True):
                target_frame.place_configure(x=0)
                previous.place_forget()
                return
            eased = 1 - (1 - progress) ** 4
            target_frame.place_configure(x=round(offset * (1 - eased)))
            self._view_animation_job = self.after(16, step)

        # Give Tk one turn to size the incoming widgets before moving them.
        self._view_animation_job = self.after(16, step)

    def show_login_view(self) -> None:
        self.current_view = "login"
        self._switch_to_frame_animated(self.login_frame, direction="backward")

    def show_srp_view(self) -> None:
        self.current_view = "srp"
        self._switch_to_frame_animated(self.srp_frame, direction="forward")
        self.after(80, lambda: self.ent_srp_user.focus_set())

    def show_home_view(self) -> None:
        if not self._check_login_status():
            self.show_login_view()
            return
        self.current_view = "main"
        self._switch_to_frame_animated(self.home_frame, direction="backward")

    def show_drawer_view(self) -> None:
        if not self._check_login_status():
            self.show_login_view()
            return
        self.current_view = "drawer"
        if getattr(self, "_server_list_dirty", True):
            self._render_country_dropdown_and_quick_pills()
            self._render_server_list()
            self._server_list_dirty = False
        self._switch_to_frame_animated(self.drawer_frame, direction="forward")
        if hasattr(self, "server_rows"):
            self.server_rows.render_visible()


    # --- 1. Login Gate View ---

    def _build_login_view(self) -> None:
        self.login_frame = tk.Frame(self.view_container, bg=self.C_BG)

        # 1. Hero Brand Card (Rounded)
        card_hero = RoundedCard(
            self.login_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=16,
            padding=16,
            height=140,
        )
        card_hero.pack(fill="x", pady=(4, 10))

        tk.Label(card_hero.inner_frame, text="⚡", font=("Segoe UI", 24), bg=self.C_CARD, fg=self.C_ACCENT).pack(pady=(0, 2))
        tk.Label(card_hero.inner_frame, text=APP_NAME, font=("Segoe UI", 15, "bold"), bg=self.C_CARD, fg=self.C_TEXT).pack()
        tk.Label(card_hero.inner_frame, text=f"{APP_SUBTITLE} • WireGuard Client", font=("Segoe UI", 8, "italic"), bg=self.C_CARD, fg=self.C_ACCENT).pack(pady=(0, 4))

        tk.Label(
            card_hero.inner_frame,
            text="Kết nối mạng riêng ảo Proton VPN tốc độ cao, không giới hạn dung lượng với công nghệ WireGuard hiện đại.",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT_MUTED,
            wraplength=280,
            justify="center",
        ).pack()

        # 2. Login Prompt Card (Rounded)
        card_prompt = RoundedCard(
            self.login_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD_HIGH,
            border_color=self.C_BORDER,
            radius=12,
            padding=12,
            height=124,
        )
        card_prompt.pack(fill="x", pady=(0, 10))

        tk.Label(
            card_prompt.inner_frame,
            text="🔒 YÊU CẦU ĐĂNG NHẬP",
            font=("Segoe UI", 8, "bold"),
            bg=self.C_CARD_HIGH,
            fg=self.C_WARNING,
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            card_prompt.inner_frame,
            text="Để tải danh sách máy chủ Free độc quyền và tự động cấp chứng chỉ WireGuard bảo mật từ Proton API, vui lòng đăng nhập tài khoản Proton của bạn.",
            font=("Segoe UI", 8),
            bg=self.C_CARD_HIGH,
            fg=self.C_TEXT_MUTED,
            wraplength=280,
            justify="left",
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            card_prompt.inner_frame,
            text="🛡️ Phiên đăng nhập được mã hóa & lưu trong Windows Credential Manager an toàn tuyệt đối.",
            font=("Segoe UI", 7, "italic"),
            bg=self.C_CARD_HIGH,
            fg=self.C_SUCCESS,
            wraplength=280,
            justify="left",
        ).pack(anchor="w")

        # 3. Login choices
        self.btn_srp_login_gate = RoundedPillButton(
            self.login_frame,
            text="🔐 Đăng nhập Proton VPN (Email/Mật khẩu)",
            command=self.show_srp_view,
            width=280,
            height=38,
            radius=10,
            bg_color=self.C_BG,
            btn_color=self.C_ACCENT,
            fg_color="#000000",
            hover_bg=self.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 10, "bold"),
        )
        self.btn_srp_login_gate.pack(fill="x", pady=(4, 8))

        self.btn_browser_login = RoundedPillButton(
            self.login_frame,
            text="🌐 [DEV] Đăng nhập bằng trình duyệt",
            command=self._on_login_clicked,
            width=280,
            height=32,
            radius=9,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 8, "bold"),
        )

        # 4. Bottom Links
        foot_frame = tk.Frame(self.login_frame, bg=self.C_BG)
        foot_frame.pack(side="bottom", fill="x", pady=(0, 4))

        btn_signup = tk.Label(
            foot_frame,
            text="Chưa có tài khoản? Đăng ký Proton miễn phí ↗",
            font=("Segoe UI", 8, "underline"),
            bg=self.C_BG,
            fg=self.C_ACCENT,
            cursor="hand2",
        )
        btn_signup.pack(pady=(0, 4))
        btn_signup.bind("<Button-1>", lambda e: webbrowser.open_new_tab("https://account.protonvpn.com/signup"))

        btn_about = tk.Label(
            foot_frame,
            text="ℹ️ Giới thiệu Freeton VPN",
            font=("Segoe UI", 7),
            bg=self.C_BG,
            fg=self.C_TEXT_DIM,
            cursor="hand2",
        )
        btn_about.pack()
        btn_about.bind("<Button-1>", lambda e: self._open_about_dialog())

    # --- 1B. SRP Login In-App View ---

    def _build_srp_view(self) -> None:
        self.srp_frame = tk.Frame(self.view_container, bg=self.C_BG)

        # Header with Back button & Title
        hdr = tk.Frame(self.srp_frame, bg=self.C_BG)
        hdr.pack(fill="x", pady=(0, 8))

        btn_back = RoundedPillButton(
            hdr,
            text="‹ Quay lại",
            command=self.show_login_view,
            width=76,
            height=26,
            radius=7,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_ACCENT,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT_HOVER,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 8, "bold"),
        )
        btn_back.pack(side="left")

        tk.Label(hdr, text="Đăng Nhập Proton SRP", font=("Segoe UI", 10, "bold"), bg=self.C_BG, fg=self.C_TEXT).pack(side="right")

        # Hero Card with Badge
        card_hero = RoundedCard(
            self.srp_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=14,
            padding=10,
            height=70,
        )
        card_hero.pack(fill="x", pady=(0, 10))

        tk.Label(card_hero.inner_frame, text="⚡ Mật mã Client-Side SRP", font=("Segoe UI", 9, "bold"), bg=self.C_CARD, fg=self.C_ACCENT).pack(pady=(0, 2))
        tk.Label(card_hero.inner_frame, text="Đăng nhập trực tiếp qua thư viện mật mã Proton API\nKhông mở trình duyệt • Không lưu mật khẩu trên máy", font=("Segoe UI", 8), bg=self.C_CARD, fg=self.C_TEXT_MUTED, justify="center").pack()

        # Inputs Container
        card_inputs = tk.Frame(self.srp_frame, bg=self.C_BG)
        card_inputs.pack(fill="x", pady=(0, 4))

        # Email / Username
        tk.Label(card_inputs, text="EMAIL HOẶC USERNAME PROTON", font=("Segoe UI", 7, "bold"), bg=self.C_BG, fg=self.C_TEXT_MUTED).pack(anchor="w", pady=(0, 2))
        f_user = RoundedCard(card_inputs, bg_color=self.C_BG, card_color=self.C_CARD, border_color=self.C_BORDER, hover_border=self.C_ACCENT, radius=10, padding=4, height=34)
        f_user.pack(fill="x", pady=(0, 6))
        tk.Label(f_user.inner_frame, text="✉", font=("Segoe UI", 9), bg=self.C_CARD, fg=self.C_TEXT_DIM).pack(side="left", padx=(4, 6))
        self.var_srp_user = tk.StringVar()
        self.ent_srp_user = tk.Entry(f_user.inner_frame, textvariable=self.var_srp_user, bg=self.C_CARD, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Segoe UI", 9))
        self.ent_srp_user.pack(side="left", fill="x", expand=True)

        # Password with Show/Hide Eye Toggle
        tk.Label(card_inputs, text="MẬT KHẨU PROTON", font=("Segoe UI", 7, "bold"), bg=self.C_BG, fg=self.C_TEXT_MUTED).pack(anchor="w", pady=(0, 2))
        f_pass = RoundedCard(card_inputs, bg_color=self.C_BG, card_color=self.C_CARD, border_color=self.C_BORDER, hover_border=self.C_ACCENT, radius=10, padding=4, height=34)
        f_pass.pack(fill="x", pady=(0, 6))
        tk.Label(f_pass.inner_frame, text="🔒", font=("Segoe UI", 9), bg=self.C_CARD, fg=self.C_TEXT_DIM).pack(side="left", padx=(4, 6))
        self.var_srp_pass = tk.StringVar()
        self.srp_show_pass = False
        self.ent_srp_pass = tk.Entry(f_pass.inner_frame, textvariable=self.var_srp_pass, show="●", bg=self.C_CARD, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Segoe UI", 9))
        self.ent_srp_pass.pack(side="left", fill="x", expand=True)

        self.btn_srp_eye = tk.Label(f_pass.inner_frame, text="👁", font=("Segoe UI", 9), bg=self.C_CARD, fg=self.C_TEXT_DIM, cursor="hand2")
        self.btn_srp_eye.pack(side="right", padx=(4, 2))
        self.btn_srp_eye.bind("<Button-1>", lambda e: self._toggle_srp_show_pass())

        # 2FA / recovery code.  Proton recovery codes are not always six
        # digits, so do not silently strip valid characters from this field.
        tk.Label(card_inputs, text="MÃ 2FA / RECOVERY CODE (NẾU CÓ)", font=("Segoe UI", 7, "bold"), bg=self.C_BG, fg=self.C_TEXT_MUTED).pack(anchor="w", pady=(0, 2))
        f_2fa = RoundedCard(card_inputs, bg_color=self.C_BG, card_color=self.C_CARD, border_color=self.C_BORDER, hover_border=self.C_ACCENT, radius=10, padding=4, height=34)
        f_2fa.pack(fill="x", pady=(0, 6))
        tk.Label(f_2fa.inner_frame, text="🛡", font=("Segoe UI", 8), bg=self.C_CARD, fg=self.C_TEXT_DIM).pack(side="left", padx=(4, 6))
        self.var_srp_2fa = tk.StringVar()

        self.ent_srp_2fa = tk.Entry(f_2fa.inner_frame, textvariable=self.var_srp_2fa, bg=self.C_CARD, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Segoe UI", 9))
        self.ent_srp_2fa.pack(side="left", fill="x", expand=True)

        # Status Label
        self.lbl_srp_status = tk.Label(self.srp_frame, text="", font=("Segoe UI", 8), bg=self.C_BG, fg=self.C_WARNING, wraplength=280, justify="center")
        self.lbl_srp_status.pack(fill="x", pady=(0, 6))

        # Submit Button
        self.btn_srp_submit = RoundedPillButton(
            self.srp_frame,
            text="Đăng nhập ngay ➔",
            command=self._do_srp_login,
            width=280,
            height=36,
            radius=10,
            bg_color=self.C_BG,
            btn_color=self.C_ACCENT,
            fg_color="#000000",
            hover_bg=self.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 9, "bold"),
        )
        self.btn_srp_submit.pack(fill="x", pady=(0, 6))

        # Keyboard shortcuts on inputs
        self.ent_srp_user.bind("<Return>", lambda e: self._do_srp_login())
        self.ent_srp_pass.bind("<Return>", lambda e: self._do_srp_login())
        self.ent_srp_2fa.bind("<Return>", lambda e: self._do_srp_login())

        # Footer Link
        btn_foot = tk.Label(self.srp_frame, text="‹ Trở về trang Đăng nhập chính", font=("Segoe UI", 8), bg=self.C_BG, fg=self.C_TEXT_MUTED, cursor="hand2")
        btn_foot.pack(side="bottom")
        btn_foot.bind("<Button-1>", lambda e: self.show_login_view())

    def _toggle_srp_show_pass(self) -> None:
        self.srp_show_pass = not self.srp_show_pass
        if self.srp_show_pass:
            self.ent_srp_pass.config(show="")
            self.btn_srp_eye.config(fg=self.C_ACCENT)
        else:
            self.ent_srp_pass.config(show="●")
            self.btn_srp_eye.config(fg=self.C_TEXT_DIM)

    def _do_srp_login(self) -> None:
        if getattr(self, "_is_srp_logging_in", False):
            return

        user = self.var_srp_user.get().strip()
        pwd = self.var_srp_pass.get()
        twofa = self.var_srp_2fa.get().strip()
        if not user or not pwd:
            self.lbl_srp_status.config(text="Vui lòng nhập đầy đủ Email và Mật khẩu.", fg=self.C_WARNING)
            return

        DependencyManager.ensure_runtime_path()
        self._is_srp_logging_in = True
        self.lbl_srp_status.config(text="● Đang xác thực với Proton SRP API...", fg=self.C_WARNING)
        self.btn_srp_submit.config(text="Đang xử lý...", bg=self.C_CARD_HIGH, fg=self.C_TEXT_DIM)

        def worker():
            try:
                # 1. Check if we can complete an active pending 2FA session directly without re-authenticating
                if getattr(self, "_pending_srp_session", None) and getattr(self, "_pending_srp_user", None) == user.lower() and twofa:
                    session = self._pending_srp_session
                    if not session.validate_2fa_code(twofa):
                        raise RuntimeError("Mã 2FA không hợp lệ hoặc đã hết hạn. Vui lòng nhập lại.")
                else:
                    session = create_proton_session()
                    authenticate_with_captcha(session, user, pwd, captcha_timeout=300)
                    if session.needs_twofa:
                        if not twofa:
                            self._pending_srp_session = session
                            self._pending_srp_user = user.lower()
                            raise RuntimeError("Tài khoản yêu cầu mã 2FA. Vui lòng nhập mã 2FA vào ô trên rồi bấm Đăng nhập ngay.")
                        if not session.validate_2fa_code(twofa):
                            self._pending_srp_session = session
                            self._pending_srp_user = user.lower()
                            raise RuntimeError("Mã 2FA không hợp lệ. Vui lòng kiểm tra lại.")

                self._pending_srp_session = None
                self._pending_srp_user = None
                keyring.set_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP, user)
                keyring.set_password(KEYRING_SERVICE_SRP, f"session:{user.lower()}", json.dumps(session.__getstate__()))
                self._is_srp_logging_in = False
                self.after(0, lambda: self._on_login_success(None))
            except Exception as ex:
                self._is_srp_logging_in = False
                import traceback
                tb = traceback.format_exc()
                self.after(0, lambda e=ex, t=tb: self._on_srp_error(str(e), t))

        threading.Thread(target=worker, daemon=True).start()

    def _on_srp_error(self, err: str, raw_trace: str = "") -> None:
        self._is_srp_logging_in = False
        self.btn_srp_submit.config(text="Đăng nhập ngay ➔", bg=self.C_ACCENT, fg="#000000")
        
        friendly_title = "Lỗi Xác Thực SRP"
        friendly_msg = "Xác thực mật mã Proton SRP thất bại."
        
        err_lower = err.lower()
        if "429" in err or "2028" in err or "too many requests" in err_lower:
            friendly_title = "Giới Hạn Yêu Cầu (Rate Limit 429)"
            friendly_msg = (
                "Máy chủ Proton đang tạm thời giới hạn lượt yêu cầu do có quá nhiều lần thử từ mạng/IP này trong thời gian ngắn.\n\n"
                "💡 Cách xử lý nhanh nhất:\n"
                "1. Phát 4G/5G từ điện thoại cho máy tính kết nối (đổi IP mạng mới) rồi đăng nhập lại ngay lập tức.\n"
                "2. Hoặc chờ khoảng 5 - 15 phút để máy chủ Proton tự động mở khóa giới hạn.\n"
                "3. Tránh bấm nút Đăng nhập hoặc Enter liên tục nhiều lần."
            )
        elif "captcha" in err_lower:
            friendly_msg = "Xác minh Captcha không thành công hoặc đã hết hạn. Vui lòng thử lại."
        elif "2fa" in err_lower:
            friendly_msg = err

        if self.is_debug_mode:
            self.lbl_srp_status.config(text=f"Lỗi: {err[:80]}...", fg=self.C_DANGER)
            self.show_error_dialog(
                title=friendly_title,
                friendly_msg=friendly_msg,
                detail=err,
                raw_trace=raw_trace,
            )
        else:
            self.lbl_srp_status.config(text=f"Lỗi: {err[:60]}...", fg=self.C_DANGER)
            messagebox.showerror(friendly_title, friendly_msg, parent=self)

    # --- 2. Home Dashboard View ---

    def _build_home_view(self) -> None:
        self.home_frame = tk.Frame(self.view_container, bg=self.C_BG)

        # 1. Top Protection Status Card (Height 110px prevents any text cutoff)
        self.card_toggle = RoundedCard(
            self.home_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=14,
            padding=12,
            height=110,
        )
        self.card_toggle.pack(fill="x", pady=(4, 6))

        lbl_hero_tag = tk.Label(
            self.card_toggle.inner_frame,
            text="KẾT NỐI CỦA BẠN",
            font=("Segoe UI", 8, "bold"),
            bg=self.C_CARD,
            fg=self.C_TEXT_DIM,
        )
        lbl_hero_tag.pack(anchor="w")

        # Center Status Title
        self.lbl_toggle_status = tk.Label(
            self.card_toggle.inner_frame,
            text="CHƯA BẬT VPN",
            font=("Segoe UI", 15, "bold"),
            bg=self.C_CARD,
            fg=self.C_TEXT,
        )
        self.lbl_toggle_status.pack(anchor="w", pady=(2, 0))

        # Subtitle / IP Details (wraplength ensures 2-line detail fits perfectly)
        self.lbl_toggle_sub = tk.Label(
            self.card_toggle.inner_frame,
            text="Bấm công tắc để kích hoạt kết nối an toàn WireGuard",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT_MUTED,
            justify="left",
            wraplength=310,
        )
        self.lbl_toggle_sub.pack(anchor="w", pady=(2, 0))

        # 2. Central Giant iOS Pill Switch Area
        self.switch_hero_box = tk.Frame(self.home_frame, bg=self.C_BG)
        self.switch_hero_box.pack(fill="both", expand=True, pady=(2, 6))

        # Live Session Duration Pill Badge right above the toggle switch
        self.hero_timer_pill = RoundedPillButton(
            self.switch_hero_box,
            text="Sẵn sàng khi bạn cần",
            width=190,
            height=30,
            radius=10,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_DIM,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD,
            hover_fg=self.C_TEXT_DIM,
            hover_border=self.C_BORDER,
            font=("Segoe UI", 9, "bold"),
            auto_width=True,
            min_width=175,
            padding_x=14,
            cursor="",
        )
        self.hero_timer_pill.pack(side="top", pady=(8, 2))
        self.lbl_hero_timer = self.hero_timer_pill

        self.ios_toggle = IOSToggleSwitch(
            self.switch_hero_box,
            width=136,
            height=70,
            command=self._on_toggle_clicked,
            bg_color=self.C_BG,
            cursor="hand2",
        )
        self.ios_toggle.pack(expand=True, pady=(2, 6))

        tk.Label(
            self.switch_hero_box, text="WIREGUARD  /  KẾT NỐI MÃ HÓA",
            font=("Segoe UI", 8), bg=self.C_BG, fg=self.C_TEXT_DIM,
        ).pack(side="bottom", pady=(0, 14))

        # 3. Selected Server / Location Card (Rounded Corners with Hover Glow)
        self.card_server = RoundedCard(
            self.home_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            hover_border=self.C_ACCENT,
            radius=14,
            padding=11,
            cursor="hand2",
            height=102,
        )
        self.card_server.pack(fill="x", pady=(0, 10))
        self.card_server.bind("<Button-1>", lambda e: self.show_drawer_view())
        self.card_server.inner_frame.bind("<Button-1>", lambda e: self.show_drawer_view())

        row_top = tk.Frame(self.card_server.inner_frame, bg=self.C_CARD)
        row_top.pack(fill="x")
        row_top.bind("<Button-1>", lambda e: self.show_drawer_view())

        lbl_vmc = tk.Label(row_top, text="VỊ TRÍ MÁY CHỦ", font=("Segoe UI", 7, "bold"), bg=self.C_CARD, fg=self.C_TEXT_DIM)
        lbl_vmc.pack(side="left")
        lbl_vmc.bind("<Button-1>", lambda e: self.show_drawer_view())

        self.lbl_change = tk.Label(row_top, text="Đổi vị trí ❯", font=("Segoe UI", 8, "bold"), bg=self.C_CARD, fg=self.C_ACCENT, cursor="hand2")
        self.lbl_change.pack(side="right")
        self.lbl_change.bind("<Button-1>", lambda e: self.show_drawer_view())

        self.lbl_server_name = tk.Label(
            self.card_server.inner_frame,
            text="Đang tìm node tốt nhất...",
            font=("Segoe UI", 11, "bold"),
            bg=self.C_CARD,
            fg=self.C_TEXT,
            cursor="hand2",
        )
        self.lbl_server_name.pack(anchor="w", pady=(3, 5))
        self.lbl_server_name.bind("<Button-1>", lambda e: self.show_drawer_view())

        self.row_meta = tk.Frame(self.card_server.inner_frame, bg=self.C_CARD)
        self.row_meta.pack(fill="x")
        self.row_meta.bind("<Button-1>", lambda e: self.show_drawer_view())

        self.lbl_server_ping = RoundedPillButton(
            self.row_meta,
            text="Ping: -- ms",
            command=lambda: self.show_drawer_view(),
            width=90,
            height=26,
            radius=7,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_SUCCESS,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_SUCCESS,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 8, "bold"),
            auto_width=True,
            min_width=80,
            padding_x=10,
        )
        self.lbl_server_ping.pack(side="left", padx=(0, 6))

        self.lbl_server_load = RoundedPillButton(
            self.row_meta,
            text="Tải: --%",
            command=lambda: self.show_drawer_view(),
            width=70,
            height=26,
            radius=7,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_TEXT_MUTED,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 8),
            auto_width=True,
            min_width=65,
            padding_x=10,
        )
        self.lbl_server_load.pack(side="left")

        # 4. Bottom Action Chips (Windows 11 Rounded Pill Buttons)
        self.action_box = tk.Frame(self.home_frame, bg=self.C_BG)
        self.action_box.pack(side="bottom", fill="x", pady=(0, 2))

        self.btn_export_conf = RoundedPillButton(
            self.action_box,
            text="💾 Xuất .conf",
            command=self._export_selected_conf,
            width=80,
            height=34,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_border=self.C_ACCENT,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 9, "bold"),
        )

        self.btn_settings = RoundedPillButton(
            self.action_box,
            text="Cài đặt",
            command=self._open_wg_settings,
            width=76,
            height=34,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_border=self.C_ACCENT,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 9, "bold"),
        )
        self.btn_settings.pack(side="left", expand=True, fill="x", padx=(0, 4))

        self.btn_about = RoundedPillButton(
            self.action_box,
            text="Giới thiệu",
            command=self._open_about_dialog,
            width=78,
            height=34,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_border=self.C_ACCENT,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 9, "bold"),
        )
        self.btn_about.pack(side="left", expand=True, fill="x", padx=(0, 4))

        self.btn_login_act = RoundedPillButton(
            self.action_box,
            text="Đăng xuất",
            command=self._logout,
            width=80,
            height=34,
            radius=8,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_border=self.C_DANGER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_DANGER,
            font=("Segoe UI", 9, "bold"),
        )
        self.btn_login_act.pack(side="left", expand=True, fill="x")

        self._update_debug_mode_ui()

    # --- 3. Drawer / Server Picker View ---

    def _build_drawer_view(self) -> None:
        self.drawer_frame = tk.Frame(self.view_container, bg=self.C_BG)

        # Header with Back & Title
        hdr = tk.Frame(self.drawer_frame, bg=self.C_BG)
        hdr.pack(fill="x", pady=(0, 6))

        btn_back = RoundedPillButton(
            hdr,
            text="‹ Quay lại",
            command=self.show_home_view,
            width=76,
            height=26,
            radius=7,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_ACCENT,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_ACCENT_HOVER,
            hover_border=self.C_ACCENT,
            font=("Segoe UI", 8, "bold"),
        )
        btn_back.pack(side="left")

        tk.Label(hdr, text="Danh Sách Máy Chủ", font=("Segoe UI", 10, "bold"), bg=self.C_BG, fg=self.C_TEXT).pack(side="right")

        # 1. Search Bar (Rounded Card)
        search_box = RoundedCard(
            self.drawer_frame,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            hover_border=self.C_ACCENT,
            radius=12,
            padding=4,
            height=36,
        )
        search_box.pack(fill="x", pady=(0, 6))

        tk.Label(search_box.inner_frame, text="🔍", bg=self.C_CARD, fg=self.C_TEXT_DIM, font=("Segoe UI", 8)).pack(side="left", padx=(6, 2))
        self.var_search = tk.StringVar()
        self.var_search.trace_add("write", lambda *args: self._on_search_changed())

        entry_s = tk.Entry(
            search_box.inner_frame,
            textvariable=self.var_search,
            bg=self.C_CARD,
            fg=self.C_TEXT,
            insertbackground=self.C_ACCENT,
            relief="flat",
            font=("Segoe UI", 9),
        )
        entry_s.pack(side="left", fill="x", expand=True, padx=4, pady=2)

        # 2. Country Dropdown Menu Row
        country_row = tk.Frame(self.drawer_frame, bg=self.C_BG)
        country_row.pack(fill="x", pady=(0, 6))

        tk.Label(country_row, text="Quốc gia:", font=("Segoe UI", 8, "bold"), bg=self.C_BG, fg=self.C_TEXT_MUTED).pack(side="left", padx=(0, 6))

        self.cb_country_var = tk.StringVar()
        self.cb_country = ttk.Combobox(
            country_row,
            textvariable=self.cb_country_var,
            style="Dark.TCombobox",
            state="readonly",
            font=("Segoe UI", 8),
        )
        self.cb_country.pack(side="left", fill="x", expand=True)
        self.cb_country.bind("<<ComboboxSelected>>", self._on_combobox_country_selected)

        # 3. Quick Popular Country Filter Pills (Rounded Pills)
        self.quick_pills_frame = tk.Frame(self.drawer_frame, bg=self.C_BG)
        self.quick_pills_frame.pack(fill="x", pady=(0, 5))

        # 4. Sort Bar (Tối ưu nhất, Ping thấp nhất, Tải nhẹ nhất, A-Z)
        sort_box = tk.Frame(self.drawer_frame, bg=self.C_BG)
        sort_box.pack(fill="x", pady=(0, 6))

        tk.Label(sort_box, text="Sắp xếp:", font=("Segoe UI", 7, "bold"), bg=self.C_BG, fg=self.C_TEXT_DIM).pack(side="left", padx=(0, 4))

        sort_options = [
            ("🚀 Tối ưu", "best"),
            ("⚡ Ping", "ping"),
            ("📊 Tải", "load"),
            ("🔤 A-Z", "name"),
        ]

        self.sort_chips: dict[str, RoundedPillButton] = {}
        for text, mode in sort_options:
            is_best = (mode == "best")
            lbl_s = RoundedPillButton(
                sort_box,
                text=text,
                command=lambda m=mode: self._on_sort_selected(m),
                width=60,
                height=22,
                radius=6,
                bg_color=self.C_BG,
                btn_color=self.C_ACCENT if is_best else self.C_CARD,
                fg_color="#000000" if is_best else self.C_TEXT_MUTED,
                border_color=self.C_ACCENT if is_best else self.C_BORDER,
                hover_bg=self.C_ACCENT_HOVER if is_best else self.C_CARD_HIGH,
                hover_fg="#000000" if is_best else self.C_TEXT,
                font=("Segoe UI", 7, "bold"),
            )
            lbl_s.pack(side="left", padx=(0, 3))
            self.sort_chips[mode] = lbl_s

        # 5. Scrollable Server List (with universal MouseWheel binding)
        list_container = tk.Frame(self.drawer_frame, bg=self.C_BG)
        list_container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(list_container, bg=self.C_BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(list_container, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.C_BG)

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_frame_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self._on_server_scroll)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_frame_id, width=e.width))

        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.scrollable_frame.bind("<MouseWheel>", self._on_mousewheel)

    def _on_server_scroll(self, first: str, last: str) -> None:
        self.scrollbar.set(first, last)
        if hasattr(self, "server_rows"):
            self.server_rows.render_visible()

    def _cancel_scroll_animation(self) -> None:
        job = getattr(self, "_scroll_job", None)
        if job:
            self.after_cancel(job)
        self._scroll_job = None
        self._scroll_target = None

    def _on_mousewheel(self, event: Any) -> None:
        if not self.canvas.winfo_ismapped():
            return
        if not self.wg_config.get("animations_enabled", True):
            self._cancel_scroll_animation()
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
            return
        bounds = self.canvas.bbox("all")
        if not bounds:
            return
        height = max(1, bounds[3] - bounds[1])
        start, end = self.canvas.yview()
        target = getattr(self, "_scroll_target", None)
        target = start if target is None else target
        target = max(0.0, min(max(0.0, 1 - (end - start)), target - event.delta / 120 * 72 / height))
        self._cancel_scroll_animation()
        self._scroll_target = target
        started = time.perf_counter()

        def step():
            self._scroll_job = None
            progress = min(1.0, (time.perf_counter() - started) / 0.14)
            if not self.wg_config.get("animations_enabled", True):
                progress = 1.0
            self.canvas.yview_moveto(start + (target - start) * (1 - (1 - progress) ** 3))
            if progress < 1:
                self._scroll_job = self.after(16, step)
            else:
                self._scroll_target = None

        step()

    def _bind_mousewheel_recursive(self, widget: tk.Widget) -> None:
        widget.bind("<MouseWheel>", self._on_mousewheel, add="+")
        for child in widget.winfo_children():
            self._bind_mousewheel_recursive(child)

    def _on_search_changed(self) -> None:
        job = getattr(self, "_search_job", None)
        if job:
            self.after_cancel(job)
        self._search_job = self.after(120, self._apply_search)

    def _apply_search(self) -> None:
        self._search_job = None
        self._render_server_list()
        self._server_list_dirty = False

    def _on_sort_selected(self, mode: str) -> None:
        self.sort_mode.set(mode)
        for m, btn in self.sort_chips.items():
            if m == mode:
                btn.config(btn_color=self.C_ACCENT, fg_color="#000000", border_color=self.C_ACCENT, hover_bg=self.C_ACCENT_HOVER, hover_fg="#000000")
            else:
                btn.config(btn_color=self.C_CARD, fg_color=self.C_TEXT_MUTED, border_color=self.C_BORDER, hover_bg=self.C_CARD_HIGH, hover_fg=self.C_TEXT)
        self._server_list_dirty = True
        self._render_server_list()
        self._server_list_dirty = False

    def _render_country_dropdown_and_quick_pills(self) -> None:
        country_counts: dict[str, int] = {}
        for s in self.all_free_servers:
            c = s.get("country")
            if c:
                country_counts[c] = country_counts.get(c, 0) + 1

        sorted_codes = sorted(country_counts.keys(), key=lambda c: (-country_counts[c], get_country_display(c)))

        self.country_options_map = {}
        total_label = f"Tất cả quốc gia ({len(self.all_free_servers)} máy chủ)"
        self.country_options_map[total_label] = None
        dropdown_labels = [total_label]

        for c in sorted_codes:
            d_name = get_country_display(c)
            label = f"{d_name} ({country_counts[c]} máy chủ)"
            self.country_options_map[label] = c
            dropdown_labels.append(label)

        self.cb_country.config(values=dropdown_labels)

        current_code = self.selected_country_code
        found_idx = 0
        for idx, (label, code) in enumerate(self.country_options_map.items()):
            if code == current_code:
                found_idx = idx
                break
        if dropdown_labels:
            self.cb_country.current(found_idx)

        for w in self.quick_pills_frame.winfo_children():
            w.destroy()

        popular_quick = [("Tất cả", None), ("Singapore", "SG"), ("Nhật Bản", "JP"), ("Hoa Kỳ", "US"), ("Hà Lan", "NL")]
        for label, code in popular_quick:
            is_active = (self.selected_country_code == code)
            btn_c = self.C_ACCENT if is_active else self.C_CARD
            fg_c = "#000000" if is_active else self.C_TEXT_MUTED
            b_col = self.C_ACCENT if is_active else self.C_BORDER

            chip = RoundedPillButton(
                self.quick_pills_frame,
                text=label,
                command=lambda c=code: self._select_country(c),
                width=64 if len(label) <= 7 else 76,
                height=24,
                radius=8,
                bg_color=self.C_BG,
                btn_color=btn_c,
                fg_color=fg_c,
                border_color=b_col,
                hover_bg=self.C_ACCENT_HOVER if is_active else self.C_CARD_HIGH,
                hover_fg="#000000" if is_active else self.C_ACCENT,
                font=("Segoe UI", 7, "bold"),
            )
            chip.pack(side="left", padx=(0, 4))

    def _on_combobox_country_selected(self, event: Any) -> None:
        selected_label = self.cb_country_var.get()
        code = self.country_options_map.get(selected_label)
        self._select_country(code)

    def _select_country(self, code: str | None) -> None:
        self.selected_country_code = code
        self._render_country_dropdown_and_quick_pills()
        self._render_server_list()
        self._server_list_dirty = False

    def _render_server_list(self) -> None:
        self._cancel_scroll_animation()
        self.canvas.yview_moveto(0)
        query = self.var_search.get().strip().lower()
        filtered = [s for s in self.all_free_servers
                    if (not self.selected_country_code or s.get("country") == self.selected_country_code)
                    and (not query or any(query in str(value).lower() for value in (
                        s.get("name", ""), s.get("city", ""), s.get("domain", ""),
                        get_country_display(s.get("country", "")))))]

        def score(server):
            ping = server.get("pingMs")
            load = server.get("load")
            return (ping if ping is not None else 9999) * .7 + (load if load is not None else 50) * .8

        mode = self.sort_mode.get()
        if mode == "ping":
            filtered.sort(key=lambda s: (s.get("pingMs") if s.get("pingMs") is not None else 9999, s.get("load") or 0))
        elif mode == "load":
            filtered.sort(key=lambda s: (s.get("load") or 0, s.get("pingMs") if s.get("pingMs") is not None else 9999))
        elif mode == "name":
            filtered.sort(key=lambda s: s.get("name", ""))
        else:
            filtered.sort(key=score)
        best = min(filtered, key=score) if filtered else None
        if not hasattr(self, "server_rows"):
            self.server_rows = VirtualServerRows(self.scrollable_frame, self)
            self.server_rows.pack(fill="x")
            self._bind_mousewheel_recursive(self.server_rows)
        self.server_rows.set_servers(filtered, best)

    def _select_and_connect_server(self, server: dict[str, Any]) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        self.selected_server = server
        self._server_selection_manual = True
        self._update_home_server_card()
        self.show_home_view()
        self._connect_to_server(server)

    def _update_home_server_card(self) -> None:
        if not self.selected_server:
            self.lbl_server_name.config(text="Chưa chọn máy chủ")
            self.lbl_server_ping.config(text="Ping: -- ms")
            self.lbl_server_load.config(text="Tải: --%")
            return

        c_display = get_country_display(self.selected_server.get("country", ""))
        self.lbl_server_name.config(text=f"{c_display} ({self.selected_server.get('name')})")

        ping_val = self.selected_server.get("pingMs")
        ping_str = f"Ping: {ping_val:g} ms" if ping_val is not None else "Ping: -- ms"
        self.lbl_server_ping.config(text=ping_str)
        self.lbl_server_load.config(text=f"Tải: {self.selected_server.get('load', 0)}%")

    # --- System Tray Integration ---

    def _setup_tray_icon(self) -> None:
        def on_open(icon, item):
            self.after(0, self.show_window)

        def on_toggle_tray(icon, item):
            self.after(0, self._on_toggle_clicked)

        def on_settings(icon, item):
            self.after(0, self._open_wg_settings)

        def on_about(icon, item):
            self.after(0, self._open_about_dialog)

        def on_exit(icon, item):
            self.after(0, self.quit_app)

        menu = pystray.Menu(
            pystray.MenuItem(f"Mở {APP_NAME}", on_open, default=True),
            pystray.MenuItem("⚡ Bật/Tắt VPN", on_toggle_tray),
            pystray.MenuItem("⚙️ Cài đặt", on_settings),
            pystray.MenuItem("ℹ️ Giới thiệu", on_about),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("❌ Thoát", on_exit),
        )

        self.tray_icon = pystray.Icon(
            "FreetonVPN",
            create_tray_image(connected=False),
            f"{APP_NAME} - {APP_SUBTITLE}",
            menu,
        )

        def run_tray():
            self.tray_icon.run()

        threading.Thread(target=run_tray, daemon=True).start()

    def update_tray_icon_status(self, connected: bool = False, connecting: bool = False) -> None:
        state = (connected, connecting)
        if self._tray_status == state:
            return
        try:
            self.tray_icon.icon = create_tray_image(connected=connected, connecting=connecting)
            self._tray_status = state
        except Exception:
            pass

    def register_modal(self, modal_window: Any) -> None:
        """Register open dialog so focus-out auto-hide does not trigger."""
        self._active_modals.add(modal_window)
        modal_window.bind("<Destroy>", lambda e: self.unregister_modal(modal_window), add="+")

    def unregister_modal(self, modal_window: Any) -> None:
        self._active_modals.discard(modal_window)

    def _on_focus_out(self, event: Any = None) -> None:
        # Proton browser login, file dialogs and UAC prompts all move focus
        # away temporarily.  Automatically hiding here made the app look as if
        # it crashed during login, so minimising is now explicit via ×/tray.
        return

    def _check_focus_and_auto_hide(self) -> None:
        if not self.winfo_viewable():
            return
        if self._active_modals or self._drag_data.get("dragging", False):
            return
        try:
            # If focus is None (user clicked another app/desktop)
            if self.focus_get() is None:
                self.hide_to_tray(animate=True)
        except Exception:
            pass

    def toggle_window_visibility(self) -> None:
        if self.winfo_viewable() and self.attributes("-alpha") > 0.3:
            self.hide_to_tray(animate=True)
        else:
            self.show_window()

    def show_window(self) -> None:
        if self.winfo_viewable() and self.attributes("-alpha") > 0.8:
            self.lift()
            self.focus_force()
            return

        if not getattr(self, "_user_has_custom_dragged", False):
            self._position_at_system_tray()

        self.attributes("-alpha", 0.0)
        self.deiconify()
        self.attributes("-topmost", False)
        self.lift()
        self.focus_force()

        if self.wg_config.get("animations_enabled", True):
            alphas = [0.2, 0.5, 0.8, 0.95, 1.0]
            def fade_in(i=0):
                if not self.winfo_exists():
                    return
                if i < len(alphas):
                    self.attributes("-alpha", alphas[i])
                    self.after(14, lambda: fade_in(i + 1))
                else:
                    self.attributes("-alpha", 1.0)
            fade_in(0)
        else:
            self.attributes("-alpha", 1.0)

    def hide_to_tray(self, animate: bool = True) -> None:
        if not self.winfo_viewable():
            return
        if animate and self.wg_config.get("animations_enabled", True):
            alphas = [0.75, 0.45, 0.15, 0.0]
            def fade_out(i=0):
                if not self.winfo_exists():
                    return
                if i < len(alphas):
                    self.attributes("-alpha", alphas[i])
                    self.after(12, lambda: fade_out(i + 1))
                else:
                    self.withdraw()
                    self.attributes("-alpha", 1.0)
            fade_out(0)
        else:
            self.withdraw()

    def quit_app(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._connection_generation += 1
        self.lbl_toggle_status.config(text="ĐANG THOÁT...")

        def worker():
            try:
                # The manager lock lets an in-flight install finish before removal.
                WireGuardManager.disconnect_tunnel(DEFAULT_TUNNEL_NAME)
                self.after(0, finish)
            except Exception as error:
                self.after(0, lambda e=str(error): failed(e))

        def finish():
            self.anim_running = False
            self.tray_icon.stop()
            self.destroy()

        def failed(error):
            self._closing = False
            self.is_connecting_vpn = False
            self._refresh_wireguard_status()
            self.show_error_dialog("Không thể ngắt VPN để thoát", "Hãy thử ngắt VPN rồi thoát lại.", detail=error)

        threading.Thread(target=worker, daemon=True).start()


    # --- Window Drag Support ---

    def _start_drag(self, event: Any) -> None:
        self._drag_data["dragging"] = True
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y

    def _on_drag(self, event: Any) -> None:
        self._user_has_custom_dragged = True
        dx = event.x - self._drag_data["x"]
        dy = event.y - self._drag_data["y"]
        x = self.winfo_x() + dx
        y = self.winfo_y() + dy
        self.geometry(f"+{x}+{y}")

    def _stop_drag(self, event: Any = None) -> None:
        self.after(200, lambda: self._drag_data.update({"dragging": False}))

    # --- Animation Loop (Breathing Glow & Live Session Timer) ---

    def _start_animation_loop(self) -> None:
        def tick():
            if self.anim_running:
                if self.current_view == "main" and self.winfo_viewable():
                    # Stable status colors; movement is reserved for interactions.
                    color = (self.C_WARNING if self.is_connecting_vpn or
                             (self._tunnel_running and not self._tunnel_verified)
                             else self.C_SUCCESS if self._tunnel_verified else None)
                    self.card_toggle.set_border_color(color)

                # Update live session timer if viewing main home screen
                if self.current_view == "main":
                    self._update_session_timer()

            self.after(1000, tick)

        self.after(1000, tick)

    def _update_session_timer(self) -> None:
        if not hasattr(self, "hero_timer_pill") or not self.winfo_exists():
            return
        if self.is_connecting_vpn:
            text, color = "Đang thiết lập kết nối…", self.C_WARNING
        elif self.vpn_connect_time is not None and self._tunnel_verified:
            elapsed = max(0, int(time.time() - self.vpn_connect_time))
            hours, rem = divmod(elapsed, 3600)
            minutes, seconds = divmod(rem, 60)
            time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            text, color = f"Thời gian kết nối  {time_str}", self.C_SUCCESS
        elif self._tunnel_running:
            text, color = "Đang kiểm tra đường truyền…", self.C_WARNING
        else:
            text, color = "Sẵn sàng khi bạn cần", self.C_TEXT_DIM
        if self._last_timer_text != (text, color):
            self._last_timer_text = (text, color)
            self.hero_timer_pill.config(text=text, fg=color, border_color=color)

    # --- WireGuard Connection Toggle Logic ---

    def _on_toggle_clicked(self) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        if self._tunnel_running:
            self._disconnect_vpn()
            return
        if not self._check_login_status():
            self.show_login_view()
            return

        if not self.selected_server and self.all_free_servers:
            self._pick_best_server_as_selected()
        if self.selected_server:
            self._connect_to_server(self.selected_server)
        else:
            self.start_scan()

    def _check_wireguard_status(self) -> None:
        # Rendering only: service/IPC reads belong to the background status worker.
        running = self._tunnel_running and self._tunnel_verified
        if running:
            if self.vpn_connect_time is None:
                self.vpn_connect_time = time.time()
            country = get_country_display(self.connected_server.get("country", "")) if self.connected_server else ""
            entry_ip = self.connected_server.get("entryIP", "") if self.connected_server else ""
            port = self.wg_config.get("port", str(DEFAULT_WG_PORT))
            addr = self.wg_config.get("address", DEFAULT_WG_ADDRESS)
            public_ip = getattr(self, "live_public_ip", None)

            self.card_toggle.set_border_color(self.C_SUCCESS)
            self.ios_toggle.set_state(True, connecting=False, animate=False)
            self.lbl_toggle_status.config(text="ĐÃ KẾT NỐI", fg=self.C_SUCCESS)

            if public_ip:
                self.lbl_toggle_sub.config(
                    text=f"IP Public (Exit): {public_ip} ({country})\nEndpoint: {entry_ip}:{port} • IP Nội bộ: {addr}",
                    fg=self.C_TEXT,
                )
            else:
                self.lbl_toggle_sub.config(
                    text=f"Đang mã hóa qua {country} • Endpoint: {entry_ip}:{port}\nIP Nội bộ WireGuard: {addr}",
                    fg=self.C_TEXT,
                )
            self.update_tray_icon_status(connected=True)
        elif self._tunnel_running:
            self.card_toggle.set_border_color(self.C_WARNING)
            self.ios_toggle.set_state(True, connecting=False, animate=False)
            self.lbl_toggle_status.config(text="VPN CHƯA XÁC MINH", fg=self.C_WARNING)
            self.lbl_toggle_sub.config(text="Tunnel đang bật nhưng chưa xác minh handshake/DNS.\nBấm công tắc để ngắt hoặc thử máy chủ khác.", fg=self.C_WARNING)
            self.update_tray_icon_status(connecting=True)
        else:
            self.connected_server = None
            self.vpn_connect_time = None
            self.live_public_ip = None
            self.card_toggle.set_border_color(None)
            self.ios_toggle.set_state(False, connecting=False, animate=False)
            self.lbl_toggle_status.config(text="CHƯA BẬT VPN", fg=self.C_TEXT)
            self.lbl_toggle_sub.config(text="Bấm công tắc để kích hoạt kết nối an toàn WireGuard", fg=self.C_TEXT_MUTED)
            self.update_tray_icon_status(connected=False)
        self._update_session_timer()

    def _periodic_vpn_status_check(self) -> None:
        self._refresh_wireguard_status()
        self.after(3500, self._periodic_vpn_status_check)

    def _refresh_wireguard_status(self) -> None:
        if self.is_connecting_vpn or self._status_check_pending or self._closing:
            return
        self._status_check_pending = True
        generation = self._connection_generation
        server = dict(self.connected_server or {})
        config = dict(self.wg_config)

        def worker():
            running, verified = self._tunnel_running, False
            try:
                running = WireGuardManager.is_tunnel_running(DEFAULT_TUNNEL_NAME)
                if running:
                    cli = find_wg_cli(WireGuardManager.find_wireguard_exe())
                    stamp = latest_handshake(cli, DEFAULT_TUNNEL_NAME, server.get("x25519PublicKey"))
                    verified = stamp > 0 and 0 <= time.time() - stamp <= 180
                    if verified and not self._tunnel_verified:
                        verified = dns_responds_through_tunnel(
                            config.get("address") or DEFAULT_WG_ADDRESS,
                            config.get("dns") or DEFAULT_WG_DNS,
                        )
            except Exception:
                verified = False
            self.after(0, lambda: apply_status(running, verified))

        def apply_status(running, verified):
            self._status_check_pending = False
            if generation != self._connection_generation or self.is_connecting_vpn or self._closing:
                return
            self._tunnel_running, self._tunnel_verified = running, verified
            self._check_wireguard_status()

        threading.Thread(target=worker, daemon=True).start()

    def _resolve_live_public_ip(self) -> None:
        generation = self._connection_generation
        def apply_ip(pub_ip):
            if generation == self._connection_generation and self._tunnel_verified and not self._closing:
                self.live_public_ip = pub_ip
                self._check_wireguard_status()

        def worker():
            try:
                req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "curl/7.68.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    pub_ip = data.get("ip")
                    if pub_ip:
                        self.after(0, lambda: apply_ip(pub_ip))
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _connect_to_server(self, server: dict[str, Any]) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        if self._tunnel_verified and self.connected_server == server:
            return
        DependencyManager.ensure_runtime_path()
        if not DependencyManager.find_wireguard_exe():
            self.is_connecting_vpn = False
            self.ios_toggle.set_state(False, connecting=False, animate=False)
            self._check_wireguard_status()
            if messagebox.askyesno(
                "Thiếu WireGuard for Windows",
                "Máy tính của bạn chưa cài đặt WireGuard for Windows để tạo card mạng ảo TUN.\n\n"
                "Bạn có muốn mở Trình Tự Động Tải & Cài Đặt (1-Click) ngay bây giờ không?",
                parent=self,
            ):
                self._open_dependency_dialog()
            return

        self.is_connecting_vpn = True
        self._connection_generation += 1
        self.live_public_ip = None
        self._tunnel_verified = False
        server = dict(server)
        
        # Step 0: Immediate Knob Slide & UI Feedback!
        self.card_toggle.set_border_color(self.C_WARNING)
        self.ios_toggle.set_state(True, connecting=True, animate=True)
        self.lbl_toggle_status.config(text="ĐANG THIẾT LẬP KẾT NỐI...", fg=self.C_WARNING)
        
        entry_ip = server.get("entryIP") or server.get("pingTarget") or server.get("domain") or ""
        port = self.wg_config.get("port", str(DEFAULT_WG_PORT))
        addr = self.wg_config.get("address", DEFAULT_WG_ADDRESS)
        dns = self.wg_config.get("dns", DEFAULT_WG_DNS)
        pubkey = server.get("x25519PublicKey") or ""
        pubkey_short = (pubkey[:10] + "..." + pubkey[-6:]) if len(pubkey) > 16 else pubkey

        self.lbl_toggle_sub.config(
            text=f"Server: {server.get('name')} • Endpoint: {entry_ip}:{port}\nInterface: {addr} • DNS: {dns}",
            fg=self.C_TEXT,
        )
        self.update_tray_icon_status(connecting=True)

        self._show_loading_status(f"● [1/4] 🔑 Kiểm tra WireGuard Key & Chứng chỉ...")
        self.progress_bar.config(mode="determinate", maximum=100, value=25)

        def connect_worker():
            try:
                # Step 1: WireGuard Key validation / generation
                if not WireGuardManager.has_usable_key(self.wg_config):
                    self.after(0, lambda: self._show_loading_status("● [1/4] 🔑 Đang cấp & kích hoạt WireGuard Key mới từ Proton API..."))
                    self.wg_config = WireGuardManager.auto_fetch_and_register_key()

                self.after(0, lambda: self.progress_bar.config(value=45))

                # Step 2: Configuration generation
                self.after(0, lambda: self._show_loading_status(f"● [2/4] 📝 Cấu hình Tunnel: {entry_ip}:{port} • Peer: {pubkey_short}"))
                self.after(0, lambda: self.progress_bar.config(value=65))

                # Step 3: Service install & handshake initiation
                self.after(0, lambda: self._show_loading_status(f"● [3/4] ⚡ Đang xác minh handshake & DNS qua {entry_ip}..."))
                self.after(0, lambda: self.progress_bar.config(value=85))

                with WireGuardManager._tunnel_lock:
                    if self._closing:
                        return
                    WireGuardManager.connect_tunnel(server, dict(self.wg_config), DEFAULT_TUNNEL_NAME)

                self.after(0, lambda: self._on_connect_success(server))
            except Exception as ex:
                import traceback
                tb = traceback.format_exc()
                self.after(0, lambda e=ex, t=tb: self._on_connect_failed(str(e), t))

        threading.Thread(target=connect_worker, daemon=True).start()

    def _on_connect_success(self, server: dict[str, Any]) -> None:
        if self._closing:
            return
        self.is_connecting_vpn = False
        self._tunnel_running = self._tunnel_verified = True
        self.connected_server = server
        self.vpn_connect_time = time.time()
        self.ios_toggle.set_state(True, connecting=False, animate=False)
        self._check_wireguard_status()
        self._hide_loading_with_delay(f"● [4/4] 🛡 Kết nối {server.get('name')} thành công!")
        self._resolve_live_public_ip()

    def _on_connect_failed(self, error_msg: str, raw_trace: str = "") -> None:
        if self._closing:
            return
        self.is_connecting_vpn = False
        self._tunnel_verified = False
        self.connected_server = None
        self.vpn_connect_time = None
        self.ios_toggle.set_state(False, connecting=False, animate=True)
        self._check_wireguard_status()
        self._refresh_wireguard_status()
        self._hide_loading_with_delay(f"Lỗi: {error_msg}")
        self.show_error_dialog(
            title="Lỗi Kết Nối WireGuard",
            friendly_msg=f"Chưa xác minh được đường truyền VPN.\n\n{error_msg}",
            detail=error_msg,
            raw_trace=raw_trace,
        )

    def _disconnect_vpn(self) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        self.is_connecting_vpn = True
        self._connection_generation += 1
        self.lbl_toggle_status.config(text="ĐANG NGẮT KẾT NỐI...")
        self.ios_toggle.set_state(False, connecting=True, animate=True)
        self._show_loading_status("● Đang ngắt WireGuard Tunnel & hoàn trả cấu hình mạng...")
        self.update_tray_icon_status(connecting=True)

        def dc_worker():
            try:
                WireGuardManager.disconnect_tunnel(DEFAULT_TUNNEL_NAME)
                self.after(0, self._on_disconnect_success)
            except Exception as error:
                self.after(0, lambda e=str(error): self._on_disconnect_failed(e))

        threading.Thread(target=dc_worker, daemon=True).start()

    def _on_disconnect_success(self) -> None:
        if self._closing:
            return
        self.is_connecting_vpn = False
        self._tunnel_running = self._tunnel_verified = False
        self.connected_server = None
        self.vpn_connect_time = None
        self.ios_toggle.set_state(False, connecting=False, animate=True)
        self._check_wireguard_status()
        self._hide_loading_with_delay("● Đã ngắt kết nối an toàn.")
        if getattr(self, "_logout_after_disconnect", False):
            self._logout_after_disconnect = False
            self._logout()

    def _on_disconnect_failed(self, error: str) -> None:
        if self._closing:
            return
        self.is_connecting_vpn = False
        self._logout_after_disconnect = False
        self._check_wireguard_status()
        self._refresh_wireguard_status()
        self._hide_loading_with_delay("● Chưa ngắt được VPN.")
        self.show_error_dialog("Lỗi ngắt VPN", "Tunnel có thể vẫn đang bật. Vui lòng thử ngắt lại.", detail=error)


    # --- Scanning & Smart Auto-Hiding Loading Progress ---

    def _show_loading_status(self, text: str) -> None:
        if self._loading_hide_job is not None:
            self.after_cancel(self._loading_hide_job)
            self._loading_hide_job = None
        self.loading_frame.pack(fill="x", padx=14, pady=(2, 6), before=self.view_container)
        self.lbl_loading_detail.config(text=text)

    def _hide_loading_with_delay(self, final_text: str = "● Hoàn tất!") -> None:
        if self._loading_hide_job is not None:
            self.after_cancel(self._loading_hide_job)
        self.lbl_loading_detail.config(text=final_text)
        self.progress_bar.config(mode="determinate", maximum=100, value=100)
        def hide():
            self._loading_hide_job = None
            self.loading_frame.pack_forget()
        self._loading_hide_job = self.after(1400, hide)

    def _show_scan_status(self, text: str) -> None:
        if not self.is_connecting_vpn and not self._closing:
            self._show_loading_status(text)

    def _auto_start_scan_and_key(self) -> None:
        if self._check_login_status():
            self.start_scan()
            self._ensure_key_background()

    def _ensure_key_background(self) -> None:
        def worker():
            if WireGuardManager.needs_key_refresh(self.wg_config):
                try:
                    self.wg_config = WireGuardManager.auto_fetch_and_register_key()
                except Exception:
                    pass

        threading.Thread(target=worker, daemon=True).start()

    def _on_refresh_clicked(self) -> None:
        if not self._check_login_status():
            self.show_login_view()
            return
        self.start_scan()

    def start_scan(self) -> None:
        if not self._check_login_status():
            self.show_login_view()
            return

        if self.is_scanning or self.is_connecting_vpn or self._closing:
            return

        self.is_scanning = True
        self.btn_refresh.config(text="↻", fg=self.C_ACCENT)
        self._show_loading_status("● Đang kết nối Proton API & lấy danh sách máy chủ...")
        self.progress_bar.config(mode="determinate", maximum=100, value=10)

        def scan_worker():
            try:
                payload = None
                browser_state = get_saved_browser_state()
                if browser_state:
                    self.after(0, lambda: self._show_scan_status("● Đang đọc phiên Browser Cookies..."))
                    payload = fetch_payload_from_browser_cookies(browser_state)

                if payload is None:
                    self.after(0, lambda: self._show_scan_status("● Đang đọc phiên đăng nhập SRP..."))
                    payload = fetch_payload_from_srp()

                if payload is None and os.environ.get("PROTON_COOKIE"):
                    headers = {**API_HEADERS, "Cookie": os.environ["PROTON_COOKIE"]}
                    if os.environ.get("PROTON_UID"):
                        headers["x-pm-uid"] = os.environ["PROTON_UID"]
                    req = urllib.request.Request(API_URL, headers=headers)
                    with urllib.request.urlopen(req, timeout=25) as res:
                        body = decode_response(res.read(), res.headers.get("Content-Encoding"))
                        payload = json.loads(body.decode("utf-8"))

                if payload is None:
                    self.after(0, self._prompt_login_required)
                    return

                free_servers = select_free_servers_with_wg(payload, country=None, include_down=False)
                self._ping_servers_threaded(free_servers)
                self.after(0, lambda: self._finish_scan(payload, free_servers))

            except Exception as ex:
                import traceback
                tb = traceback.format_exc()
                self.after(0, lambda e=ex, t=tb: self._on_scan_error(str(e), t))

        threading.Thread(target=scan_worker, daemon=True).start()

    def _ping_servers_threaded(self, servers: list[dict[str, Any]]) -> None:
        total = len(servers)
        self.after(0, lambda: self._update_ping_status_step(0, total, 0))

        completed = 0
        timeout_ms = DEFAULT_PING_TIMEOUT_MS
        targets: dict[str | None, list[dict[str, Any]]] = {}
        for server in servers:
            targets.setdefault(server.get("pingTarget"), []).append(server)
        last_update = time.monotonic()

        with ThreadPoolExecutor(max_workers=min(DEFAULT_PING_WORKERS, max(1, total))) as executor:
            futures = {
                executor.submit(ping_target, target, timeout_ms): group
                for target, group in targets.items()
            }
            for future in as_completed(futures):
                group = futures[future]
                try:
                    latency = future.result()
                except Exception:
                    latency = None
                for server in group:
                    server["pingMs"] = latency
                completed += len(group)
                cur = completed
                pct = int(cur / total * 100) if total > 0 else 0
                if cur == total or time.monotonic() - last_update >= 0.1:
                    self.after(0, lambda c=cur, p=pct: self._update_ping_status_step(c, total, p))
                    last_update = time.monotonic()

    def _update_ping_status_step(self, cur: int, total: int, pct: int) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        self.lbl_loading_detail.config(text=f"● Đang đo ping: {cur}/{total} máy chủ ({pct}%)...")
        self.progress_bar.config(mode="determinate", maximum=100, value=pct)

    def _finish_scan(self, payload: dict[str, Any], servers: list[dict[str, Any]]) -> None:
        if self._closing:
            return
        self.raw_payload, self.all_free_servers = payload, servers
        self.is_scanning = False
        self.btn_refresh.config(text="↻", fg=self.C_TEXT)
        self._server_list_dirty = True
        preserve_selection = self.selected_server and (
            self.is_connecting_vpn or self._tunnel_running or getattr(self, "_server_selection_manual", False)
        )
        if preserve_selection:
            self.selected_server = next((s for s in servers if s.get("name") == self.selected_server.get("name")), self.selected_server)
            self._update_home_server_card()
        else:
            self._pick_best_server_as_selected()
        self._render_country_dropdown_and_quick_pills()
        if self.current_view == "drawer":
            self._render_server_list()
            self._server_list_dirty = False
        # Save to disk cache for instant startup next time
        ServerCacheManager.save(self.raw_payload, self.all_free_servers)
        if not self.is_connecting_vpn:
            self._hide_loading_with_delay(f"● Hoàn tất! Đã quét {len(self.all_free_servers)} máy chủ Free.")

    def _pick_best_server_as_selected(self) -> None:
        if not self.all_free_servers:
            return
        reachable = [s for s in self.all_free_servers if s.get("pingMs") is not None]
        def best_fn(s):
            ping = s.get("pingMs") if s.get("pingMs") is not None else 9999
            load = s.get("load") if s.get("load") is not None else 50
            return (ping * 0.7) + (load * 0.8)
        best = min(reachable, key=best_fn) if reachable else min(self.all_free_servers, key=lambda s: s.get("load") or 0)
        self.selected_server = best
        self._update_home_server_card()

    def _prompt_login_required(self) -> None:
        self.is_scanning = False
        self.btn_refresh.config(text="↻", fg=self.C_TEXT)
        if self._check_login_status():
            self._hide_loading_with_delay("● Không thể nạp server. Bấm ↻ để thử lại.")
            self.show_home_view()
        else:
            self._hide_loading_with_delay("● Cần đăng nhập Proton.")
            self.show_login_view()

    def _on_scan_error(self, err: str, raw_trace: str = "") -> None:
        self.is_scanning = False
        self.btn_refresh.config(text="↻")
        self._hide_loading_with_delay("● Lỗi quét danh sách.")
        self.show_error_dialog(
            title="Lỗi Quét Máy Chủ",
            friendly_msg="Không thể lấy danh sách máy chủ Proton VPN. Vui lòng kiểm tra kết nối mạng và thử lại.",
            detail=err,
            raw_trace=raw_trace,
        )

    # --- Session & Settings & About Dialogs ---

    def _check_login_status(self) -> bool:
        browser_state = get_saved_browser_state()
        if browser_state:
            cookies = browser_state.get("cookies", [])
            has_real_auth = any(
                c.get("name", "").startswith("AUTH-") or c.get("name", "") in {"UID", "SSID"}
                for c in cookies
            )
            if has_real_auth:
                self.lbl_account_chip.config(text="● Browser", fg=self.C_SUCCESS)
                self.btn_login_act.config(text="Đăng xuất", fg=self.C_TEXT_MUTED)
                return True

        srp_acc = keyring.get_password(KEYRING_SERVICE_SRP, KEYRING_ACCOUNT_SRP)
        if srp_acc:
            acc_short = srp_acc if len(srp_acc) <= 14 else (srp_acc[:11] + "...")
            self.lbl_account_chip.config(text=f"● {acc_short}", fg=self.C_SUCCESS)
            self.btn_login_act.config(text="Đăng xuất", fg=self.C_TEXT_MUTED)
            return True

        self.lbl_account_chip.config(text="○ Chưa đăng nhập", fg=self.C_TEXT_DIM)
        self.btn_login_act.config(text="🔑 Đăng nhập", fg=self.C_ACCENT)
        return False

    def _on_account_chip_clicked(self) -> None:
        if self._check_login_status():
            if messagebox.askyesno("Tài khoản", "Đang lưu phiên đăng nhập.\n\nBạn có muốn đăng xuất để đổi tài khoản không?", parent=self):
                self._logout()
        else:
            self.show_login_view()

    def _open_srp_login_dialog(self) -> None:
        self.show_srp_view()


    def _on_login_clicked(self) -> None:
        reply = messagebox.askyesno(
            "Đăng nhập Proton",
            "Ứng dụng sẽ mở Microsoft Edge để bạn đăng nhập Proton an toàn và tự động lưu phiên trên máy.\n\nTiếp tục?",
            parent=self,
        )
        if not reply:
            return

        self._show_loading_status("● Đang khởi chạy trình duyệt Edge...")

        def login_worker():
            try:
                from playwright.sync_api import sync_playwright

                with sync_playwright() as playwright:
                    browser, browser_name = launch_browser(playwright)
                    try:
                        context = browser.new_context(
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
                            viewport={"width": 1024, "height": 720},
                        )
                        context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                        login_page = context.new_page()
                        self.after(0, lambda: self._show_loading_status(f"● {browser_name} đã mở! Hãy đăng nhập trên trình duyệt..."))
                        login_page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60_000)


                        captured_payload: dict[str, Any] = {"data": None}

                        def handle_response(response: Any) -> None:
                            try:
                                url = response.url.lower()
                                if "logicals" in url and response.status == 200:
                                    data = response.json()
                                    if isinstance(data, dict) and isinstance(data.get("LogicalServers"), list):
                                        captured_payload["data"] = data
                            except Exception:
                                pass

                        context.on("response", handle_response)

                        deadline = time.monotonic() + 300
                        has_been_on_login = False
                        saved_successfully = False
                        payload = None

                        while time.monotonic() < deadline:
                            # 1. Check if passive response listener caught logicals payload
                            if captured_payload["data"]:
                                st = context.storage_state()
                                keyring.set_password(KEYRING_SERVICE_BROWSER, KEYRING_ACCOUNT_BROWSER, encode_state(st))
                                payload = captured_payload["data"]
                                saved_successfully = True
                                break

                            # 2. Check all open pages
                            for page in list(context.pages):
                                if page.is_closed():
                                    continue
                                try:
                                    cur_url = page.url.lower()
                                    if "/login" in cur_url or "sso" in cur_url or "signin" in cur_url:
                                        has_been_on_login = True

                                    # Only consider logged in if the user was on the login page and now navigated to an authenticated page
                                    is_auth_page = (
                                        ("/downloads" in cur_url or "/dashboard" in cur_url or "/account" in cur_url or "/home" in cur_url)
                                        and "/login" not in cur_url
                                    )
                                    if has_been_on_login and is_auth_page:
                                        cookies = context.cookies()
                                        has_auth_cookie = any(
                                            c.get("name", "").startswith("AUTH-") or c.get("name", "") in {"Session-Id", "SSID", "UID"}
                                            for c in cookies
                                        )
                                        if has_auth_cookie:
                                            st = context.storage_state()
                                            keyring.set_password(KEYRING_SERVICE_BROWSER, KEYRING_ACCOUNT_BROWSER, encode_state(st))
                                            saved_successfully = True

                                            # Try in-page fetch for fast payload
                                            try:
                                                in_page = page.evaluate("""
                                                    async () => {
                                                        try {
                                                            const r = await fetch('/api/vpn/v1/logicals?WithIpV6=1', { credentials: 'include' });
                                                            if (r.status === 200) return await r.json();
                                                        } catch(e) {}
                                                        try {
                                                            const r2 = await fetch('/api/vpn/logicals?WithIpV6=1', { credentials: 'include' });
                                                            if (r2.status === 200) return await r2.json();
                                                        } catch(e) {}
                                                        return null;
                                                    }
                                                """)
                                                if in_page and isinstance(in_page.get("LogicalServers"), list):
                                                    payload = in_page
                                            except Exception:
                                                pass
                                            break
                                except Exception:
                                    pass

                            if saved_successfully:
                                break

                            if all(p.is_closed() for p in context.pages):
                                raise RuntimeError("Bạn đã đóng trình duyệt trước khi hoàn tất đăng nhập.")
                            time.sleep(1.0)

                        if not saved_successfully:
                            raise RuntimeError("Hết thời gian chờ đăng nhập (300 giây).")



                        self.raw_payload = payload
                        self.after(0, lambda: self._show_loading_status("● Đăng nhập thành công! Đang lưu phiên..."))
                        self.after(0, lambda: self._on_login_success(payload))
                    finally:
                        try:
                            browser.close()
                        except Exception:
                            pass
            except Exception as ex:
                import traceback
                tb = traceback.format_exc()
                self.after(0, lambda e=ex, t=tb: self._on_login_failed(str(e), t))

        threading.Thread(target=login_worker, daemon=True).start()

    def _on_login_failed(self, err: str, raw_trace: str = "") -> None:
        self._hide_loading_with_delay("● Đăng nhập thất bại.")
        self.show_error_dialog(
            title="Lỗi Đăng Nhập",
            friendly_msg="Đăng nhập không thành công hoặc phiên duyệt web đã bị đóng.",
            detail=err,
            raw_trace=raw_trace,
        )

    def _on_login_success(self, payload: dict[str, Any] | None) -> None:
        self._check_login_status()
        self.show_home_view()
        self._ensure_key_background()
        self.start_scan()

    def _logout(self) -> None:
        if self.is_connecting_vpn or self._closing:
            return
        if self._tunnel_running:
            self._logout_after_disconnect = True
            self._disconnect_vpn()
            return
        delete_all_saved_sessions()
        ServerCacheManager.clear()
        self.wg_config = WireGuardManager.load_config()
        self.all_free_servers = []
        self.selected_server = None
        self.connected_server = None
        self._pending_srp_session = None
        self._pending_srp_user = None
        self._check_login_status()
        self.show_login_view()
        messagebox.showinfo("Đã đăng xuất", "Đã xóa phiên đăng nhập trên máy.", parent=self)

    def _check_for_updates(self, manual: bool = False) -> None:
        """Checks for software updates via remote version.json or GitHub API."""
        def worker():
            try:
                info = fetch_update_info()
                if info and is_newer_version(APP_VERSION, info.version):
                    self.after(0, lambda: UpdateDialog(self, info))
                elif manual:
                    if info:
                        self.after(0, lambda: messagebox.showinfo(
                            "Kiểm tra cập nhật",
                            f"🎉 Bạn đang sử dụng phiên bản mới nhất ({APP_NAME} v{APP_VERSION})!\nKhông có bản cập nhật nào.",
                            parent=self,
                        ))
                    else:
                        self.after(0, lambda: messagebox.showwarning(
                            "Kiểm tra cập nhật",
                            "Không thể kiểm tra phiên bản mới lúc này. Vui lòng kiểm tra lại kết nối mạng hoặc thử lại sau.",
                            parent=self,
                        ))
            except Exception as ex:
                if manual:
                    self.after(0, lambda e=str(ex): messagebox.showerror(
                        "Lỗi Kiểm Tra Cập Nhật",
                        f"Đã xảy ra lỗi khi kiểm tra phiên bản mới:\n{e}",
                        parent=self,
                    ))

        threading.Thread(target=worker, daemon=True).start()

    def _open_about_dialog(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title(f"Giới thiệu {APP_NAME}")
        dlg.geometry("350x450")
        dlg.resizable(False, False)
        dlg.configure(bg=self.C_BG)
        dlg.attributes("-topmost", True)
        dlg.transient(self)
        dlg.grab_set()
        self.register_modal(dlg)
        self.after(50, lambda: apply_window_rounded_corners(dlg))

        try:
            x = self.winfo_x() + (self.winfo_width() - 350) // 2
            y = self.winfo_y() + (self.winfo_height() - 450) // 2
            dlg.geometry(f"350x450+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        card = RoundedCard(
            dlg,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=16,
            padding=16,
            height=410,
        )
        card.pack(fill="both", expand=True, padx=12, pady=12)

        tk.Label(card.inner_frame, text="⚡", font=("Segoe UI", 24), bg=self.C_CARD, fg=self.C_ACCENT).pack(pady=(0, 2))
        tk.Label(card.inner_frame, text=APP_NAME, font=("Segoe UI", 14, "bold"), bg=self.C_CARD, fg=self.C_TEXT).pack()
        
        # Version badge & quick check button row
        row_ver = tk.Frame(card.inner_frame, bg=self.C_CARD)
        row_ver.pack(pady=(0, 8))
        tk.Label(row_ver, text=f"{APP_SUBTITLE} • v{APP_VERSION}", font=("Segoe UI", 8, "italic"), bg=self.C_CARD, fg=self.C_ACCENT).pack(side="left", padx=(0, 6))

        btn_chk = RoundedPillButton(
            row_ver,
            text="🔄 Kiểm tra bản mới",
            command=lambda: [dlg.destroy(), self._check_for_updates(manual=True)],
            width=110,
            height=20,
            radius=5,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg=self.C_BORDER,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 7),
        )
        btn_chk.pack(side="left")

        tk.Label(
            card.inner_frame,
            text="Phần mềm kết nối WireGuard tốc độ cao, siêu nhẹ cho các cụm máy chủ Proton VPN Free với thuật toán tự động chọn node tối ưu.",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT_MUTED,
            wraplength=280,
            justify="center",
        ).pack(pady=(0, 8))

        # Legal Disclaimer box in Vietnamese
        disc_box = RoundedCard(
            card.inner_frame,
            bg_color=self.C_CARD,
            card_color=self.C_CARD_HIGH,
            border_color=self.C_BORDER,
            radius=10,
            padding=8,
            height=110,
        )
        disc_box.pack(fill="x", pady=(0, 10))

        tk.Label(disc_box.inner_frame, text="TUYÊN BỐ PHÁP LÝ (LEGAL DISCLAIMER)", font=("Segoe UI", 7, "bold"), bg=self.C_CARD_HIGH, fg=self.C_TEXT_DIM).pack(anchor="w", pady=(0, 2))
        tk.Label(
            disc_box.inner_frame,
            text="Freeton VPN là một dự án mã nguồn mở độc lập và KHÔNG thuộc sở hữu, KHÔNG liên kết, cũng như KHÔNG được ủy quyền hay tài trợ bởi Proton AG hoặc Proton VPN. Tất cả tên nhãn hiệu, logo và thương hiệu đều thuộc bản quyền của chủ sở hữu tương ứng.",
            font=("Segoe UI", 7),
            bg=self.C_CARD_HIGH,
            fg=self.C_TEXT_MUTED,
            wraplength=270,
            justify="left",
        ).pack(anchor="w")

        btn_close = RoundedPillButton(
            card.inner_frame,
            text="Đóng",
            command=dlg.destroy,
            width=120,
            height=32,
            radius=10,
            bg_color=self.C_CARD,
            btn_color=self.C_ACCENT,
            fg_color="#000000",
            hover_bg=self.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 8, "bold"),
        )
        btn_close.pack(side="bottom")

    def _open_wg_settings(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("Cài đặt Freeton VPN")
        dlg.geometry("360x650")
        dlg.resizable(False, False)
        dlg.configure(bg=self.C_BG)
        dlg.attributes("-topmost", True)
        dlg.transient(self)
        dlg.grab_set()
        self.register_modal(dlg)
        self.after(50, lambda: apply_window_rounded_corners(dlg))

        try:
            x = self.winfo_x() + (self.winfo_width() - 360) // 2
            y = self.winfo_y() + (self.winfo_height() - 650) // 2
            dlg.geometry(f"360x650+{max(0, x)}+{max(0, y)}")
        except Exception:
            pass

        main_box = tk.Frame(dlg, bg=self.C_BG)
        main_box.pack(fill="both", expand=True, padx=12, pady=10)

        # Header Title
        hdr = tk.Frame(main_box, bg=self.C_BG)
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="⚙️ Cài Đặt Hệ Thống", font=("Segoe UI", 11, "bold"), bg=self.C_BG, fg=self.C_TEXT).pack(side="left")

        # Middle Mouse Press & Hold to Toggle Debug / Developer Mode
        middle_hold_timer: list[Any] = [None]

        def trigger_debug_toggle() -> None:
            middle_hold_timer[0] = None
            self.is_debug_mode = not self.is_debug_mode
            self.wg_config["debug_mode"] = self.is_debug_mode
            WireGuardManager.save_config(self.wg_config)
            self._update_debug_mode_ui()
            refresh_debug_badge_in_settings()

            if self.is_debug_mode:
                messagebox.showinfo(
                    "Chế độ Nhà phát triển (Debug Mode)",
                    "🛠️ ĐÃ KÍCH HOẠT CHẾ ĐỘ DEBUG!\n\n"
                    "• Mở khóa các nút '💾 Xuất .conf' trên Trang chủ và Danh sách máy chủ.\n"
                    "• Hiển thị chi tiết lỗi kỹ thuật & Stack Trace đầy đủ khi gặp sự cố.\n"
                    "• Nhấn giữ chuột giữa trong Cài đặt một lần nữa để quay lại Chế độ Bình thường.",
                    parent=dlg,
                )
            else:
                messagebox.showinfo(
                    "Chế độ Người dùng (Normal Mode)",
                    "🔒 ĐÃ TẮT CHẾ ĐỘ DEBUG!\n\n"
                    "• Ứng dụng đã chuyển về Chế độ Người dùng Tiêu chuẩn (ẩn các nút xuất .conf).",
                    parent=dlg,
                )

        def on_middle_press(event: Any = None) -> None:
            if middle_hold_timer[0] is not None:
                try:
                    dlg.after_cancel(middle_hold_timer[0])
                except Exception:
                    pass
            middle_hold_timer[0] = dlg.after(750, trigger_debug_toggle)

        def on_middle_release(event: Any = None) -> None:
            if middle_hold_timer[0] is not None:
                try:
                    dlg.after_cancel(middle_hold_timer[0])
                except Exception:
                    pass
                middle_hold_timer[0] = None

        lbl_debug_tag = RoundedPillButton(
            hdr,
            text="🛠️ DEV MODE",
            command=trigger_debug_toggle,
            width=86,
            height=22,
            radius=6,
            bg_color=self.C_BG,
            btn_color=self.C_ACCENT,
            fg_color="#000000",
            border_color=self.C_ACCENT,
            hover_bg=self.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 7, "bold"),
        )

        def refresh_debug_badge_in_settings() -> None:
            if self.is_debug_mode:
                lbl_debug_tag.pack(side="right")
            else:
                lbl_debug_tag.pack_forget()

        refresh_debug_badge_in_settings()

        # ==========================================
        # SECTION 1: ⚙️ Cài Đặt Ứng Dụng (App Settings)
        # ==========================================
        card_app = RoundedCard(
            main_box,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=12,
            padding=10,
            height=215,
        )
        card_app.pack(fill="x", pady=(0, 8))

        tk.Label(card_app.inner_frame, text="⚙️ CÀI ĐẶT ỨNG DỤNG", font=("Segoe UI", 7, "bold"), bg=self.C_CARD, fg=self.C_ACCENT).pack(anchor="w", pady=(0, 4))

        # Switch 1: Startup with Windows (Modern iOS Pill Toggle)
        row_startup = tk.Frame(card_app.inner_frame, bg=self.C_CARD)
        row_startup.pack(fill="x", pady=(0, 5))
        lbl_st = tk.Label(
            row_startup,
            text="Khởi động cùng Windows (Startup)",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT,
            cursor="hand2",
        )
        lbl_st.pack(side="left")

        var_startup = tk.BooleanVar(value=WindowsStartupManager.is_enabled())
        sw_startup = IOSToggleSwitch(row_startup, width=44, height=24, bg_color=self.C_CARD, cursor="hand2")
        sw_startup.pack(side="right")
        sw_startup.set_state(var_startup.get(), animate=False)

        def toggle_startup():
            new_val = not sw_startup._state
            sw_startup.set_state(new_val)
            var_startup.set(new_val)

        sw_startup.command = toggle_startup
        lbl_st.bind("<Button-1>", lambda e: toggle_startup())

        # Switch 2: UI Animations (Modern iOS Pill Toggle)
        row_anim = tk.Frame(card_app.inner_frame, bg=self.C_CARD)
        row_anim.pack(fill="x", pady=(0, 5))
        lbl_an = tk.Label(
            row_anim,
            text="Hiệu ứng chuyển động (Animations)",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT,
            cursor="hand2",
        )
        lbl_an.pack(side="left")

        var_anim = tk.BooleanVar(value=self.wg_config.get("animations_enabled", True))
        sw_anim = IOSToggleSwitch(row_anim, width=44, height=24, bg_color=self.C_CARD, cursor="hand2")
        sw_anim.pack(side="right")
        sw_anim.set_state(var_anim.get(), animate=False)

        def toggle_anim():
            new_val = not sw_anim._state
            sw_anim.set_state(new_val)
            var_anim.set(new_val)

        sw_anim.command = toggle_anim
        lbl_an.bind("<Button-1>", lambda e: toggle_anim())

        # Switch 3: Auto-check for Updates (Modern iOS Pill Toggle)
        row_update = tk.Frame(card_app.inner_frame, bg=self.C_CARD)
        row_update.pack(fill="x", pady=(0, 6))
        lbl_upd = tk.Label(
            row_update,
            text="Tự động kiểm tra bản cập nhật",
            font=("Segoe UI", 8),
            bg=self.C_CARD,
            fg=self.C_TEXT,
            cursor="hand2",
        )
        lbl_upd.pack(side="left")

        var_update = tk.BooleanVar(value=self.wg_config.get("auto_check_update", True))
        sw_update = IOSToggleSwitch(row_update, width=44, height=24, bg_color=self.C_CARD, cursor="hand2")
        sw_update.pack(side="right")
        sw_update.set_state(var_update.get(), animate=False)

        def toggle_update():
            new_val = not sw_update._state
            sw_update.set_state(new_val)
            var_update.set(new_val)

        sw_update.command = toggle_update
        lbl_upd.bind("<Button-1>", lambda e: toggle_update())

        # Buttons Row: Check update & Manage dependencies
        row_app_btns = tk.Frame(card_app.inner_frame, bg=self.C_CARD)
        row_app_btns.pack(fill="x", pady=(0, 0))

        btn_chk_now = RoundedPillButton(
            row_app_btns,
            text="🔄 Kiểm tra bản mới",
            command=lambda: [dlg.destroy(), self._check_for_updates(manual=True)],
            width=135,
            height=26,
            radius=7,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_bg=self.C_BORDER,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 7),
        )
        btn_chk_now.pack(side="left", fill="x", expand=True, padx=(0, 3))

        btn_dep = RoundedPillButton(
            row_app_btns,
            text="🛠️ Thành phần hệ thống",
            command=lambda: [dlg.destroy(), self._open_dependency_dialog()],
            width=155,
            height=26,
            radius=7,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_ACCENT,
            border_color=self.C_BORDER,
            hover_bg=self.C_BORDER,
            hover_fg=self.C_ACCENT_HOVER,
            font=("Segoe UI", 7, "bold"),
        )
        btn_dep.pack(side="right", fill="x", expand=True, padx=(3, 0))

        # ==========================================
        # SECTION 2: 🛡️ Cài Đặt WireGuard & Mạng
        # ==========================================
        card_wg = RoundedCard(
            main_box,
            bg_color=self.C_BG,
            card_color=self.C_CARD,
            border_color=self.C_BORDER,
            radius=12,
            padding=10,
            height=285,
        )
        card_wg.pack(fill="x", pady=(0, 8))

        tk.Label(card_wg.inner_frame, text="🛡️ CÀI ĐẶT WIREGUARD & MẠNG", font=("Segoe UI", 7, "bold"), bg=self.C_CARD, fg=self.C_ACCENT).pack(anchor="w", pady=(0, 4))

        exp_time = self.wg_config.get("expiration", 0)
        exp_str = datetime.fromtimestamp(exp_time).strftime("%d/%m/%Y %H:%M") if exp_time else "Vĩnh viễn / Tĩnh"
        is_dynamic = exp_time > 0

        lbl_exp = tk.Label(
            card_wg.inner_frame,
            text=f"● Trạng thái Key: {exp_str} {'(Tự làm mới)' if is_dynamic else '(Key tĩnh)'}",
            font=("Segoe UI", 7, "bold"),
            bg=self.C_CARD,
            fg=self.C_SUCCESS if (is_dynamic or self.wg_config.get("private_key")) else self.C_WARNING,
        )
        lbl_exp.pack(anchor="w", pady=(0, 4))

        # Action Buttons Row: Fetch Key & Import Conf
        btn_wg_row = tk.Frame(card_wg.inner_frame, bg=self.C_CARD)
        btn_wg_row.pack(fill="x", pady=(0, 6))

        def fetch_new_key():
            try:
                self.wg_config = WireGuardManager.auto_fetch_and_register_key(force=True)
                var_priv.set(self.wg_config.get("private_key", ""))
                new_exp = self.wg_config.get("expiration", 0)
                lbl_exp.config(
                    text=f"● Trạng thái Key: {datetime.fromtimestamp(new_exp).strftime('%d/%m/%Y %H:%M')} (Tự làm mới)",
                    fg=self.C_SUCCESS,
                )
                messagebox.showinfo("Thành công", "Đã cấp và kích hoạt WireGuard Key mới thành công!", parent=dlg)
            except Exception as ex:
                self.show_error_dialog(
                    title="Lỗi Cấp Key",
                    friendly_msg="Không thể tự động cấp WireGuard Key từ tài khoản.",
                    detail=str(ex),
                    exc=ex,
                    parent=dlg,
                )

        def import_conf_file():
            file_path = filedialog.askopenfilename(
                title="Chọn file cấu hình WireGuard (.conf)",
                filetypes=[("WireGuard Config", "*.conf"), ("All files", "*.*")],
                parent=dlg,
            )
            if not file_path:
                return
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                priv_match = re.search(r"PrivateKey\s*=\s*([A-Za-z0-9+/=]+)", content)
                addr_match = re.search(r"Address\s*=\s*([^\r\n]+)", content)
                dns_match = re.search(r"DNS\s*=\s*([^\r\n]+)", content)
                if priv_match:
                    var_priv.set(priv_match.group(1).strip())
                if addr_match:
                    self.wg_config["address"] = addr_match.group(1).strip()
                if dns_match:
                    var_dns.set(dns_match.group(1).strip())
                self.wg_config["expiration"] = 0
                lbl_exp.config(text="● Trạng thái Key: Đã nạp từ .conf (Key tĩnh)", fg=self.C_SUCCESS)
                messagebox.showinfo("Thành công", f"Đã nạp cấu hình từ file:\n{Path(file_path).name}", parent=dlg)
            except Exception as ex:
                self.show_error_dialog(
                    title="Lỗi Nạp File .conf",
                    friendly_msg="File cấu hình WireGuard không hợp lệ hoặc không thể đọc.",
                    detail=str(ex),
                    exc=ex,
                    parent=dlg,
                )

        btn_auto = RoundedPillButton(
            btn_wg_row,
            text="⚡ Cấp Key mới (API)",
            command=fetch_new_key,
            width=140,
            height=28,
            radius=8,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_ACCENT,
            border_color=self.C_BORDER,
            hover_bg=self.C_BORDER,
            hover_fg=self.C_ACCENT_HOVER,
            font=("Segoe UI", 7, "bold"),
        )
        btn_auto.pack(side="left", fill="x", expand=True, padx=(0, 4))

        btn_import = RoundedPillButton(
            btn_wg_row,
            text="📂 Nhập file .conf",
            command=import_conf_file,
            width=140,
            height=28,
            radius=8,
            bg_color=self.C_CARD,
            btn_color=self.C_CARD_HIGH,
            fg_color=self.C_TEXT,
            border_color=self.C_BORDER,
            hover_bg=self.C_BORDER,
            hover_fg=self.C_ACCENT,
            font=("Segoe UI", 7),
        )
        btn_import.pack(side="right", fill="x", expand=True, padx=(4, 0))

        # WireGuard Private Key Field
        tk.Label(card_wg.inner_frame, text="WIREGUARD PRIVATE KEY", font=("Segoe UI", 6, "bold"), bg=self.C_CARD, fg=self.C_TEXT_MUTED).pack(anchor="w")
        var_priv = tk.StringVar(value=self.wg_config.get("private_key", ""))
        f_priv = RoundedCard(card_wg.inner_frame, bg_color=self.C_CARD, card_color=self.C_BG, border_color=self.C_BORDER, radius=8, padding=4, height=30)
        f_priv.pack(fill="x", pady=(1, 6))
        ent_priv = tk.Entry(f_priv.inner_frame, textvariable=var_priv, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Consolas", 8))
        ent_priv.pack(fill="x", expand=True, padx=4)

        # DNS & Port in 2 columns
        cols_frame = tk.Frame(card_wg.inner_frame, bg=self.C_CARD)
        cols_frame.pack(fill="x", pady=(0, 4))

        # DNS
        f_col1 = tk.Frame(cols_frame, bg=self.C_CARD)
        f_col1.pack(side="left", fill="x", expand=True, padx=(0, 4))
        tk.Label(f_col1, text="DNS SERVER", font=("Segoe UI", 6, "bold"), bg=self.C_CARD, fg=self.C_TEXT_MUTED).pack(anchor="w")
        var_dns = tk.StringVar(value=self.wg_config.get("dns", DEFAULT_WG_DNS))
        f_dns = RoundedCard(f_col1, bg_color=self.C_CARD, card_color=self.C_BG, border_color=self.C_BORDER, radius=8, padding=4, height=30)
        f_dns.pack(fill="x", pady=(1, 0))
        tk.Entry(f_dns.inner_frame, textvariable=var_dns, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Segoe UI", 8)).pack(fill="x", expand=True, padx=4)

        # Port
        f_col2 = tk.Frame(cols_frame, bg=self.C_CARD)
        f_col2.pack(side="right", fill="x", expand=True, padx=(4, 0))
        tk.Label(f_col2, text="PORT WIREGUARD", font=("Segoe UI", 6, "bold"), bg=self.C_CARD, fg=self.C_TEXT_MUTED).pack(anchor="w")
        var_port = tk.StringVar(value=self.wg_config.get("port", str(DEFAULT_WG_PORT)))
        f_port = RoundedCard(f_col2, bg_color=self.C_CARD, card_color=self.C_BG, border_color=self.C_BORDER, radius=8, padding=4, height=30)
        f_port.pack(fill="x", pady=(1, 0))
        tk.Entry(f_port.inner_frame, textvariable=var_port, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_ACCENT, relief="flat", font=("Segoe UI", 8)).pack(fill="x", expand=True, padx=4)

        def save_settings():
            custom_priv = var_priv.get().strip()
            if custom_priv:
                self.wg_config["private_key"] = custom_priv
            self.wg_config["dns"] = var_dns.get().strip() or DEFAULT_WG_DNS
            self.wg_config["port"] = var_port.get().strip() or str(DEFAULT_WG_PORT)
            self.wg_config["animations_enabled"] = var_anim.get()
            self.wg_config["auto_check_update"] = var_update.get()
            WireGuardManager.save_config(self.wg_config)

            # Apply Windows Startup setting
            WindowsStartupManager.set_enabled(var_startup.get())

            dlg.destroy()
            messagebox.showinfo("Cài đặt", "Đã lưu và áp dụng cài đặt thành công!", parent=self)

        # ==========================================
        # BOTTOM ACTION ROW
        # ==========================================
        bot_bar = tk.Frame(main_box, bg=self.C_BG)
        bot_bar.pack(side="bottom", fill="x", pady=(6, 0))

        btn_close = RoundedPillButton(
            bot_bar,
            text="Đóng",
            command=dlg.destroy,
            width=100,
            height=34,
            radius=10,
            bg_color=self.C_BG,
            btn_color=self.C_CARD,
            fg_color=self.C_TEXT_MUTED,
            border_color=self.C_BORDER,
            hover_bg=self.C_CARD_HIGH,
            hover_fg=self.C_TEXT,
            font=("Segoe UI", 8),
        )
        btn_close.pack(side="left")

        btn_save = RoundedPillButton(
            bot_bar,
            text="💾 Lưu & Áp dụng",
            command=save_settings,
            width=150,
            height=34,
            radius=10,
            bg_color=self.C_BG,
            btn_color=self.C_ACCENT,
            fg_color="#000000",
            hover_bg=self.C_ACCENT_HOVER,
            hover_fg="#000000",
            font=("Segoe UI", 9, "bold"),
        )
        btn_save.pack(side="right")

        # Bind middle mouse press-and-hold recursively across dialog
        def bind_middle_click_recursive(w: tk.Widget) -> None:
            w.bind("<Button-2>", on_middle_press, add="+")
            w.bind("<ButtonRelease-2>", on_middle_release, add="+")
            for child in w.winfo_children():
                bind_middle_click_recursive(child)

        bind_middle_click_recursive(dlg)

    def _open_dependency_dialog(self) -> None:
        DependencySetupDialog(self)

    def _export_selected_conf(self) -> None:
        if self.selected_server:
            self._export_specific_conf(self.selected_server)

    def _export_specific_conf(self, server: dict[str, Any]) -> None:
        if not WireGuardManager.has_usable_key(self.wg_config):
            try:
                self.wg_config = WireGuardManager.auto_fetch_and_register_key()
            except Exception as ex:
                self.show_error_dialog(
                    title="Lỗi Key WireGuard",
                    friendly_msg="Không thể lấy hoặc đăng ký WireGuard Key cho tài khoản.",
                    detail=str(ex),
                    exc=ex,
                    parent=self,
                )
                return

        conf_content = WireGuardManager.generate_conf_content(server, self.wg_config)
        default_name = f"{server.get('name', 'FreetonVPN')}.conf"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_name,
            defaultextension=".conf",
            filetypes=[("WireGuard Config", "*.conf"), ("All files", "*.*")],
            title=f"Xuất cấu hình cho {server.get('name')}",
            parent=self,
        )
        if file_path:
            try:
                Path(file_path).write_text(conf_content, encoding="utf-8")
                messagebox.showinfo("Đã xuất cấu hình", f"Đã lưu file WireGuard tại:\n{file_path}", parent=self)
            except Exception as ex:
                self.show_error_dialog(
                    title="Lỗi Xuất File",
                    friendly_msg="Không thể lưu file cấu hình WireGuard.",
                    detail=str(ex),
                    exc=ex,
                    parent=self,
                )


def _global_cleanup_on_exit() -> None:
    try:
        if WireGuardManager.is_tunnel_running(DEFAULT_TUNNEL_NAME):
            WireGuardManager.disconnect_tunnel(DEFAULT_TUNNEL_NAME)
    except Exception:
        pass


def main() -> int:
    # Importing the module (tests/tools) must never disconnect a live VPN.
    atexit.register(_global_cleanup_on_exit)
    app = FreetonVPNApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
