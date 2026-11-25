# -*- coding: utf-8 -*-
"""
updater.py - Auto-Update Manager for Freeton VPN
Supports checking versions via remote version.json (GitHub Raw) or GitHub Releases API,
stream-downloading standalone executable with progress tracking, SHA-256 verification,
and seamless Windows batch-assisted in-place replacement and restart.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Tuple, List, Dict, Any

logger = logging.getLogger("freeton.updater")

# Default Update Endpoints
DEFAULT_GITHUB_REPO = "datpusheen/FreetonVPN"
DEFAULT_VERSION_JSON_URL = "https://raw.githubusercontent.com/datpusheen/FreetonVPN/refs/heads/main/version.json"
DEFAULT_RELEASES_API_URL = f"https://api.github.com/repos/{DEFAULT_GITHUB_REPO}/releases/latest"

USER_AGENT = "FreetonVPN-Desktop-Updater/2.4.3 (Windows NT 10.0; Win64; x64)"


@dataclass
class UpdateInfo:
    """Represents release update metadata."""
    version: str
    release_date: str = ""
    title: str = ""
    changelog: List[str] = field(default_factory=list)
    download_url: str = ""
    file_size_bytes: int = 0
    sha256: str = ""
    mandatory: bool = False
    min_supported_version: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @property
    def formatted_changelog(self) -> str:
        """Returns changelog as formatted plain text string."""
        if isinstance(self.changelog, list):
            return "\n".join(f"• {item}" if not item.strip().startswith(("•", "-", "*")) else item for item in self.changelog)
        return str(self.changelog or "Không có thông tin thay đổi.")


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """
    Parses a version string into a comparable tuple of integers.
    Examples:
        '2.4' -> (2, 4)
        'v2.4.1' -> (2, 4, 1)
        '3.0-beta2' -> (3, 0, 2)
    """
    if not v_str:
        return (0,)
    nums = re.findall(r"\d+", str(v_str))
    if not nums:
        return (0,)
    return tuple(int(n) for n in nums)


def is_newer_version(current_version: str, remote_version: str) -> bool:
    """
    Returns True if remote_version is strictly newer than current_version.
    Handles different lengths by padding with zeros (e.g., (2, 4) vs (2, 4, 1)).
    """
    curr = list(parse_version_tuple(current_version))
    remote = list(parse_version_tuple(remote_version))

    max_len = max(len(curr), len(remote))
    curr.extend([0] * (max_len - len(curr)))
    remote.extend([0] * (max_len - len(remote)))

    return tuple(remote) > tuple(curr)


def fetch_update_info(
    url: Optional[str] = None,
    repo: Optional[str] = None,
    timeout: float = 6.0
) -> Optional[UpdateInfo]:
    """
    Fetches update metadata from version.json URL, falling back to GitHub Releases API.
    """
    target_url = url or DEFAULT_VERSION_JSON_URL
    target_repo = repo or DEFAULT_GITHUB_REPO

    # Append timestamp query param to bypass GitHub CDN cache
    separator = "&" if "?" in target_url else "?"
    cache_busted_url = f"{target_url}{separator}_cb={int(time.time())}"

    # 1. Try fetching version.json directly
    try:
        req = urllib.request.Request(
            cache_busted_url,
            headers={
                "User-Agent": USER_AGENT,
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_text = resp.read().decode("utf-8")
                data = json.loads(raw_text)
                return _parse_json_update_info(data)
    except Exception as ex:
        logger.debug(f"Direct version.json check failed: {ex}. Falling back to GitHub Releases API...")

    # 2. Fallback: GitHub Releases API
    try:
        api_url = f"https://api.github.com/repos/{target_repo}/releases/latest"
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw_text = resp.read().decode("utf-8")
                data = json.loads(raw_text)
                return _parse_github_release_info(data)
    except Exception as ex:
        logger.warning(f"GitHub Releases API check failed: {ex}")

    return None


def _parse_json_update_info(data: Dict[str, Any]) -> UpdateInfo:
    """Parses raw version.json dictionary into UpdateInfo."""
    ver = str(data.get("version", "")).strip()
    title = str(data.get("title", f"Freeton VPN v{ver}")).strip()
    rel_date = str(data.get("release_date", "")).strip()
    download_url = str(data.get("download_url", "")).strip()
    size_bytes = int(data.get("file_size_bytes", 0) or 0)
    sha256 = str(data.get("sha256", "")).strip().lower()
    mandatory = bool(data.get("mandatory", False))
    min_sup = str(data.get("min_supported_version", "")).strip()

    raw_cl = data.get("changelog", [])
    if isinstance(raw_cl, list):
        changelog = [str(x).strip() for x in raw_cl if str(x).strip()]
    elif isinstance(raw_cl, str):
        changelog = [x.strip() for x in raw_cl.splitlines() if x.strip()]
    else:
        changelog = []

    return UpdateInfo(
        version=ver,
        release_date=rel_date,
        title=title,
        changelog=changelog,
        download_url=download_url,
        file_size_bytes=size_bytes,
        sha256=sha256,
        mandatory=mandatory,
        min_supported_version=min_sup,
        raw_data=data,
    )


def _parse_github_release_info(data: Dict[str, Any]) -> UpdateInfo:
    """Parses GitHub Releases API response into UpdateInfo."""
    tag_name = str(data.get("tag_name", "")).lstrip("v")
    title = str(data.get("name", f"Freeton VPN v{tag_name}")).strip()
    rel_date = str(data.get("published_at", "")[:10]).strip()
    body = str(data.get("body", "")).strip()

    download_url = ""
    file_size = 0
    for asset in data.get("assets", []):
        asset_name = str(asset.get("name", ""))
        if asset_name.lower().endswith(".exe"):
            download_url = str(asset.get("browser_download_url", ""))
            file_size = int(asset.get("size", 0) or 0)
            break

    changelog = [line.strip() for line in body.splitlines() if line.strip()]

    return UpdateInfo(
        version=tag_name,
        release_date=rel_date,
        title=title,
        changelog=changelog,
        download_url=download_url,
        file_size_bytes=file_size,
        raw_data=data,
    )


def download_update_stream(
    download_url: str,
    dest_path: Path,
    progress_callback: Optional[Callable[[int, int, float], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    chunk_size: int = 65536,
    timeout: float = 20.0
) -> bool:
    """
    Downloads the update file in chunks with progress reporting.
    progress_callback receives (downloaded_bytes, total_bytes, percent_0_to_100).
    """
    dest_path = Path(dest_path)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    temp_dest = dest_path.with_suffix(dest_path.suffix + ".part")
    if temp_dest.exists():
        try:
            temp_dest.unlink()
        except Exception:
            pass

    req = urllib.request.Request(
        download_url,
        headers={"User-Agent": USER_AGENT}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            total_size = int(response.headers.get("Content-Length", 0) or 0)
            downloaded = 0

            with open(temp_dest, "wb") as f_out:
                while True:
                    if cancel_event and cancel_event.is_set():
                        f_out.close()
                        if temp_dest.exists():
                            temp_dest.unlink()
                        return False

                    chunk = response.read(chunk_size)
                    if not chunk:
                        break

                    f_out.write(chunk)
                    downloaded += len(chunk)

                    if progress_callback:
                        percent = (downloaded / total_size * 100.0) if total_size > 0 else 0.0
                        try:
                            progress_callback(downloaded, total_size, min(100.0, percent))
                        except Exception:
                            pass

        if dest_path.exists():
            try:
                dest_path.unlink()
            except Exception:
                pass
        temp_dest.rename(dest_path)
        return True

    except Exception as ex:
        logger.error(f"Download failed from {download_url}: {ex}")
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except Exception:
                pass
        raise ex


def compute_file_sha256(file_path: Path) -> str:
    """Calculates the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def is_running_as_frozen_exe() -> bool:
    """Checks if running as a PyInstaller standalone executable."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def get_current_executable_path() -> Path:
    """Gets the path to the currently running executable."""
    return Path(sys.executable).resolve()


def apply_update_and_restart(new_exe_path: Path) -> bool:
    """
    Executes a Windows batch script to overwrite the current executable with the new version
    after the current process terminates, then restarts the new application.
    """
    if not is_running_as_frozen_exe():
        logger.info("Running in Python source mode - Skipping executable replacement.")
        return False

    target_exe = get_current_executable_path()
    new_exe = Path(new_exe_path).resolve()

    if not new_exe.exists():
        raise FileNotFoundError(f"New executable not found at: {new_exe}")

    temp_dir = Path(tempfile.gettempdir())
    batch_path = temp_dir / f"freeton_updater_handoff_{int(time.time())}.bat"

    batch_script = f"""@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

set "SOURCE={new_exe}"
set "TARGET={target_exe}"
set "OLD_PID={os.getpid()}"

:: 1. Wait for parent process to release file handle
timeout /t 1 /nobreak >nul

:: 2. Retry loop up to 15 times (15 seconds total)
set /a ATTEMPTS=0
:RETRY_LOOP
set /a ATTEMPTS+=1

copy /y /b "!SOURCE!" "!TARGET!" >nul 2>&1
if !ERRORLEVEL! equ 0 goto SUCCESS

if !ATTEMPTS! geq 15 goto FAILED
timeout /t 1 /nobreak >nul
goto RETRY_LOOP

:SUCCESS
:: Clean up downloaded temp file
del /f /q "!SOURCE!" >nul 2>&1
:: Launch the newly updated executable
start "" "!TARGET!"
goto CLEANUP

:FAILED
msg * "Loi cap nhat: Khong the ghi de file FreetonVPN.exe. Vui long tai lai thu cong."
goto CLEANUP

:CLEANUP
:: Self-delete batch file cleanly
(goto) 2>nul & del "%~f0"
"""

    batch_path.write_text(batch_script, encoding="utf-8")

    CREATE_NO_WINDOW = 0x08000000
    DETACHED_PROCESS = 0x00000008

    # The replacement is a fresh application instance, not a PyInstaller
    # worker child of the process that is about to exit. This tells PyInstaller
    # to clear inherited onefile state before the batch script launches it.
    handoff_env = os.environ.copy()
    handoff_env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"

    subprocess.Popen(
        ["cmd.exe", "/c", str(batch_path)],
        creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
        close_fds=True,
        shell=False,
        env=handoff_env,
    )

    return True
