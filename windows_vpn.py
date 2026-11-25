"""Bounded, read-only Windows/WireGuard health checks (no private key dumps)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time

SERVICE_RUNNING = 4


def service_state(name: str) -> int:
    """Return the numeric SCM state, or 0 only when the service is absent."""
    if os.name != "nt":
        return 0
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenSCManagerW.restype = wintypes.HANDLE
    api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenServiceW.restype = wintypes.HANDLE
    api.QueryServiceStatusEx.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    api.QueryServiceStatusEx.restype = wintypes.BOOL
    api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    api.CloseServiceHandle.restype = wintypes.BOOL
    manager = api.OpenSCManagerW(None, None, 1)  # SC_MANAGER_CONNECT
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        service = api.OpenServiceW(manager, name, 4)  # SERVICE_QUERY_STATUS
        if not service:
            error = ctypes.get_last_error()
            if error == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return 0
            raise ctypes.WinError(error)
        try:
            # SERVICE_STATUS_PROCESS: nine DWORD fields, state is the second.
            status = (wintypes.DWORD * 9)()
            needed = wintypes.DWORD()
            if not api.QueryServiceStatusEx(service, 0, status, ctypes.sizeof(status), ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            return int(status[1])
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


def latest_handshake(wg_exe: str, tunnel: str, peer: str | None = None) -> int:
    result = subprocess.run(
        [wg_exe, "show", tunnel, "latest-handshakes"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=2, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError("Không đọc được handshake WireGuard. Hãy chạy ứng dụng với quyền Administrator.")
    stamps = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and (peer is None or fields[0] == peer):
            try:
                stamps.append(int(fields[1]))
            except ValueError:
                continue
    return max(stamps, default=0)


def dns_responds_through_tunnel(address: str, dns: str, timeout: float = 2) -> bool:
    """Bind the DNS request to the tunnel address, never the physical adapter."""
    sources = [ipaddress.ip_interface(value.strip()).ip for value in address.split(",")]
    deadline = time.monotonic() + timeout
    targets = dns.split(",")
    for index, value in enumerate(targets):
        try:
            target = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        source = next((ip for ip in sources if ip.version == target.version), None)
        remaining = deadline - time.monotonic()
        if source is None or remaining <= 0:
            continue
        query_id = secrets.randbits(16)
        question = b"\x07account\x09protonvpn\x03com\x00\x00\x01\x00\x01"
        query = struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + question
        family = socket.AF_INET if target.version == 4 else socket.AF_INET6
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(remaining / (len(targets) - index))
                sock.bind((str(source), 0))
                sock.connect((str(target), 53))
                sock.send(query)
                response = sock.recv(4096)
            if len(response) >= 12:
                ident, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
                if ident == query_id and flags & 0x8000 and not flags & 0x020F and questions == 1 and answers > 0:
                    return True
        except OSError:
            continue
    return False


def find_wg_cli(wireguard_exe: str | None) -> str:
    if wireguard_exe:
        candidate = Path(wireguard_exe).with_name("wg.exe")
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("Thiếu wg.exe để xác minh kết nối. Vui lòng cài lại WireGuard for Windows.")
