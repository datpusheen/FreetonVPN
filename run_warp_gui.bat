@echo off
title Freeton VPN by pishun
cd /d "%~dp0"

:: 1. Kiem tra quyen Administrator (De quan ly WireGuard Tunnel Service)
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [THONG BAO] Dang yeu cau quyen Administrator de khoi chay Freeton VPN...
    powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 0
)


:: 2. Chay ung dung bang pythonw de chay ngam tren khay he thong khong hien cua so den CMD
if exist .venv-windows\Scripts\pythonw.exe (
    start "" .\.venv-windows\Scripts\pythonw.exe proton_warp_material_gui.py
    exit /b 0
)

if exist .venv\Scripts\pythonw.exe (
    start "" .\.venv\Scripts\pythonw.exe proton_warp_material_gui.py
    exit /b 0
)

if exist .venv\Scripts\python.exe (
    start "" .\.venv\Scripts\python.exe proton_warp_material_gui.py
    exit /b 0
)

where pythonw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pythonw proton_warp_material_gui.py
    exit /b 0
)

where python >nul 2>nul
if %errorlevel% equ 0 (
    start "" python proton_warp_material_gui.py
    exit /b 0
)

echo [LOI] Khong tim thay Python tren he thong de khoi chay giao dien!
pause
exit /b 1
