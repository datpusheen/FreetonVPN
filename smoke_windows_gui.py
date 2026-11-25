"""Manual Windows GUI smoke test with isolated credentials, network and services.

Run with .venv-windows/Scripts/python.exe smoke_windows_gui.py.
Creates a withdrawn Tk window; does not connect a real VPN or launch a tray icon.
"""
from contextlib import ExitStack
from unittest.mock import MagicMock, patch
import tkinter as tk
import time

import proton_warp_material_gui as app


def main():
    original_init = tk.Tk.__init__

    def hidden_init(root, *args, **kwargs):
        original_init(root, *args, **kwargs)
        root.withdraw()

    config = {"private_key": "", "animations_enabled": False, "auto_check_update": False}
    with ExitStack() as stack:
        stack.enter_context(patch.object(tk.Tk, "__init__", hidden_init))
        stack.enter_context(patch.object(app.WireGuardManager, "load_config", return_value=config))
        stack.enter_context(patch.object(app.DependencyManager, "is_all_satisfied", return_value=True))
        stack.enter_context(patch.object(app.ServerCacheManager, "load", return_value=(None, [])))
        stack.enter_context(patch.object(app.ServerCacheManager, "save"))
        for method in ("_setup_tray_icon", "_refresh_wireguard_status", "_auto_start_scan_and_key", "_position_at_system_tray"):
            stack.enter_context(patch.object(app.FreetonVPNApp, method))
        stack.enter_context(patch.object(app.FreetonVPNApp, "_check_login_status", return_value=True))
        root = app.FreetonVPNApp()
        try:
            root.tray_icon = MagicMock()
            root._check_wireguard_status()
            assert "CHƯA BẬT" in root.lbl_toggle_status.cget("text")
            root._tunnel_running = True
            root._tunnel_verified = False
            root._check_wireguard_status()
            assert "CHƯA XÁC MINH" in root.lbl_toggle_status.cget("text")
            root._tunnel_verified = True
            root._check_wireguard_status()
            assert "ĐÃ KẾT NỐI" in root.lbl_toggle_status.cget("text")
            root.update_idletasks()
            # Exercise cancelled transitions and reduced motion without networking.
            root.wg_config["animations_enabled"] = True
            with patch.object(root, "winfo_viewable", return_value=True):
                root.show_drawer_view()
                root.show_home_view()
                until = time.monotonic() + 0.3
                while time.monotonic() < until:
                    root.update()
                    time.sleep(0.01)
            assert root.home_frame.winfo_manager() == "place"
            assert root.drawer_frame.winfo_manager() == ""
            assert root._view_animation_job is None
            root.btn_settings._on_enter()
            root.wg_config["animations_enabled"] = False
            root.btn_settings._on_leave()
            assert root.btn_settings._hover_amount == 0
            assert root.btn_settings._hover_job is None
            root.ios_toggle.set_state(True, animate=True)
            assert root.ios_toggle.current_knob_x == root.ios_toggle.target_knob_x
            print("Windows GUI smoke passed: disconnected, unverified, verified, timer, widgets.")
        finally:
            root.destroy()


if __name__ == "__main__":
    main()
