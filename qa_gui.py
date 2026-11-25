"""Isolated GUI performance/preview harness: no credentials, VPN or network."""
from contextlib import ExitStack
from unittest.mock import patch
import json
import sys
import time

import proton_warp_material_gui as app


def main():
    preview = "--preview" in sys.argv
    if preview and sys.platform == "win32":
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FreetonVPN.UIPreview")
    config = {"private_key": "", "animations_enabled": True, "auto_check_update": False}
    servers = [dict(name=f"{country}-FREE#{i + 1:03}", country=country,
                    city="", load=(i * 7) % 100, pingMs=22 + i % 170,
                    domain=f"demo-{i}.invalid")
               for i, country in enumerate(["SG", "JP", "US", "NL", "RO"] * 60)]
    with ExitStack() as stack:
        stack.enter_context(patch.object(app.WireGuardManager, "load_config", return_value=config))
        stack.enter_context(patch.object(app.DependencyManager, "is_all_satisfied", return_value=True))
        stack.enter_context(patch.object(app.ServerCacheManager, "load", return_value=(None, servers)))
        stack.enter_context(patch.object(app.ServerCacheManager, "save"))
        for method in ("_setup_tray_icon", "_refresh_wireguard_status", "_auto_start_scan_and_key",
                       "_position_at_system_tray", "_on_focus_out", "update_tray_icon_status",
                       "_connect_to_server", "_on_toggle_clicked", "_logout", "_on_refresh_clicked"):
            stack.enter_context(patch.object(app.FreetonVPNApp, method))
        stack.enter_context(patch.object(app.FreetonVPNApp, "_check_login_status", return_value=True))
        root = app.FreetonVPNApp()
        if preview:
            root.overrideredirect(False)
        root.title("Freeton VPN — UI preview (dữ liệu mẫu)")
        root.geometry("390x610+700+180")
        errors = []
        root.report_callback_exception = lambda *exc: errors.append(str(exc[1]))
        root.bind("<Escape>", lambda e: root.destroy())
        root.update()
        if preview:
            root.mainloop()
            return
        intervals = []
        last = time.perf_counter()

        def heartbeat():
            nonlocal last
            now = time.perf_counter()
            intervals.append((now - last) * 1000)
            last = now
            root.after(8, heartbeat)

        heartbeat()
        started = time.perf_counter()
        root.show_drawer_view()
        open_ms = (time.perf_counter() - started) * 1000
        until = time.perf_counter() + 2
        while time.perf_counter() < until:
            root.update()
            time.sleep(.001)
        initial_rows = len(root.server_rows.servers)
        assert initial_rows == 300, initial_rows
        assert len(root.server_rows.find_all()) < 100
        assert len(root.scrollable_frame.winfo_children()) == 1
        print(json.dumps(dict(servers=len(servers), open_call_ms=round(open_ms, 1),
                              max_event_gap_ms=round(max(intervals), 1),
                              p95_event_gap_ms=round(sorted(intervals)[int(len(intervals) * .95)], 1),
                              initial_rows=initial_rows, errors=errors)))
        # Rapid filtering/navigation must retain only current data and bounded canvas items.
        def pump(seconds):
            until = time.perf_counter() + seconds
            while time.perf_counter() < until:
                root.update()
                time.sleep(.001)

        root._select_country("SG")
        root._select_country("JP")
        root.show_home_view()
        pump(.3)
        root.show_drawer_view()
        pump(.9)
        assert len(root.server_rows.servers) == 60
        assert all(s["country"] == "JP" for s in root.server_rows.servers)
        root._on_mousewheel(type("Wheel", (), {"delta": -120})())
        pump(.2)
        assert root.canvas.yview()[0] > 0
        root.var_search.set("SG-")
        root.var_search.set("not-a-real-server")
        pump(.3)
        assert not root.server_rows.servers
        assert len(root.server_rows.find_all()) == 1
        assert root._scroll_job is None
        root.var_search.set("")
        pump(.6)
        root.wg_config["animations_enabled"] = False
        root.show_home_view()
        root.show_drawer_view()
        assert root._view_animation_job is None
        assert root.drawer_frame.winfo_x() == 0
        # Canvas hit testing must preserve connect/export targets after scrolling.
        rows = root.server_rows
        with patch.object(root, "_select_and_connect_server") as connect, patch.object(root, "_export_specific_conf") as export:
            rows._click(type("Click", (), {"x": 20, "y": 20})())
            connect.assert_called_once_with(rows.best)
            connect.reset_mock()
            row_y = rows.LIST_TOP + 12 * rows.ROW_HEIGHT
            rows._click(type("Click", (), {"x": 20, "y": row_y + 16})())
            connect.assert_called_once_with(rows.servers[12])
            root.is_debug_mode = True
            rows._click(type("Click", (), {"x": rows.winfo_width() - 20, "y": row_y + 38})())
            export.assert_called_once_with(rows.servers[12])
        root.canvas.yview_moveto(1)
        pump(.1)
        assert len(rows.find_all()) < 100
        assert any(rows.itemcget(item, "text").startswith(rows.servers[-1]["name"])
                   for item in rows.find_all() if rows.type(item) == "text")
        assert not errors, errors
        print("Passed: full list, virtualized rows and filter replacement, rapid navigation, search debounce, smooth scroll, reduced motion.")
        root.destroy()
        assert not errors, errors


if __name__ == "__main__":
    main()
