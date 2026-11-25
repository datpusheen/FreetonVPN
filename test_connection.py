"""Connection regressions: all network, credentials and service mutations are mocked."""

import socket
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import proton_warp_material_gui as app
import windows_vpn as vpn


class HealthChecks(unittest.TestCase):
    def test_handshake_requires_expected_peer_and_nonzero_timestamp(self):
        result = SimpleNamespace(returncode=0, stdout="other\t9999999999\nexpected\t0\nbad line extra\n")
        with patch.object(vpn.subprocess, "run", return_value=result) as run:
            self.assertEqual(vpn.latest_handshake("wg.exe", "test", "expected"), 0)
            self.assertEqual(run.call_args.args[0], ["wg.exe", "show", "test", "latest-handshakes"])
            self.assertEqual(run.call_args.kwargs["timeout"], 2)

    def test_handshake_read_failure_is_not_connected(self):
        with patch.object(vpn.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(RuntimeError, "Administrator"):
                vpn.latest_handshake("wg.exe", "test")

    def test_dns_binds_to_vpn_address_and_checks_response(self):
        sock = MagicMock()
        sock.recv.return_value = struct.pack("!6H", 42, 0x8180, 1, 1, 0, 0)
        with patch.object(vpn.socket, "socket") as create, patch.object(vpn.secrets, "randbits", return_value=42):
            create.return_value.__enter__.return_value = sock
            self.assertTrue(vpn.dns_responds_through_tunnel("10.2.0.2/32", "10.2.0.1"))
            sock.bind.assert_called_once_with(("10.2.0.2", 0))
            sock.connect.assert_called_once_with(("10.2.0.1", 53))
            # A response from another query or a resolver error cannot verify a tunnel.
            for ident, flags, answers in [(43, 0x8180, 1), (42, 0x8182, 0), (42, 0x8380, 1), (42, 0x0100, 1)]:
                sock.recv.return_value = struct.pack("!6H", ident, flags, 1, answers, 0, 0)
                self.assertFalse(vpn.dns_responds_through_tunnel("10.2.0.2/32", "10.2.0.1"))

    def test_dns_failure_never_falls_back_to_physical_adapter(self):
        with patch.object(vpn.socket, "socket") as create:
            create.return_value.__enter__.return_value.bind.side_effect = OSError("missing adapter")
            self.assertFalse(vpn.dns_responds_through_tunnel("10.2.0.2/32", "10.2.0.1"))
            create.return_value.__enter__.return_value.send.assert_not_called()

    def test_dns_tries_configured_secondary_resolver(self):
        sock = MagicMock()
        sock.recv.side_effect = [socket.timeout(), struct.pack("!6H", 42, 0x8180, 1, 1, 0, 0)]
        with patch.object(vpn.socket, "socket") as create, patch.object(vpn.secrets, "randbits", return_value=42):
            create.return_value.__enter__.return_value = sock
            self.assertTrue(vpn.dns_responds_through_tunnel("10.2.0.2/32", "10.2.0.1, 1.1.1.1"))
            self.assertEqual(sock.connect.call_args.args, (("1.1.1.1", 53),))


class TunnelLifecycle(unittest.TestCase):
    def setUp(self):
        self.manager = app.WireGuardManager
        self.server = {"name": "test", "entryIP": "192.0.2.1", "x25519PublicKey": "peer"}
        self.config = {"private_key": "test-key", "expiration": 0, "address": "10.2.0.2/32", "dns": "10.2.0.1"}
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.conf"
        for target, kwargs in [
            ("find_wg_cli", {"return_value": "wg.exe"}),
            ("latest_handshake", {"return_value": int(time.time())}),
            ("dns_responds_through_tunnel", {"return_value": True}),
        ]:
            mock = patch.object(app, target, **kwargs)
            setattr(self, target, mock.start())
            self.addCleanup(mock.stop)
        for target, kwargs in [
            ("find_wireguard_exe", {"return_value": "wireguard.exe"}),
            ("get_tunnel_conf_path", {"return_value": self.path}),
            ("run_wireguard_command", {}),
            ("is_service_existing", {"return_value": False}),
            ("is_tunnel_running", {"return_value": True}),
            ("wait_for_service", {}),
        ]:
            mock = patch.object(self.manager, target, **kwargs)
            setattr(self, target, mock.start())
            self.addCleanup(mock.stop)

    def test_success_requires_handshake_and_dns(self):
        self.manager.connect_tunnel(self.server, self.config, "test")
        self.assertTrue(self.path.exists())
        self.latest_handshake.assert_called_once_with("wg.exe", "test", "peer")
        self.dns_responds_through_tunnel.assert_called_once()

    def test_running_service_without_handshake_times_out(self):
        self.latest_handshake.return_value = 0
        with patch.object(app.time, "monotonic", side_effect=[0, 0, 2]), patch.object(app.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "chưa phản hồi handshake"):
                self.manager.wait_for_connection(self.server, self.config, "test", timeout=1)
        self.dns_responds_through_tunnel.assert_not_called()

    def test_handshake_with_broken_dns_is_not_success(self):
        self.dns_responds_through_tunnel.return_value = False
        with patch.object(app.time, "monotonic", side_effect=[0, 0, 0, 2]), patch.object(app.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "DNS qua VPN chưa phản hồi"):
                self.manager.wait_for_connection(self.server, self.config, "test", timeout=1)

    def test_wait_retries_while_ipc_is_starting(self):
        self.latest_handshake.side_effect = [RuntimeError("IPC starting"), int(time.time())]
        with patch.object(app.time, "sleep"):
            self.manager.wait_for_connection(self.server, self.config, "test")
        self.assertEqual(self.latest_handshake.call_count, 2)

    def test_failed_connection_removes_tunnel_and_config(self):
        self.is_service_existing.side_effect = [False, True]
        with patch.object(self.manager, "wait_for_connection", side_effect=RuntimeError("no handshake")):
            with self.assertRaisesRegex(RuntimeError, "no handshake"):
                self.manager.connect_tunnel(self.server, self.config, "test")
        self.assertFalse(self.path.exists())
        self.assertEqual(self.run_wireguard_command.call_args.args[0], ["/uninstalltunnelservice", "test"])

    def test_switch_waits_for_old_service_to_be_removed(self):
        self.is_service_existing.return_value = True
        events = []
        self.run_wireguard_command.side_effect = lambda args: events.append(args[0])
        self.wait_for_service.side_effect = lambda name, state: events.append(state)
        self.manager.connect_tunnel(self.server, self.config, "test")
        self.assertEqual(events, ["/uninstalltunnelservice", 0, "/installtunnelservice", vpn.SERVICE_RUNNING])

    def test_uninstall_failure_retains_configuration_and_propagates(self):
        self.path.write_text("keep this configuration")
        self.is_service_existing.return_value = True
        self.run_wireguard_command.side_effect = RuntimeError("access denied")
        with self.assertRaisesRegex(RuntimeError, "access denied"):
            self.manager.disconnect_tunnel("test")
        self.assertTrue(self.path.exists())

    def test_invalid_config_does_not_disconnect_working_tunnel(self):
        with self.assertRaises(ValueError):
            self.manager.connect_tunnel({**self.server, "x25519PublicKey": ""}, self.config, "test")
        self.run_wireguard_command.assert_not_called()

    def test_missing_cli_does_not_disconnect_working_tunnel(self):
        self.find_wg_cli.side_effect = RuntimeError("missing wg.exe")
        with self.assertRaisesRegex(RuntimeError, "missing wg.exe"):
            self.manager.connect_tunnel(self.server, self.config, "test")
        self.run_wireguard_command.assert_not_called()

    def test_service_wait_uses_state_not_fixed_delay(self):
        self.wait_for_service.side_effect = None
        # Exercise the actual method separately from the lifecycle fixture mock.
        with patch.object(app, "service_state", return_value=0), patch.object(app.time, "sleep") as sleep:
            ORIGINAL_WAIT("test", 0)
        sleep.assert_not_called()

    def test_service_deletion_timeout_is_visible(self):
        with patch.object(app, "service_state", return_value=4), patch.object(app.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(RuntimeError):
                ORIGINAL_WAIT("test", 0)


ORIGINAL_WAIT = app.WireGuardManager.wait_for_service


class UIRegressions(unittest.TestCase):
    def test_animation_and_timer_never_query_windows_services(self):
        ui = MagicMock()
        ui.anim_running = True
        ui.wg_config = {"animations_enabled": True}
        ui.current_view = "main"
        ui.anim_step = 0
        ui.is_connecting_vpn = False
        ui._tunnel_running = ui._tunnel_verified = True
        ui.vpn_connect_time = 900
        ui._last_timer_text = None
        ui._update_session_timer = lambda: app.FreetonVPNApp._update_session_timer(ui)
        with patch.object(app.WireGuardManager, "is_tunnel_running", side_effect=AssertionError("UI blocked")), patch.object(app.time, "time", return_value=1000):
            app.FreetonVPNApp._start_animation_loop(ui)
            tick = ui.after.call_args.args[1]
            for _ in range(10):
                tick()
        ui.hero_timer_pill.config.assert_called_once()

    def test_repeated_connect_or_server_click_does_not_start_another_worker(self):
        ui = MagicMock()
        ui.is_connecting_vpn = True
        with patch.object(app.threading, "Thread") as thread:
            app.FreetonVPNApp._connect_to_server(ui, {})
            app.FreetonVPNApp._select_and_connect_server(ui, {})
        thread.assert_not_called()
        ui._update_home_server_card.assert_not_called()

    def test_disconnect_sets_busy_before_worker_starts(self):
        ui = MagicMock()
        ui.is_connecting_vpn = ui._closing = False
        ui._connection_generation = 1
        with patch.object(app.threading, "Thread") as thread:
            app.FreetonVPNApp._disconnect_vpn(ui)
            app.FreetonVPNApp._disconnect_vpn(ui)
        self.assertTrue(ui.is_connecting_vpn)
        self.assertEqual(ui._connection_generation, 2)
        self.assertEqual(thread.call_count, 1)

    def test_stale_health_result_cannot_overwrite_new_connection(self):
        ui = MagicMock()
        ui.is_connecting_vpn = ui._closing = ui._status_check_pending = False
        ui._tunnel_running = ui._tunnel_verified = True
        ui._connection_generation = 1
        ui.wg_config = {}
        ui.connected_server = {}
        with patch.object(app.WireGuardManager, "is_tunnel_running", return_value=False), patch.object(app.threading, "Thread") as thread:
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            app.FreetonVPNApp._refresh_wireguard_status(ui)
        ui._connection_generation = 2
        ui.after.call_args.args[1]()
        self.assertTrue(ui._tunnel_running)
        ui._check_wireguard_status.assert_not_called()

    def test_scan_does_not_replace_manual_selection_during_connect(self):
        ui = MagicMock()
        ui._closing = False
        ui.is_connecting_vpn = True
        ui.selected_server = {"name": "manual"}
        ui.current_view = "main"
        with patch.object(app.ServerCacheManager, "save"):
            app.FreetonVPNApp._finish_scan(ui, {}, [{"name": "fastest"}, {"name": "manual", "pingMs": 50}])
        self.assertEqual(ui.selected_server["name"], "manual")
        ui._pick_best_server_as_selected.assert_not_called()
        ui._hide_loading_with_delay.assert_not_called()

    def test_zero_load_is_better_than_fifty_percent(self):
        ui = MagicMock()
        ui.all_free_servers = [{"name": "loaded", "pingMs": 20, "load": 50}, {"name": "empty", "pingMs": 20, "load": 0}]
        app.FreetonVPNApp._pick_best_server_as_selected(ui)
        self.assertEqual(ui.selected_server["name"], "empty")


if __name__ == "__main__":
    unittest.main()
