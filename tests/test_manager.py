import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

BASE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("xbnode", BASE / "xbnode.py")
xb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xb)
REAL_RELEASE_BUNDLE = xb.release_bundle

TOKEN = "synthetic-secret-$-`-\\-\"-not-production"
PROFILE = {"url": "https://panel.example.com", "token": TOKEN}
RAW = {"protocol": "vless", "server_port": 30000, "tls": 2,
       "tls_settings": {"private_key": "SYNTHETIC", "server_name": "target.example.com"}}


def manifest(release="v0.1.0"):
    return {"release": release, "node_version": "v1.13-maint-20261023", "upstream_commit": "a" * 40,
            "config_schema": 1, "manager_schema": 1,
            "features": ["device_snapshot_refresh_v1", "local_cert_override_v1"],
            "maintenance_patches": [{"file": "test.patch", "sha256": "a" * 64}]}


class UI:
    def __init__(self, *answers):
        self.answers = list(answers)

    def ask(self, *args, **kwargs):
        if not self.answers:
            raise AssertionError("Unexpected interactive question")
        return self.answers.pop(0)

    def confirm(self, *args):
        return True


class ValidationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd unit parser is available on Linux CI")
    def test_generated_unit_passes_real_systemd_parser(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(xb, "ROOT", root / "etc"), patch.object(xb, "LIB", root / "lib"):
                binary = xb.LIB / "releases/v0.1.0/xboard-node"
                binary.parent.mkdir(parents=True)
                binary.write_text("#!/bin/sh\nexit 0\n")
                binary.chmod(0o755)
                for mode in ("none", "file", "http"):
                    unit = root / "xbnode-41.service"
                    unit.write_text(xb.make_unit(41, "v0.1.0", xb.node_spec(RAW), {"cert_mode": mode}))
                    result = subprocess.run(["systemd-analyze", "verify", "--man=no", str(unit)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_seven_protocols_and_kernels(self):
        for proto in xb.PROTOCOLS:
            with self.subTest(protocol=proto):
                raw = {"protocol": proto, "server_port": "30000", "version": 2}
                node = xb.node_spec(raw)
                self.assertEqual(node["protocol"], proto)
                self.assertEqual(node["kernel"], "singbox" if proto in ("hysteria", "tuic", "anytls") else "xray")
        self.assertEqual(xb.node_spec({"protocol": "hysteria2", "server_port": 30001})["protocol"], "hysteria")

    def test_reality_needs_keys_and_valid_protocol(self):
        self.assertFalse(xb.node_spec(RAW)["needs_cert"])
        for raw in [dict(RAW, tls_settings={}), dict(RAW, protocol="tuic"), dict(RAW, server_port=0)]:
            with self.assertRaises(xb.Error):
                xb.node_spec(raw)

    def test_unsupported_and_conflicting_panel_kernel_stop(self):
        for raw in [dict(RAW, protocol="madeup"), dict(RAW, kernel_type="singbox"), {"protocol": "hysteria", "version": 1, "server_port": 10}]:
            with self.assertRaises(xb.Error):
                xb.node_spec(raw)

    def test_url_rejects_credentials_query_and_paths(self):
        self.assertEqual(xb.check_url("https://panel.example.com/"), "https://panel.example.com")
        for url in ["http://panel.example.com", "https://u:p@panel.example.com", "https://panel.example.com/#/admin", "https://panel.example.com?token=x", "https://panel.example.com/admin", "https://panel.example.com:bad"]:
            with self.assertRaises(xb.Error):
                xb.check_url(url)

    def test_paths_ids_versions_and_repositories_cannot_inject(self):
        for bad in ["0", "-1", "1/../../x", "1; id", "1\n2", "01"]:
            with self.assertRaises(xb.Error):
                xb.check_id(bad)
        for bad in ["latest", "../../a", "v1;id", "v1.2.3/../../a"]:
            with self.assertRaises(xb.Error):
                xb.check_release(bad)
        for bad in ["a/b/c", "https://github.com/a/b", "a/b?x", "a/b;id"]:
            with self.assertRaises(xb.Error):
                xb.check_repo(bad)

    def test_token_roundtrip_has_no_shell_interpolation(self):
        text = xb.env_text(TOKEN)
        self.assertEqual(json.loads(text.split("=", 1)[1]), TOKEN)
        for token in ["", "abc\nDEF", "has space", "bad\x00value"]:
            with self.assertRaises(xb.Error):
                xb.env_text(token)

    def test_architectures(self):
        self.assertEqual(xb.architecture("x86_64"), "amd64")
        self.assertEqual(xb.architecture("aarch64"), "arm64")
        with self.assertRaises(xb.Error):
            xb.architecture("i686")

    def test_checksums_reject_tampering_duplicates_and_path_traversal(self):
        digest = hashlib.sha256(b"safe").hexdigest()
        hashes = xb.checksum_table((digest + "  xbnode.py\n").encode())
        self.assertEqual(xb.verified(b"safe", "xbnode.py", hashes), b"safe")
        with self.assertRaises(xb.Error):
            xb.verified(b"tampered", "xbnode.py", hashes)
        for data in [(digest + "  ../file\n").encode(), ((digest + "  same\n") * 2).encode(), b"\xff"]:
            with self.assertRaises(xb.Error):
                xb.checksum_table(data)

    def test_release_requires_patch_features_and_schema(self):
        self.assertEqual(xb.validate_manifest(manifest(), "v0.1.0")["release"], "v0.1.0")
        for change in [{"release": "v9.0.0"}, {"features": []}, {"config_schema": 2}, {"manager_schema": 2}, {"maintenance_patches": []}]:
            with self.assertRaises(xb.Error):
                xb.validate_manifest(dict(manifest(), **change), "v0.1.0")

    def test_socket_check_is_protocol_and_process_specific(self):
        output = 'tcp LISTEN 0 4096 [::]:30000 [::]:* users:(("node",pid=812,fd=8))\n'
        output += 'udp UNCONN 0 0 0.0.0.0:30001 0.0.0.0:* users:(("node",pid=900,fd=4))\n'
        self.assertEqual(xb.parse_sockets(output, 30000, "tcp", 812), {"tcp"})
        self.assertEqual(xb.parse_sockets(output, 30000, "tcp", 81), set())
        self.assertEqual(xb.parse_sockets(output, 30001, "tcp"), set())
        self.assertEqual(xb.parse_sockets(output, 30001, "udp", 900), {"udp"})

    def test_unit_keeps_secret_out_of_arguments_and_root_paths(self):
        node = xb.node_spec(RAW)
        cfg = xb.make_config(41, PROFILE, node, {"cert_mode": "none"})
        unit = xb.make_unit(41, "v0.1.0", node, {"cert_mode": "none"})
        self.assertNotIn(TOKEN, json.dumps(cfg) + unit)
        self.assertTrue(cfg["cert"]["prefer_local"])
        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("LoadCredential=node.json:", unit)
        self.assertIn("-c %d/node.json", unit)
        self.assertIn("CapabilityBoundingSet=\n", unit)
        self.assertEqual(cfg["health_port"], 0)
        low = xb.make_unit(41, "v0.1.0", dict(node, port=443), {"cert_mode": "none"})
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", low)

    def test_transport_exception_never_exposes_authenticated_url(self):
        with patch.object(xb.urllib.request.OpenerDirector, "open", side_effect=urllib.error.URLError("https://panel.example.com?token=" + TOKEN)):
            with self.assertRaises(xb.Error) as error:
                xb.panel_read(PROFILE, 41, "config")
        self.assertNotIn(TOKEN, str(error.exception))
        self.assertNotIn("token=", str(error.exception))

    def test_panel_read_is_read_only_and_does_not_follow_redirect(self):
        with patch.object(xb, "get_bytes", return_value=b'{"users":[]}') as get:
            xb.panel_read(PROFILE, 41, "user")
        self.assertIn("/api/v2/server/user?", get.call_args.args[0])
        self.assertTrue(get.call_args.kwargs["panel"])
        with self.assertRaises(xb.Error):
            xb.panel_read(PROFILE, 41, "report")
        with self.assertRaises(xb.Error):
            xb.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example.com")

    def test_ready_accepts_websocket_and_rest_but_requires_owned_listener(self):
        for message in ["initial snapshot ready users=1", "xray started users=1", "[node] started, 1 users"]:
            def fake(*args, **kwargs):
                out = ""
                if args[0] == "systemctl":
                    out = "MainPID=123\nActiveState=active\nNRestarts=0\n"
                elif args[0] == "ss":
                    out = 'tcp LISTEN 0 10 *:30000 *:* users:(("node",pid=123,fd=1))'
                else:
                    out = message
                return subprocess.CompletedProcess(args, 0, out, "")
            with patch.object(xb, "command", side_effect=fake):
                xb.wait_ready(41, xb.node_spec(RAW), 1, timeout=1)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        for name, path in {"ROOT": base / "etc", "LIB": base / "lib", "UNITS": base / "units", "COMMAND": base / "bin/xbnode"}.items():
            self.stack.enter_context(patch.object(xb, name, path))
        xb.ROOT.mkdir(mode=0o700)
        xb.UNITS.mkdir()
        self.states = set()
        self.commands = []
        self.manager = xb.Manager("owner/repo", release="v0.1.0", terminal=UI("41", "42"))
        self.stack.enter_context(patch.object(self.manager, "choose_profile", return_value=("synthetic", PROFILE)))
        self.stack.enter_context(patch.object(xb, "command", side_effect=self.fake_command))
        self.stack.enter_context(patch.object(xb, "wait_ready"))
        self.stack.enter_context(patch.object(xb, "release_bundle", side_effect=self.fake_release))
        self.stack.enter_context(patch.object(xb, "panel_read", side_effect=self.fake_panel))

    def fake_command(self, *args, **kwargs):
        self.commands.append(args)
        code = 0
        if args[:2] == ("systemctl", "is-active"):
            code = 0 if args[-1] in self.states else 3
        if args[0] == "systemctl" and args[1] in ("start", "restart", "enable"):
            self.states.add(args[-1])
        if args[0] == "systemctl" and args[1] in ("stop", "disable"):
            self.states.discard(args[-1])
        return subprocess.CompletedProcess(args, code, "", "")

    def fake_release(self, repo, release):
        directory = xb.LIB / "releases" / release
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "xboard-node").write_text("synthetic binary")
        return manifest(release)

    def fake_panel(self, profile, node_id, resource):
        if resource == "user":
            return {"users": [{"id": 901}]}
        return dict(RAW, server_port=30000 + int(node_id) - 41)

    def test_two_nodes_install_independently_and_do_not_touch_existing_xrayr(self):
        self.manager.add()
        first_unit = (xb.UNITS / "xbnode-41.service").read_bytes()
        self.manager.add()
        self.assertEqual((xb.UNITS / "xbnode-41.service").read_bytes(), first_unit)
        self.assertEqual(self.states, {"xbnode-41.service", "xbnode-42.service"})
        self.assertFalse(any("XrayR" in str(c) or "xboard-node-36" in str(c) for c in self.commands))
        self.assertEqual((xb.node_dir(41) / "credentials.env").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(TOKEN, json.dumps(self.commands))
        with self.assertRaises(xb.Error):
            self.manager.terminal = UI("41")
            self.manager.add()

    def test_menu_can_continue_adding_then_return_without_nested_locks(self):
        self.manager.terminal = UI("1", "41", "42", "0")
        locked = False

        @contextlib.contextmanager
        def lock():
            nonlocal locked
            self.assertFalse(locked, "the menu must not nest the add lock")
            locked = True
            try:
                yield
            finally:
                locked = False

        def confirm(text):
            if text.startswith("安装节点"):
                self.assertTrue(locked)
                return True
            self.assertFalse(locked, "continuation must not hold the mutation lock")
            return not xb.node_dir(42).exists()

        self.manager.terminal.confirm = confirm
        with patch.object(xb, "mutation_lock", lock):
            self.manager.menu()
        self.assertEqual(self.states, {"xbnode-41.service", "xbnode-42.service"})
        self.assertEqual(self.manager.terminal.answers, [])

    def test_add_command_offers_continuation_and_can_finish_after_one_node(self):
        xb.write_json(xb.ROOT / "settings.json", {"repo": "owner/repo"})
        with patch.object(sys, "argv", ["xbnode", "add"]), \
                patch.object(xb, "require_host"), \
                patch.object(xb, "Manager", return_value=self.manager), \
                patch.object(xb, "mutation_lock", contextlib.nullcontext), \
                patch.object(self.manager.terminal, "confirm", side_effect=[True, False]) as confirm:
            xb.main()
        self.assertIn("继续", confirm.call_args.args[0])
        self.assertEqual(self.states, {"xbnode-41.service"})
        self.assertFalse(xb.node_dir(42).exists())

    def test_cancelled_install_does_not_offer_continuation(self):
        with patch.object(xb, "mutation_lock", contextlib.nullcontext), \
                patch.object(self.manager.terminal, "confirm", return_value=False) as confirm:
            self.manager.add_interactive()
        self.assertEqual(confirm.call_count, 1)
        self.assertFalse(self.states)
        self.assertFalse(xb.node_dir(41).exists())

    def test_second_add_failure_preserves_the_first_node(self):
        self.manager.terminal = UI("41", "41")
        with patch.object(xb, "mutation_lock", contextlib.nullcontext):
            with self.assertRaisesRegex(xb.Error, "已存在"):
                self.manager.add_interactive()
        self.assertEqual(self.states, {"xbnode-41.service"})
        self.assertTrue(xb.read_json(xb.node_dir(41) / "node.json")["last_ready"])

    def test_ending_terminal_at_continuation_keeps_successful_node(self):
        for end in (xb.Error("终端输入已结束。"), KeyboardInterrupt()):
            with self.subTest(end=type(end).__name__), \
                    patch.object(self.manager, "add", return_value=True) as add, \
                    patch.object(xb, "mutation_lock", contextlib.nullcontext), \
                    patch.object(self.manager.terminal, "confirm", side_effect=end), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.manager.add_interactive()
                add.assert_called_once()
                self.assertIn("已安装的节点保持运行", output.getvalue())

    def test_continuation_confirmation_defaults_to_no(self):
        terminal = xb.Terminal.__new__(xb.Terminal)
        with patch.object(terminal, "ask", side_effect=lambda text, default: default) as ask:
            self.assertFalse(terminal.confirm("继续添加"))
        self.assertEqual(ask.call_args.args[1], "no")

    def test_failed_update_rolls_back_config_unit_and_running_state(self):
        self.manager.add()
        directory = xb.node_dir(41)
        before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
        calls = 0
        def health(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise xb.Error("synthetic startup failure")
        with patch.object(xb, "wait_ready", side_effect=health):
            with self.assertRaisesRegex(xb.Error, "已恢复"):
                self.manager.update(41, "v0.2.0")
        for name, contents in before.items():
            self.assertEqual((directory / name).read_bytes(), contents)
        self.assertEqual(xb.read_json(directory / "node.json")["release"], "v0.1.0")
        self.assertIn("xbnode-41.service", self.states)
        self.assertEqual(calls, 2)

    def test_successful_update_is_per_node_and_manual_rollback_works(self):
        self.manager.add()
        self.manager.add()
        second = (xb.UNITS / "xbnode-42.service").read_bytes()
        self.manager.update(41, "v0.2.0")
        self.assertIn(b"v0.2.0", (xb.UNITS / "xbnode-41.service").read_bytes())
        self.assertEqual((xb.UNITS / "xbnode-42.service").read_bytes(), second)
        self.manager.rollback(41)
        self.assertEqual(xb.read_json(xb.node_dir(41) / "node.json")["release"], "v0.1.0")

    def test_failed_manual_rollback_restores_version_before_attempt(self):
        self.manager.add()
        self.manager.update(41, "v0.2.0")
        with patch.object(xb, "wait_ready", side_effect=[xb.Error("old no longer works"), None]):
            with self.assertRaisesRegex(xb.Error, "恢复回退操作前"):
                self.manager.rollback(41)
        self.assertEqual(xb.read_json(xb.node_dir(41) / "node.json")["release"], "v0.2.0")

    def test_updating_stopped_node_preserves_stopped_state(self):
        self.manager.add()
        self.manager.control("stop", 41)
        self.manager.update(41, "v0.2.0")
        self.assertNotIn("xbnode-41.service", self.states)

    def test_interrupted_update_restores_previous_version(self):
        self.manager.add()
        with patch.object(xb, "wait_ready", side_effect=[KeyboardInterrupt(), None]):
            with self.assertRaisesRegex(xb.Error, "已恢复"):
                self.manager.update(41, "v0.2.0")
        self.assertEqual(xb.read_json(xb.node_dir(41) / "node.json")["release"], "v0.1.0")

    def test_uninstall_keeps_config_and_can_restore(self):
        self.manager.add()
        original = (xb.node_dir(41) / "credentials.env").read_bytes()
        self.manager.uninstall(41)
        self.assertFalse((xb.UNITS / "xbnode-41.service").exists())
        self.assertEqual((xb.node_dir(41) / "credentials.env").read_bytes(), original)
        self.assertFalse(xb.read_json(xb.node_dir(41) / "node.json")["installed"])
        self.manager.restore(41)
        self.assertTrue(xb.read_json(xb.node_dir(41) / "node.json")["installed"])

    def test_connection_failure_restores_original_credentials(self):
        self.manager.add()
        before = (xb.node_dir(41) / "credentials.env").read_bytes()
        with patch.object(self.manager, "choose_profile", return_value=("new", {"url": PROFILE["url"], "token": "NEW_SYNTHETIC_SECRET"})):
            with patch.object(xb, "wait_ready", side_effect=[xb.Error("fail"), None]):
                with self.assertRaisesRegex(xb.Error, "恢复原连接"):
                    self.manager.connection(41)
        self.assertEqual((xb.node_dir(41) / "credentials.env").read_bytes(), before)

    def test_no_users_and_port_conflict_stop_before_install(self):
        with patch.object(xb, "users_count", return_value=0):
            with self.assertRaisesRegex(xb.Error, "用户为 0"):
                self.manager.add()
        self.assertFalse(xb.node_dir(41).exists())
        with patch.object(xb, "port_free", side_effect=xb.Error("occupied")):
            with self.assertRaisesRegex(xb.Error, "occupied"):
                self.manager.add()
        self.assertFalse(xb.node_dir(42).exists())

    def test_update_all_stops_after_first_failure(self):
        self.manager.add()
        self.manager.add()
        with patch.object(self.manager, "update", side_effect=xb.Error("failed")) as update:
            with self.assertRaises(xb.Error):
                self.manager.update_all("v0.2.0")
        self.assertEqual(update.call_count, 1)

    def test_foreign_backup_and_symlink_are_rejected(self):
        self.manager.add()
        with self.assertRaises(xb.Error):
            xb.restore_snapshot(41, Path(self.temp.name))
        target = Path(self.temp.name) / "outside"
        target.write_text("untouched")
        link = xb.ROOT / "link"
        link.symlink_to(target)
        with self.assertRaises(xb.Error):
            xb.atomic(link, "bad")
        self.assertEqual(target.read_text(), "untouched")

    def test_log_display_redacts_credentials(self):
        xb.write_json(xb.ROOT / "panels/synthetic.json", PROFILE)
        self.manager.add()
        out = io.StringIO()
        result = subprocess.CompletedProcess([], 0, "failure ?token=" + TOKEN + "&node_id=41", "")
        with patch.object(xb, "command", return_value=result), contextlib.redirect_stdout(out):
            self.manager.logs(41)
        self.assertNotIn(TOKEN, out.getvalue())
        self.assertIn("REDACTED", out.getvalue())

    def test_release_directories_remain_executable_under_private_umask(self):
        data = json.dumps(manifest()).encode()
        binary = b"synthetic binary"
        name = "xboard-node-linux-" + xb.architecture()
        hashes = (hashlib.sha256(data).hexdigest() + "  manifest.json\n" + hashlib.sha256(binary).hexdigest() + "  " + name + "\n").encode()
        version = subprocess.CompletedProcess([], 0, "xboard-node v1.13-maint-20261023 (built test)", "")
        with patch.object(xb, "get_bytes", side_effect=[hashes, data, binary]), patch.object(xb, "command", return_value=version):
            REAL_RELEASE_BUNDLE("owner/repo", "v0.1.0")
            for path in [xb.LIB, xb.LIB / "releases", xb.LIB / "releases/v0.1.0"]:
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_certificate_update_rolls_back_when_new_runtime_fails(self):
        with patch.object(xb, "node_spec", return_value={"protocol": "trojan", "label": "Trojan", "kernel": "xray", "port": 30000, "transport": "tcp", "tls": 1, "needs_cert": True}), patch.object(self.manager, "choose_certificate", return_value=({"cert_mode": "file"}, (b"old cert", b"old key"))):
            self.manager.add()
            with patch.object(self.manager, "choose_certificate", return_value=({"cert_mode": "file"}, (b"new cert", b"new key"))), patch.object(xb, "wait_ready", side_effect=[xb.Error("synthetic mismatch"), None]):
                with self.assertRaisesRegex(xb.Error, "恢复更新前"):
                    self.manager.certificate(41)
            self.assertEqual((xb.node_dir(41) / "tls/privkey.pem").read_bytes(), b"old key")

    def test_bad_certificate_pair_is_rejected_before_install(self):
        cert = Path(self.temp.name) / "cert.pem"
        key = Path(self.temp.name) / "key.pem"
        cert.write_text("synthetic cert")
        key.write_text("synthetic wrong key")
        self.manager.terminal = UI("1", str(cert), str(key))
        node = dict(xb.node_spec(RAW), needs_cert=True)
        with patch.object(xb.ssl.SSLContext, "load_cert_chain", side_effect=ssl.SSLError("synthetic mismatch")):
            with self.assertRaisesRegex(xb.Error, "不匹配"):
                self.manager.choose_certificate(41, node, {})
        self.assertFalse(xb.node_dir(41).exists())

    def test_acme_agreement_is_explicit_and_no_ca_is_contacted_by_manager(self):
        self.manager.terminal = UI("2", "node.example.com", "ops@example.com")
        node = dict(xb.node_spec(RAW), needs_cert=True)
        answer = [(2, 1, 6, "", ("203.0.113.5", 80))]
        with patch.object(xb.socket, "getaddrinfo", return_value=answer):
            cert, files = self.manager.choose_certificate(41, node, {})
        self.assertTrue(cert["acme_agreed"])
        self.assertIsNone(files)
        self.manager.terminal = UI("2", "node.example.com", "ops@example.com")
        self.manager.terminal.confirm = lambda *args: False
        with patch.object(xb.socket, "getaddrinfo", return_value=answer):
            with self.assertRaisesRegex(xb.Error, "取消"):
                self.manager.choose_certificate(41, node, {})



if __name__ == "__main__":
    unittest.main()
