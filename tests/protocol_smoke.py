#!/usr/bin/env python3
"""Run ONLY in an isolated Linux container (--network none), synthetic data.

All services, temporary certs, users and traffic exist inside that container.
No production panel, DNS, account, external CA or real customer token is used.
"""
import argparse
import base64
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

USER = {"id": 901, "uuid": "43e50a02-29dd-4d52-b315-d86f3fa14ead", "device_limit": 0, "speed_limit": 0}
definitions = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == "/ok":
            self.reply({"synthetic_proxy_request": True})
            return
        args = urllib.parse.parse_qs(path.query)
        assert args.get("token") == ["synthetic-only-token"]
        if path.path.endswith("/config"):
            self.reply(definitions[int(args["node_id"][0])])
        elif path.path.endswith("/user"):
            self.reply({"users": [USER]})
        else:
            self.send_error(404)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path.endswith("/handshake"):
            self.reply({"websocket": {"enabled": False}, "settings": {"push_interval": 60, "pull_interval": 60}})
        else:
            self.reply({"data": True})


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def listening(port, transport):
    result = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        path = Path("/proc/net") / name
        if path.exists():
            for line in path.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and int(fields[1].split(":")[1], 16) == port:
                    if name.startswith("udp") or fields[3] == "0A":
                        result.add("udp" if name.startswith("udp") else "tcp")
    return ({"tcp", "udp"} if transport == "tcp+udp" else {transport}) <= result


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--client", type=Path)
    args = parser.parse_args()
    # A hard guard prevents accidentally running these network fixtures on a
    # landing host. Docker network=none has loopback and no default route.
    assert Path("/.dockerenv").exists(), "Use an isolated Docker container"
    assert not any(line.split()[1] == "00000000" for line in Path("/proc/net/route").read_text().splitlines()[1:]), "Use --network none"
    results = []
    panel = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=panel.serve_forever, daemon=True).start()
    api_port = panel.server_address[1]
    try:
        with tempfile.TemporaryDirectory(prefix="xbnode-seven-protocols-") as folder:
            root = Path(folder)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            for node_id, (protocol, kernel, transport, tls) in enumerate([
                ("vless", "xray", "tcp", 0), ("vmess", "xray", "tcp", 0),
                ("trojan", "xray", "tcp", 1), ("shadowsocks", "xray", "tcp+udp", 0),
                ("hysteria", "singbox", "udp", 1), ("tuic", "singbox", "udp", 1),
                ("anytls", "singbox", "tcp", 1),
            ], 901):
                port = free_port()
                definition = {"protocol": protocol, "server_port": port, "listen_ip": "127.0.0.1", "network": "tcp", "tls": tls,
                              "flow": "", "version": 2, "cipher": "2022-blake3-aes-128-gcm", "server_key": base64.b64encode(bytes(range(16))).decode(),
                              "tls_settings": {"server_name": "localhost"}, "base_config": {"push_interval": 60, "pull_interval": 60},
                              "cert_config": {"cert_mode": "none"}}
                definitions[node_id] = definition
                runtime = root / protocol
                runtime.mkdir()
                config = {"panel": {"url": f"http://127.0.0.1:{api_port}", "token": "synthetic-only-token", "node_id": node_id, "node_type": protocol},
                          "kernel": {"type": kernel, "config_dir": str(runtime), "log_level": "warn"},
                          "cert": {"prefer_local": True, "cert_mode": "file" if tls else "none", "cert_file": str(cert), "key_file": str(key)},
                          "node": {"push_interval": 60, "pull_interval": 60, "track_interval": 2, "device_report_interval": 30}, "log": {"level": "info"}, "health_port": 0}
                # Loopback routing is permitted ONLY in this synthetic fixture.
                if kernel == "xray":
                    config["kernel"]["custom_route"] = [{"type": "field", "ip": ["127.0.0.1/32"], "outboundTag": "direct"}]
                else:
                    config["kernel"]["custom_route"] = [{"ip_cidr": ["127.0.0.1/32"], "outbound": "direct"}]
                path = runtime / "config.json"
                path.write_text(json.dumps(config))
                client = None
                with (runtime / "server.log").open("w+") as log, (runtime / "client.log").open("w+") as client_log:
                    process = subprocess.Popen([str(args.binary), "-c", str(path)], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 40
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise AssertionError(protocol + " exited: " + (runtime / "server.log").read_text()[-2500:])
                            if listening(port, transport):
                                break
                            time.sleep(0.2)
                        assert listening(port, transport), protocol + " did not listen"
                        result = {"protocol": "hysteria2" if protocol == "hysteria" else protocol, "kernel": kernel, "listener": True, "local_cert_override": bool(tls)}
                        if args.client:
                            http_port = free_port()
                            outbound = {"type": "hysteria2" if protocol == "hysteria" else protocol, "tag": "proxy", "server": "127.0.0.1", "server_port": port}
                            if protocol in ("vless", "vmess", "tuic"):
                                outbound["uuid"] = USER["uuid"]
                            if protocol in ("trojan", "hysteria", "tuic", "anytls"):
                                outbound["password"] = USER["uuid"]
                            if protocol == "vmess":
                                outbound["security"] = "auto"
                            if protocol == "shadowsocks":
                                user_key = base64.b64encode(USER["uuid"].encode()[:16]).decode()
                                outbound.update(method=definition["cipher"], password=definition["server_key"] + ":" + user_key)
                            if tls:
                                outbound["tls"] = {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}
                                if protocol in ("hysteria", "tuic"):
                                    outbound["tls"]["alpn"] = ["h3"]
                            client_cfg = {"log": {"level": "warn"}, "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": http_port}], "outbounds": [outbound], "route": {"final": "proxy"}}
                            client_path = runtime / "client.json"
                            client_path.write_text(json.dumps(client_cfg))
                            client = subprocess.Popen([str(args.client), "run", "-c", str(client_path)], stdout=client_log, stderr=client_log)
                            deadline = time.monotonic() + 15
                            while time.monotonic() < deadline and not listening(http_port, "tcp") and client.poll() is None:
                                time.sleep(0.2)
                            assert client.poll() is None, (runtime / "client.log").read_text()
                            # urllib bypasses proxies for loopback, so send an
                            # absolute-form HTTP request to the proxy manually.
                            with socket.create_connection(("127.0.0.1", http_port), timeout=8) as connection:
                                connection.settimeout(15)
                                connection.sendall(f"GET http://127.0.0.1:{api_port}/ok HTTP/1.1\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n".encode())
                                data = b""
                                while True:
                                    part = connection.recv(8192)
                                    if not part:
                                        break
                                    data += part
                            assert b"200 OK" in data and b"synthetic_proxy_request" in data, protocol + " request failed: " + (runtime / "client.log").read_text()[-1500:] + (runtime / "server.log").read_text()[-1500:]
                            result["synthetic_proxy_request"] = True
                        results.append(result)
                        print(json.dumps(result), flush=True)
                    finally:
                        stop(client)
                        stop(process)
    finally:
        panel.shutdown()
        panel.server_close()
    print(json.dumps({"pass": len(results) == 7, "network_isolated": True, "real_panel_used": False, "protocols": results}), flush=True)


if __name__ == "__main__":
    main()
