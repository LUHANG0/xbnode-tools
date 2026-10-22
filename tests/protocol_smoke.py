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
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

USER = {"id": 901, "uuid": "43e50a02-29dd-4d52-b315-d86f3fa14ead", "device_limit": 1, "speed_limit": 0}
MIDDLE = dict(USER, id=903, uuid="7f7ac9bd-2a2e-4701-87df-bb289c2709e0", device_limit=0)
OTHER = dict(USER, id=902, uuid="0b8fc97d-ab1d-49d2-8a48-69d131fad4ac", device_limit=0)
definitions = {}
user_sets = {}
reported_traffic = {}
hold_started = threading.Event()
hold_release = threading.Event()


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
        if path.path == "/hold":
            # Keep a real proxied stream active while other source IPs try
            # admission. No customer traffic or externally reachable target.
            self.send_response(200)
            self.send_header("Content-Length", "32")
            self.end_headers()
            self.wfile.write(b"held")
            self.wfile.flush()
            hold_started.set()
            hold_release.wait(60)
            try:
                self.wfile.write(b"x" * 28)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        args = urllib.parse.parse_qs(path.query)
        assert args.get("token") == ["synthetic-only-token"]
        if path.path.endswith("/config"):
            self.reply(definitions[int(args["node_id"][0])])
        elif path.path.endswith("/user"):
            self.reply({"users": user_sets[int(args["node_id"][0])]})
        else:
            self.send_error(404)

    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get("Content-Length", 0)))
        parsed=urllib.parse.urlsplit(self.path)
        args=urllib.parse.parse_qs(parsed.query)
        if parsed.path.endswith("/report"):
            for uid,d in json.loads(raw).get("traffic",{}).items():
                old=reported_traffic.get(int(uid),[0,0]);reported_traffic[int(uid)]=[old[0]+d[0],old[1]+d[1]]
        if parsed.path.endswith("/handshake"):
            self.reply({"websocket": {"enabled": False}, "settings": {"push_interval": 5, "pull_interval": 2}})
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


def proxy_request(proxy_port, api_port, path="/ok", keep_open=False, timeout=6):
    connection = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    connection.settimeout(timeout)
    handed_off = False
    try:
        connection.sendall(f"GET http://127.0.0.1:{api_port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{api_port}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            part = connection.recv(8192)
            if not part:
                break
            data += part
            if keep_open and b"held" in data:
                handed_off = True
                return connection, data
        return None, data
    finally:
        if not handed_off:
            connection.close()


def recv_exact(sock,n):
    data=b""
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk:raise OSError("unexpected SOCKS EOF")
        data+=chunk
    return data

def udp_target_request(proxy_port,target_port,timeout=8):
    control=socket.create_connection(("127.0.0.1",proxy_port),timeout=5)
    with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        control.sendall(b"\x05\x01\x00");assert recv_exact(control,2)==b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01"+socket.inet_aton("127.0.0.1")+b"\x00\x00")
        head=recv_exact(control,4);assert head[1]==0,head
        if head[3]==1:host=socket.inet_ntoa(recv_exact(control,4))
        elif head[3]==4:host=socket.inet_ntop(socket.AF_INET6,recv_exact(control,16))
        else:host=recv_exact(control,recv_exact(control,1)[0]).decode()
        port=struct.unpack("!H",recv_exact(control,2))[0]
        if host in ("0.0.0.0","::"):host="127.0.0.1"
        packet=b"\x00\x00\x00\x01"+socket.inet_aton("127.0.0.1")+struct.pack("!H",target_port)+b"synthetic-udp-target"
        udp.settimeout(timeout);udp.sendto(packet,(host,port));data,_=udp.recvfrom(65535)
        assert data.endswith(b"synthetic-udp-target"),data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--client", type=Path)
    parser.add_argument("--only")
    parser.add_argument("--reality", action="store_true")
    parser.add_argument("--namespace", action="store_true", help="isolated unshare network on landing host")
    args = parser.parse_args()
    # A hard guard prevents accidentally running these network fixtures on a
    # landing host. Docker network=none has loopback and no default route.
    assert Path("/.dockerenv").exists() or args.namespace, "Use an isolated Docker container or explicit network namespace"
    assert not any(line.split()[1] == "00000000" for line in Path("/proc/net/route").read_text().splitlines()[1:]), "Use --network none"
    results = []
    panel = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=panel.serve_forever, daemon=True).start()
    api_port = panel.server_address[1]
    echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(("127.0.0.1",0));udp_port=echo.getsockname()[1]
    def echo_packets():
        while True:
            try:data,peer=echo.recvfrom(65535);echo.sendto(data,peer)
            except OSError:return
    threading.Thread(target=echo_packets,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="xbnode-seven-protocols-") as folder:
            root = Path(folder)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
            reality_listener=None
            if args.reality:
                assert args.only=='vless'
                private_file=root/'reality.key'
                subprocess.run(['openssl','genpkey','-algorithm','X25519','-out',str(private_file)],check=True,capture_output=True)
                private_der=subprocess.check_output(['openssl','pkey','-in',str(private_file),'-outform','DER'])
                public_der=subprocess.check_output(['openssl','pkey','-in',str(private_file),'-pubout','-outform','DER'])
                private_key=base64.urlsafe_b64encode(private_der[-32:]).decode().rstrip('=')
                public_key=base64.urlsafe_b64encode(public_der[-32:]).decode().rstrip('=')
                tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls_context.minimum_version=ssl.TLSVersion.TLSv1_3;tls_context.maximum_version=ssl.TLSVersion.TLSv1_3;tls_context.set_alpn_protocols(['h2','http/1.1']);tls_context.load_cert_chain(str(cert),str(key))
                reality_listener=socket.socket();reality_listener.bind(('127.0.0.1',0));reality_listener.listen();target_port=reality_listener.getsockname()[1]
                def tls_connection(sock):
                    try:
                        sock.settimeout(3)
                        with tls_context.wrap_socket(sock,server_side=True) as wrapped:wrapped.recv(1)
                    except (OSError,ssl.SSLError):sock.close()
                def tls_target():
                    while True:
                        try:sock,_=reality_listener.accept()
                        except OSError:return
                        threading.Thread(target=tls_connection,args=(sock,),daemon=True).start()
                threading.Thread(target=tls_target,daemon=True).start()
            for node_id, (protocol, kernel, transport, tls) in enumerate([
                ("shadowsocks", "xray", "tcp+udp", 0),
                ("hysteria", "singbox", "udp", 1), ("tuic", "singbox", "udp", 1),
                ("anytls", "singbox", "tcp", 1),
                ("vless", "xray", "tcp", 0), ("vmess", "xray", "tcp", 0),
                ("trojan", "xray", "tcp", 1),
            ], 901):
                if args.only and protocol != args.only:
                    continue
                user_sets[node_id]=[USER,MIDDLE,OTHER]
                reported_traffic.clear()
                port = free_port()
                definition = {"protocol": protocol, "server_port": port, "listen_ip": "127.0.0.1", "network": "tcp", "tls": tls,
                              "flow": "", "version": 2, "cipher": "2022-blake3-aes-128-gcm", "server_key": base64.b64encode(bytes(range(16))).decode(),
                              "tls_settings": {"server_name": "localhost"}, "base_config": {"push_interval": 5, "pull_interval": 2},
                              "cert_config": {"cert_mode": "none"}}
                if args.reality:
                    definition.update(tls=2,flow='xtls-rprx-vision',tls_settings={'private_key':private_key,'short_id':'a1b2c3d4','server_name':'localhost','dest':'127.0.0.1:'+str(target_port)})
                definitions[node_id] = definition
                runtime = root / protocol
                runtime.mkdir()
                config = {"panel": {"url": f"http://127.0.0.1:{api_port}", "token": "synthetic-only-token", "node_id": node_id, "node_type": protocol},
                          "kernel": {"type": kernel, "config_dir": str(runtime), "log_level": "warn"},
                          "cert": {"prefer_local": True, "cert_mode": "file" if tls else "none", "cert_file": str(cert), "key_file": str(key)},
                          "node": {"push_interval": 5, "pull_interval": 2, "track_interval": 1, "device_report_interval": 30}, "log": {"level": "info"}, "health_port": 0}
                # Loopback routing is permitted ONLY in this synthetic fixture.
                if kernel == "xray":
                    config["kernel"]["custom_route"] = [{"type": "field", "ip": ["127.0.0.1/32"], "outboundTag": "direct"}]
                else:
                    config["kernel"]["custom_route"] = [{"ip_cidr": ["127.0.0.1/32"], "outbound": "direct"}]
                path = runtime / "config.json"
                path.write_text(json.dumps(config))
                clients, held = [], None
                hold_started.clear()
                hold_release.clear()
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
                            if args.reality:
                                outbound.update(flow='xtls-rprx-vision',tls={'enabled':True,'server_name':'localhost','utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':public_key,'short_id':'a1b2c3d4'}})
                                result['reality_vision']=True
                            def start_client(source_ip, selected=None):
                                proxy_port = free_port()
                                bound = dict(outbound, inet4_bind_address=source_ip)
                                if selected:
                                    if protocol in ("vless","vmess","tuic"):bound['uuid']=selected['uuid']
                                    if protocol in ("trojan","hysteria","tuic","anytls"):bound['password']=selected['uuid']
                                    if protocol=='shadowsocks':bound['password']=definition['server_key']+":"+base64.b64encode(selected['uuid'].encode()[:16]).decode()
                                client_cfg = {"log": {"level": "warn"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": proxy_port}], "outbounds": [bound], "route": {"final": "proxy"}}
                                client_path = runtime / ("client-" + source_ip + ".json")
                                client_path.write_text(json.dumps(client_cfg))
                                client = subprocess.Popen([str(args.client), "run", "-c", str(client_path)], stdout=client_log, stderr=client_log)
                                clients.append(client)
                                deadline = time.monotonic() + 15
                                while time.monotonic() < deadline and not listening(proxy_port, "tcp") and client.poll() is None:
                                    time.sleep(0.1)
                                assert client.poll() is None and listening(proxy_port, "tcp"), (runtime / "client.log").read_text()
                                return client, proxy_port

                            first, first_port = start_client("127.0.0.9")
                            held, data = proxy_request(first_port, api_port, "/hold", keep_open=True)
                            assert b"200 OK" in data and hold_started.wait(2), protocol + " initial IP failed"
                            _, data = proxy_request(first_port, api_port)
                            assert b"200 OK" in data and b"synthetic_proxy_request" in data, protocol + " same-IP request failed"
                            result["synthetic_proxy_request"] = True
                            second, second_port = start_client("127.0.0.2")
                            try:
                                _, data = proxy_request(second_port, api_port, timeout=3)
                            except (OSError, TimeoutError):
                                data = b""
                            assert b"synthetic_proxy_request" not in data, protocol + " exceeded a one-IP device limit"
                            result["new_source_ip_rejected"] = True
                            result["same_source_ip_allowed"] = True
                            hold_release.set()
                            held.close()
                            held = None
                            stop(first)
                            deadline = time.monotonic() + 25
                            data = b""
                            while time.monotonic() < deadline:
                                try:
                                    _, data = proxy_request(second_port, api_port, timeout=3)
                                    if b"synthetic_proxy_request" in data:
                                        break
                                except (OSError, TimeoutError):
                                    pass
                                time.sleep(0.3)
                            assert b"200 OK" in data and b"synthetic_proxy_request" in data, protocol + " slot not released: " + (runtime / "client.log").read_text()[-1500:] + (runtime / "server.log").read_text()[-1500:]
                            result["slot_reused_after_disconnect"] = True
                            if protocol != 'anytls':
                                udp_target_request(second_port,udp_port)
                                result['udp_target_echo']=True
                            else:
                                result['udp_target_echo']='unsupported by AnyTLS outbound (TCP only)'
                            valid,valid_port=start_client('127.0.0.2',OTHER)
                            hold_release.clear();hold_started.clear()
                            revoked,_=proxy_request(second_port,api_port,'/hold',keep_open=True)
                            kept,_=proxy_request(valid_port,api_port,'/hold',keep_open=True)
                            try:
                                # Reorder while both streams remain active. Their authenticated names
                                # must not change with list positions.
                                user_sets[node_id]=[OTHER,MIDDLE,USER]
                                time.sleep(2.8)
                                _,again=proxy_request(second_port,api_port)
                                assert b'synthetic_proxy_request' in again,protocol+' reorder disrupted user'
                                if protocol!='anytls':udp_target_request(second_port,udp_port)
                                user_sets[node_id]=[USER,MIDDLE,OTHER]
                                time.sleep(2.8)
                                user_sets[node_id]=[MIDDLE,OTHER]
                                result['user_reorder_preserves_identity']=True
                                revoked.settimeout(15)
                                try:closed=revoked.recv(8192)==b''
                                except (ConnectionResetError,BrokenPipeError):closed=True
                                assert closed, protocol+' revoked stream remained live'
                                kept.settimeout(.3)
                                try:
                                    chunk=kept.recv(8192)
                                    assert chunk!=b'',protocol+' valid user was kicked'
                                except socket.timeout:pass
                                result['revoked_user_stream_closed']=True
                                result['other_user_kept']=True
                                try:_,denied=proxy_request(second_port,api_port,timeout=3)
                                except OSError:denied=b''
                                assert b'synthetic_proxy_request' not in denied,protocol+' revoked credential accepted'
                                result['revoked_credential_rejected']=True
                                if protocol!='anytls':
                                    try:udp_target_request(second_port,udp_port,timeout=2.5)
                                    except (OSError,AssertionError):pass
                                    else:raise AssertionError(protocol+' revoked UDP session admitted new target flow')
                                    result['revoked_udp_rejected']=True
                            finally:
                                hold_release.set();revoked.close();kept.close()
                            replacement=dict(USER,uuid='05b693a3-9235-4f83-84b8-b15d8243fbb9')
                            user_sets[node_id]=[OTHER,replacement,MIDDLE]
                            newer,newer_port=start_client('127.0.0.2',replacement)
                            deadline=time.monotonic()+15
                            while True:
                                try:_,data=proxy_request(newer_port,api_port,timeout=2)
                                except OSError:data=b''
                                if b'synthetic_proxy_request' in data:break
                                assert time.monotonic()<deadline,protocol+' readded ID/UUID failed'
                                time.sleep(.3)
                            result['same_id_new_uuid_works']=True
                            hold_release.clear()
                            middle_held,_=proxy_request(newer_port,api_port,'/hold',keep_open=True)
                            try:
                                user_sets[node_id]=[OTHER,MIDDLE]
                                middle_held.settimeout(15)
                                try:closed=middle_held.recv(8192)==b''
                                except (ConnectionResetError,BrokenPipeError):closed=True
                                assert closed,protocol+' removed middle user stream remained'
                                _,data=proxy_request(valid_port,api_port)
                                assert b'synthetic_proxy_request' in data,protocol+' valid user lost during middle removal'
                                result['middle_user_removed_without_kicking_others']=True
                            finally:hold_release.set();middle_held.close()
                            deadline=time.monotonic()+12
                            while sum(reported_traffic.get(USER['id'],[0,0]))==0 and time.monotonic()<deadline:time.sleep(.2)
                            assert sum(reported_traffic.get(USER['id'],[0,0]))>0,protocol+' retired traffic missing'
                            result['retired_user_traffic_reported']=True
                        results.append(result)
                        print(json.dumps(result), flush=True)
                    except Exception:
                        print("SERVER:", (runtime / "server.log").read_text()[-5000:], flush=True)
                        print("CLIENT:", (runtime / "client.log").read_text()[-2500:], flush=True)
                        raise
                    finally:
                        hold_release.set()
                        if held:
                            held.close()
                        for client in clients:
                            stop(client)
                        stop(process)
    finally:
        panel.shutdown()
        panel.server_close()
    print(json.dumps({"pass": len(results) == (1 if args.only else 7), "network_isolated": True, "real_panel_used": False, "protocols": results}), flush=True)


if __name__ == "__main__":
    main()
