#!/usr/bin/env python3
"""Run via unshare --net only; synthetic REALITY/Vision compatibility probe.
This does not read production configuration or use production customer UUIDs.
It reuses the fixed, previously verified Xray synthetic client on node 36.
"""
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import uuid

os.umask(0o077)
ROOT = Path(os.environ['NODE_PROBE_ROOT'])
assert not any(line.split()[1] == '00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:]), 'Use an isolated network namespace'
assert ROOT.is_dir()
BINARY = ROOT / os.environ.get('NODE_PROBE_BINARY', 'xboard-node-v1.13')
REALITY = os.environ.get('NODE_PROBE_REALITY') == '1'
LABEL = BINARY.name + ('-reality' if REALITY else '')
proxy_ports = {}
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
for source in ['203.0.113.10', '203.0.113.11']:
    subprocess.run(['ip', 'addr', 'add', source + '/32', 'dev', 'lo'], check=True)

def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

api_port, node_port = unused_port(), unused_port()
assert api_port != node_port
reports = []
release_holds = threading.Event()
users = [
    {'id': 901, 'uuid': '43e50a02-29dd-4d52-b315-d86f3fa14ead', 'device_limit': 1, 'speed_limit': None},
    {'id': 902, 'uuid': '3cc631dc-6412-42d5-baa9-fb281f3be588', 'device_limit': 0, 'speed_limit': None},
]
node_definition = {'protocol': 'vless', 'server_port': node_port, 'listen_ip': '127.0.0.1', 'network': 'tcp', 'tls': 0, 'flow': '', 'routes': [], 'base_config': {'push_interval': 5, 'pull_interval': 60}}

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split('?')[0]
        if path.endswith('/config'):
            self.reply(node_definition)
        elif path.endswith('/user'):
            self.reply({'users': users})
        elif path == '/hold':
            self.send_response(200)
            self.send_header('Content-Length', '1')
            self.end_headers()
            self.wfile.flush()
            release_holds.wait(75)
            try:
                self.wfile.write(b'X')
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.reply({'echo': True})

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
        if self.path.endswith('/handshake'):
            self.reply({'websocket': {'enabled': False}, 'settings': {'push_interval': 5, 'pull_interval': 60}})
        else:
            reports.append({'time': time.monotonic(), 'payload': {k: v for k, v in payload.items() if k not in ['token', 'node_id', 'node_type']}})
            self.reply({'data': True})

server = http.server.ThreadingHTTPServer(('127.0.0.1', api_port), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
result = {'isolated_network_namespace': True, 'synthetic_only': True, 'public_listener_created': False, 'binary_name': BINARY.name}
result['reality_vision'] = REALITY
connections = []

def connect(user, source):
    if REALITY:
        s = socket.create_connection(('127.0.0.1', proxy_ports[(user['id'], source)]), timeout=3)
        s.sendall(('GET http://127.0.0.1:%d/hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' % api_port).encode())
    else:
        s = socket.create_connection(('127.0.0.1', node_port), timeout=3, source_address=(source, 0))
        packet = bytes([0]) + uuid.UUID(user['uuid']).bytes + bytes([0, 1]) + struct.pack('!H', api_port) + bytes([1]) + socket.inet_aton('127.0.0.1')
        s.sendall(packet + b'GET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    s.settimeout(3)
    response = b''
    try:
        while b'\r\n\r\n' not in response:
            b = s.recv(4096)
            if not b:
                break
            response += b
    except (socket.timeout, ConnectionResetError):
        pass
    return s, b'200 OK' in response

with tempfile.TemporaryDirectory(prefix='xboard-node-probe-') as td:
    root = Path(td)
    client_proc = None
    client_log = None
    tls_listener = None
    if REALITY:
        key_output = subprocess.check_output([str(ROOT / 'xray-test-client'), 'x25519'], text=True)
        keys = dict(line.split(': ', 1) for line in key_output.strip().splitlines())
        tls_port = unused_port()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=www.example.test', '-keyout', str(root / 'tls.key'), '-out', str(root / 'tls.pem'), '-days', '1'], check=True, capture_output=True)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        tls_context.set_alpn_protocols(['h2', 'http/1.1'])
        tls_context.load_cert_chain(str(root / 'tls.pem'), str(root / 'tls.key'))
        tls_listener = socket.socket()
        tls_listener.bind(('127.0.0.1', tls_port))
        tls_listener.listen()
        tls_listener.settimeout(0.5)

        def target_connection(sock):
            try:
                sock.settimeout(3)
                with tls_context.wrap_socket(sock, server_side=True) as connection:
                    connection.recv(1)
            except (OSError, ssl.SSLError):
                sock.close()

        def target_server():
            while not release_holds.is_set():
                try:
                    sock, _ = tls_listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=target_connection, args=(sock,), daemon=True).start()

        threading.Thread(target=target_server, daemon=True).start()
        node_definition.update({'tls': 2, 'flow': 'xtls-rprx-vision', 'tls_settings': {'private_key': keys['PrivateKey'], 'short_id': 'a1b2c3d4', 'server_name': 'www.example.test', 'dest': '127.0.0.1:' + str(tls_port)}})
    config = {'panel': {'url': 'http://127.0.0.1:' + str(api_port), 'token': 'synthetic-local-only', 'node_id': 901, 'node_type': 'vless'}, 'kernel': {'type': 'xray', 'config_dir': str(root / 'runtime'), 'log_level': 'warn', 'custom_route': [{'type': 'field', 'ip': ['127.0.0.1/32'], 'outboundTag': 'direct'}]}, 'cert': {'cert_mode': 'none'}, 'node': {'push_interval': 5, 'pull_interval': 60, 'track_interval': 1, 'device_report_interval': 30}, 'log': {'level': 'info', 'output': str(root / 'node.log')}, 'health_port': 0}
    (root / 'config.json').write_text(json.dumps(config))
    log = (root / 'process.log').open('w+')
    proc = subprocess.Popen([str(BINARY), '-c', str(root / 'config.json')], stdout=log, stderr=subprocess.STDOUT, cwd=root)
    try:
        for attempt in range(20):
            time.sleep(0.5)
            if proc.poll() is not None:
                raise RuntimeError('Candidate process exited before listener')
            lines = subprocess.check_output(['ss', '-H', '-lntp'], text=True).splitlines()
            own = [line.split() for line in lines if 'pid=%d,' % proc.pid in line]
            if own:
                assert all(line[3].startswith('127.0.0.1:') for line in own), 'Unexpected listener address'
                break
        else:
            raise RuntimeError('Candidate listener not ready')

        if REALITY:
            inbounds, outbounds, rules = [], [], []
            for user in users:
                for source in ['203.0.113.10', '203.0.113.11']:
                    port = unused_port()
                    tag = 'client-' + str(user['id']) + '-' + source.rsplit('.', 1)[1]
                    proxy_ports[(user['id'], source)] = port
                    inbounds.append({'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'http', 'settings': {}})
                    outbounds.append({'tag': tag, 'protocol': 'vless', 'sendThrough': source, 'settings': {'vnext': [{'address': '127.0.0.1', 'port': node_port, 'users': [{'id': user['uuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]}, 'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {'fingerprint': 'chrome', 'serverName': 'www.example.test', 'password': keys['Password (PublicKey)'], 'shortId': 'a1b2c3d4'}}})
                    rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': tag})
            client_config = {'log': {'loglevel': 'warning', 'access': 'none'}, 'inbounds': inbounds, 'outbounds': outbounds, 'routing': {'rules': rules}}
            (root / 'client.json').write_text(json.dumps(client_config))
            client_log = (root / 'client.log').open('w+')
            client_proc = subprocess.Popen([str(ROOT / 'xray-test-client'), 'run', '-config', str(root / 'client.json')], stdout=client_log, stderr=subprocess.STDOUT)
            for attempt in range(20):
                time.sleep(0.25)
                assert client_proc.poll() is None, 'Synthetic REALITY client exited'
                lines = subprocess.check_output(['ss', '-H', '-lntp'], text=True).splitlines()
                own = [line.split() for line in lines if 'pid=%d,' % client_proc.pid in line]
                if len(own) == 4:
                    assert all(line[3].startswith('127.0.0.1:') for line in own)
                    break
            else:
                raise RuntimeError('Synthetic client listeners not ready')

        successes = 0
        for user, source in [(users[0], '203.0.113.10'), (users[1], '203.0.113.10'), (users[1], '203.0.113.11')]:
            s, ok = connect(user, source)
            connections.append(s)
            successes += int(ok)
        result['allowed_connections'] = successes
        assert successes == 3, 'Expected connections did not all reach local echo'
        denied, ok = connect(users[0], '203.0.113.11')
        denied.close()
        result['limited_second_ip_rejected'] = not ok

        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            time.sleep(0.5)
            if proc.poll() is not None:
                raise RuntimeError('Candidate process exited during traffic')
        snapshots = [r['payload'].get('alive', {}) for r in reports]
        matching = [p for p in snapshots if len(p.get('901', [])) == 1 and len(p.get('902', [])) == 2]
        result['correct_device_snapshots'] = len(matching)
        result['device_snapshot_refreshes'] = len(matching) >= 2
        result['traffic_reported'] = any(any(sum(t) > 0 for t in r['payload'].get('traffic', {}).values()) for r in reports)
        result['report_count_while_connected'] = len(reports)
        for s in connections:
            s.close()
        connections.clear()
        release_holds.set()
        time.sleep(7)
        result['connections_cleared_after_disconnect'] = bool(reports) and reports[-1]['payload'].get('metrics', {}).get('active_connections') == 0
        result['pass'] = result['limited_second_ip_rejected'] and len(matching) >= 2 and result['traffic_reported'] and result['connections_cleared_after_disconnect']
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        result['pass'] = False
    finally:
        for s in connections:
            s.close()
        release_holds.set()
        if client_proc is not None:
            client_proc.terminate()
            try:
                client_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                client_proc.kill()
                client_proc.wait()
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.flush()
        log.seek(0)
        stdout = log.read()
        log.close()
        app_log = (root / 'node.log').read_text() if (root / 'node.log').exists() else ''
        if client_log is not None:
            client_log.flush()
            client_log.seek(0)
            stdout += '\nCLIENT\n' + client_log.read()
            client_log.close()
        (ROOT / (LABEL + '-probe.private.log')).write_text(stdout + '\n' + app_log)
        if tls_listener is not None:
            tls_listener.close()
        server.shutdown()

result['report_field_sets'] = sorted({','.join(sorted(r['payload'])) for r in reports})
(ROOT / (LABEL + '-probe.json')).write_text(json.dumps(result, indent=2))
print(json.dumps(result))
