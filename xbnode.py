#!/usr/bin/env python3
"""Independent Xboard-Node installer. Python standard library, Linux/systemd.

Never import production configuration into this repository. Panel calls made by
the manager are read-only; traffic/device reports belong to the node runtime.
"""

import argparse
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "v0.2.1"
SCHEMA = 1
PROTOCOLS = {
    "vless": ("VLESS", "xray", "tcp"),
    "vmess": ("VMess", "xray", "tcp"),
    "trojan": ("Trojan", "xray", "tcp"),
    "shadowsocks": ("Shadowsocks", "xray", "tcp+udp"),
    "hysteria": ("Hysteria2", "singbox", "udp"),
    "tuic": ("TUIC", "singbox", "udp"),
    "anytls": ("AnyTLS", "singbox", "tcp"),
}
ROOT = Path("/etc/xbnode")
LIB = Path("/usr/local/lib/xbnode")
UNITS = Path("/etc/systemd/system")
COMMAND = Path("/usr/local/bin/xbnode")


class Error(Exception):
    """A deliberately credential-free message suitable for the terminal."""


def check_id(value):
    value = str(value)
    if not re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise Error("节点 ID 必须是 1–999999999 的数字。")
    return int(value)


def check_release(value):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", value):
        raise Error("版本号格式错误，例如 v0.2.1。")
    return value


def check_repo(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise Error("仓库应为 OWNER/REPO；第一版在线下载使用公开 GitHub Releases。")
    return value


def check_url(value):
    value = value.strip().rstrip("/")
    if re.search(r"[\s\x00-\x1f\x7f]", value):
        raise Error("面板地址不能包含空白或控制字符。")
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or
            parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise Error("面板地址必须是 HTTPS 根地址，例如 https://xb.1kb.day，不带后台路径。")
    try:
        parsed.port
    except ValueError:
        raise Error("面板端口格式错误。") from None
    return value


def check_token(value):
    if not value or len(value) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise Error("通讯密钥不能为空，且不能含空白、控制字符或非 ASCII 字符。")
    return value


def env_text(token):
    return "XBN_TOKEN=" + json.dumps(check_token(token)) + "\n"


def architecture(value=None):
    value = value or platform.machine()
    result = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(value)
    if not result:
        raise Error("仅支持 Linux AMD64 / ARM64。")
    return result


def command(*args, check=True, timeout=30, input_data=None):
    try:
        result = subprocess.run(args, input=input_data, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Error("本机命令失败或超时：" + str(args[0])) from None
    if check and result.returncode:
        raise Error("本机命令执行失败：" + str(args[0]) + "；请查看本机状态。")
    return result


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise Error("拒绝覆盖符号链接：" + str(path))
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content.encode() if isinstance(content, str) else content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path, value, mode=0o600):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", mode)


def read_json(path, default=None):
    path = Path(path)
    if not path.exists():
        if default is not None:
            return default
        raise Error("找不到配置文件：" + str(path))
    if path.is_symlink():
        raise Error("拒绝读取配置符号链接。")
    try:
        return json.loads(path.read_text())
    except (ValueError, OSError):
        raise Error("配置文件无法读取：" + str(path)) from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Error("面板发生重定向；请填写最终 HTTPS 根地址，认证请求未继续转发。")


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise Error("拒绝下载跳转到非 HTTPS 地址。")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def get_bytes(url, limit, panel=False):
    opener = urllib.request.build_opener(NoRedirect() if panel else HTTPSRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "Go-http-client/1.1", "Accept": "application/json" if panel else "application/octet-stream"})
    try:
        with opener.open(request, timeout=45) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise Error(("面板请求" if panel else "发布文件下载") + "返回 HTTP " + str(error.code)) from None
    except (urllib.error.URLError, OSError, TimeoutError):
        raise Error(("面板连接" if panel else "程序下载") + "失败：请检查 DNS、HTTPS 和网络；未打印认证 URL。") from None
    if len(data) > limit:
        raise Error("远端响应超过允许大小。")
    return data


def panel_read(profile, node_id, resource):
    if resource not in ("config", "user"):
        raise Error("不允许的面板操作。")
    query = urllib.parse.urlencode({"node_id": check_id(node_id), "token": check_token(profile["token"])})
    url = check_url(profile["url"]) + "/api/v2/server/" + resource + "?" + query
    try:
        value = json.loads(get_bytes(url, 12 * 1024 * 1024, panel=True))
    except ValueError:
        raise Error("面板未返回预期 JSON，请检查接口或 Cloudflare 挑战。") from None
    if not isinstance(value, dict):
        raise Error("面板响应结构不受支持。")
    return value


def node_spec(raw):
    protocol = str(raw.get("protocol", "")).lower()
    if protocol == "hysteria2":
        protocol = "hysteria"
    if protocol not in PROTOCOLS:
        raise Error("当前脚本只支持 VLESS、VMess、Trojan、SS、HY2、TUIC、AnyTLS。")
    try:
        port = int(raw.get("server_port", 0))
        tls = int(raw.get("tls", 0))
        version = int(raw.get("version", 2))
    except (ValueError, TypeError):
        raise Error("节点端口或 TLS 设置格式不正确。") from None
    if not 1 <= port <= 65535:
        raise Error("面板服务端口必须为 1–65535。")
    if protocol == "hysteria" and version != 2:
        raise Error("本版只提供 Hysteria2，请先核对面板协议版本。")
    name, kernel, transport = PROTOCOLS[protocol]
    network = str(raw.get("network", "tcp")).lower()
    if network in ("quic", "kcp", "mkcp"):
        transport = "udp"
    # The panel can override the runtime kernel. Refuse a conflicting choice
    # instead of pretending that the locally selected kernel will win.
    override = raw.get("kernel_type")
    if override and override != kernel:
        raise Error("面板指定的 kernel_type 与本脚本默认内核不一致，请先在后台核对。")
    needs_cert = tls == 1 or protocol in ("hysteria", "tuic", "anytls") or (protocol == "trojan" and tls != 2)
    if tls == 2:
        settings = raw.get("tls_settings") or {}
        if not isinstance(settings, dict) or protocol not in ("vless", "trojan") or not settings.get("private_key") or not (settings.get("server_name") or settings.get("dest")):
            raise Error("面板 REALITY 参数不完整或协议不匹配。")
        needs_cert = False
    return {"protocol": protocol, "label": name, "kernel": kernel, "port": port,
            "transport": transport, "tls": tls, "needs_cert": needs_cert}


def users_count(raw):
    users = raw.get("users")
    if not isinstance(users, list):
        raise Error("面板用户接口格式不受支持。")
    return len(users)


def parse_sockets(output, port, transport, pid=None):
    found = set()
    wanted = {"tcp", "udp"} if transport == "tcp+udp" else {transport}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in wanted:
            continue
        try:
            matches = int(fields[4].rsplit(":", 1)[1]) == port
        except (ValueError, IndexError):
            continue
        if matches and (pid is None or re.search(r"\bpid=" + str(pid) + r"(?:,|\))", line)):
            found.add(fields[0])
    return found


def port_free(port, transport):
    output = command("ss", "-H", "-lntup").stdout
    if parse_sockets(output, port, transport):
        raise Error("服务端口已被占用：" + str(port) + "/" + transport + "。未停止占用程序。")


def validate_manifest(manifest, release):
    if manifest.get("release") != check_release(release) or manifest.get("config_schema") != SCHEMA:
        raise Error("发布版本或配置结构不兼容。")
    if not re.fullmatch(r"v[0-9A-Za-z.-]+", str(manifest.get("node_version", ""))):
        raise Error("发布程序版本字段无效。")
    if not re.fullmatch(r"[a-f0-9]{40}", str(manifest.get("upstream_commit", ""))):
        raise Error("发布未固定上游源码提交。")
    if manifest.get("manager_schema") != 1:
        raise Error("新版本需要更新安装管理脚本，请先运行该版本的 install.sh。")
    if not {"device_snapshot_refresh_v1", "local_cert_override_v1"} <= set(manifest.get("features", [])):
        raise Error("发布未声明所需设备上报/本地证书能力。")
    if not manifest.get("maintenance_patches"):
        raise Error("发布缺少维护补丁记录，拒绝用原版覆盖修复。")
    return manifest


def checksum_table(data):
    result = {}
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise Error("发布校验清单编码无效。") from None
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[a-f0-9]{64}", parts[0]) or not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[1]) or parts[1] in result:
            raise Error("发布校验清单无效。")
        result[parts[1]] = parts[0]
    return result


def verified(data, name, hashes):
    if name not in hashes or hashlib.sha256(data).hexdigest() != hashes[name]:
        raise Error("文件摘要校验失败：" + name)
    return data


def release_bundle(repo, release):
    base = "https://github.com/" + check_repo(repo) + "/releases/download/" + check_release(release)
    hashes = checksum_table(get_bytes(base + "/SHA256SUMS", 128 * 1024))
    try:
        manifest = json.loads(verified(get_bytes(base + "/manifest.json", 128 * 1024), "manifest.json", hashes))
    except ValueError:
        raise Error("发布清单无法解析。") from None
    validate_manifest(manifest, release)
    name = "xboard-node-linux-" + architecture()
    LIB.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(LIB, 0o755)
    (LIB / "releases").mkdir(exist_ok=True, mode=0o755)
    os.chmod(LIB / "releases", 0o755)
    directory = LIB / "releases" / release
    if directory.exists():
        current = directory / "xboard-node"
        if not current.is_file() or current.is_symlink() or hashlib.sha256(current.read_bytes()).hexdigest() != hashes[name]:
            raise Error("同一版本的本机程序与发布摘要不同，拒绝覆盖。请发布新版本号。")
    else:
        binary = verified(get_bytes(base + "/" + name, 220 * 1024 * 1024), name, hashes)
        directory.mkdir(parents=True, mode=0o755)
        os.chmod(directory, 0o755)
        atomic(directory / "xboard-node", binary, 0o755)
        write_json(directory / "manifest.json", manifest, 0o644)
    actual = command(str(directory / "xboard-node"), "-v").stdout
    if "xboard-node " + manifest["node_version"] + " " not in actual:
        raise Error("程序内置版本与发布清单不一致。")
    return manifest


def node_dir(node_id):
    return ROOT / ("node-" + str(check_id(node_id)))


def service_name(node_id):
    return "xbnode-" + str(check_id(node_id)) + ".service"


def make_config(node_id, profile, spec, certificate):
    state = "/var/lib/xbnode-" + str(check_id(node_id))
    cert = dict(certificate)
    cert.update({"prefer_local": True, "cert_dir": state + "/certs"})
    return {"panel": {"url": check_url(profile["url"]), "token_env": "XBN_TOKEN", "node_id": node_id,
                      "node_type": spec["protocol"]},
            "kernel": {"type": spec["kernel"], "config_dir": state, "log_level": "warn"},
            "node": {"push_interval": 60, "pull_interval": 60, "track_interval": 5, "device_report_interval": 30},
            "cert": cert, "log": {"level": "info"}, "health_port": 0}


def make_unit(node_id, release, spec, certificate):
    node_id = check_id(node_id)
    release = check_release(release)
    directory = node_dir(node_id)
    caps = "CAP_NET_BIND_SERVICE" if spec["port"] < 1024 or certificate.get("cert_mode") == "http" else ""
    credentials = ""
    if certificate.get("cert_mode") == "file":
        credentials = f"LoadCredential=fullchain.pem:{directory}/tls/fullchain.pem\nLoadCredential=privkey.pem:{directory}/tls/privkey.pem\n"
    return f"""[Unit]
Description=Xboard-Node managed node {node_id}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=4

[Service]
Type=simple
DynamicUser=yes
StateDirectory=xbnode-{node_id}
StateDirectoryMode=0700
WorkingDirectory=/var/lib/xbnode-{node_id}
LoadCredential=node.json:{directory}/config.yml
{credentials}EnvironmentFile={directory}/credentials.env
ExecStart={LIB}/releases/{release}/xboard-node -c %d/node.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=40
LimitNOFILE=1048576
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet={caps}
AmbientCapabilities={caps}
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def active(node_id):
    return command("systemctl", "is-active", "--quiet", service_name(node_id), check=False).returncode == 0


def wait_ready(node_id, spec, since, timeout=75):
    deadline = time.monotonic() + timeout
    unit = service_name(node_id)
    wanted = {"tcp", "udp"} if spec["transport"] == "tcp+udp" else {spec["transport"]}
    while time.monotonic() < deadline:
        status = command("systemctl", "show", unit, "--property=MainPID,ActiveState,NRestarts").stdout
        props = dict(line.split("=", 1) for line in status.splitlines() if "=" in line)
        pid = int(props.get("MainPID", "0"))
        if props.get("ActiveState") == "active" and pid:
            sockets = command("ss", "-H", "-lntup").stdout
            log = command("journalctl", "-u", unit, "--since", "@" + str(int(since)), "--no-pager", "-o", "cat").stdout
            ready = re.search(r"(?:initial snapshot ready|xray started|sing-box started)[^\n]*users=\d+|started, \d+ users", log)
            if wanted <= parse_sockets(sockets, spec["port"], spec["transport"], pid) and ready:
                return
        time.sleep(2)
    raise Error("节点未通过用户加载与端口检查。可查看脱敏日志，客户端连接仍需实际测试。")


def snapshot(node_id):
    source = node_dir(node_id)
    destination = ROOT / "backups" / (str(node_id) + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3))
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copytree(source, destination, symlinks=False)
    os.chmod(destination, 0o700)
    return destination


def restore_snapshot(node_id, saved, start=True):
    saved = Path(saved)
    base = (ROOT / "backups").resolve()
    if saved.is_symlink() or base not in saved.resolve().parents:
        raise Error("回退来源不在本工具备份目录。")
    meta = read_json(saved / "node.json")
    if meta.get("node_id") != check_id(node_id) or meta.get("config_schema") != SCHEMA:
        raise Error("回退配置与节点不匹配。")
    command("systemctl", "stop", service_name(node_id), check=False)
    destination = node_dir(node_id)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(saved, destination)
    atomic(UNITS / service_name(node_id), (saved / "service.unit").read_bytes(), 0o644)
    command("systemctl", "daemon-reload")
    if start:
        since = time.time()
        command("systemctl", "enable", "--now", service_name(node_id))
        wait_ready(node_id, meta["spec"], since, 180 if meta["certificate"].get("cert_mode") == "http" else 75)


def optional_int(value):
    try:
        number = int(value)
        return number if 0 <= number < 2**63 else None
    except (TypeError, ValueError):
        return None


def probe_command(*args):
    try:
        result = command(*args, check=False)
        return result.stdout if result.returncode == 0 else None
    except (Error, OSError):
        return None


def process_sample(pid, proc=Path('/proc')):
    result = {'rss_bytes': None, 'pss_bytes': None, 'fds': None, 'threads': None, 'cpu_ticks': None}
    try:
        for line in (proc / str(pid) / 'status').read_text().splitlines():
            key, _, value = line.partition(':')
            if key in ('VmRSS', 'Threads'):
                number = optional_int(value.split()[0])
                result['rss_bytes' if key == 'VmRSS' else 'threads'] = number * 1024 if key == 'VmRSS' and number is not None else number
    except (OSError, ValueError, IndexError):
        pass
    try:
        fields = (proc / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
        result['cpu_ticks'] = int(fields[11]) + int(fields[12])
    except (OSError, ValueError, IndexError):
        pass
    try:
        result['fds'] = sum(1 for _ in (proc / str(pid) / 'fd').iterdir())
    except OSError:
        pass
    try:
        for line in (proc / str(pid) / 'smaps_rollup').read_text().splitlines():
            if line.startswith('Pss:'):
                result['pss_bytes'] = int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return result


def diagnose_service(unit, port=None, transport='tcp', proc=Path('/proc'), sample_seconds=0.25):
    if not re.fullmatch(r'(?:xbnode|xboard-node)-[1-9][0-9]*\.service', unit):
        raise Error('仅支持指定的 xbnode-ID / xboard-node-ID 服务。')
    properties = probe_command('systemctl', 'show', unit, '--property=ActiveState,SubState,MainPID,NRestarts,CPUUsageNSec,MemoryCurrent,ExecMainStartTimestamp')
    props = dict(line.split('=', 1) for line in (properties or '').splitlines() if '=' in line)
    pid = optional_int(props.get('MainPID')) or None
    result = {'service': unit, 'state': props.get('ActiveState'), 'substate': props.get('SubState'), 'pid': pid,
              'restarts': optional_int(props.get('NRestarts')), 'cpu_total_ns': optional_int(props.get('CPUUsageNSec')),
              'cgroup_memory_bytes': optional_int(props.get('MemoryCurrent')), 'version': None, 'binary_sha256': None,
              'cpu_percent_one_core': None, 'loaded_users': None, 'loaded_at': None, 'last_report_at': None,
              'listener_owned': None, 'business_connectivity': 'unknown', 'rss_bytes': None, 'pss_bytes': None,
              'fds': None, 'threads': None, 'socket_rows': None}
    if pid:
        before = process_sample(pid, proc)
        started = time.monotonic()
        time.sleep(sample_seconds)
        after = process_sample(pid, proc)
        result.update({k: v for k, v in after.items() if k != 'cpu_ticks'})
        if before['cpu_ticks'] is not None and after['cpu_ticks'] is not None and after['cpu_ticks'] >= before['cpu_ticks']:
            result['cpu_percent_one_core'] = round(100 * (after['cpu_ticks'] - before['cpu_ticks']) / os.sysconf('SC_CLK_TCK') / (time.monotonic() - started), 2)
        executable = proc / str(pid) / 'exe'
        try:
            with executable.open('rb') as stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            result['binary_sha256'] = digest.hexdigest()
            version = probe_command(str(executable), '-v') or ''
            match = re.search(r'xboard-node (v[0-9A-Za-z.-]+) \(built ([0-9-]+)\)', version)
            if match:
                result['version'] = match.group(1)
        except OSError:
            pass
        sockets = probe_command('ss', '-H', '-lntup')
        if sockets is not None and port is not None:
            expected = {'tcp', 'udp'} if transport == 'tcp+udp' else {transport}
            result['listener_owned'] = expected <= parse_sockets(sockets, port, transport, pid)
        connections = probe_command('ss', '-H', '-tanup')
        if connections is not None:
            result['socket_rows'] = sum('pid=' + str(pid) + ',' in row for row in connections.splitlines())
    # Only extract known numeric fields and timestamps. Never return raw journal,
    # URLs, client addresses, UUIDs, command lines or environment variables.
    journal_args = ['journalctl', '-u', unit, '-b', '-n', '2000', '--no-pager', '-o', 'json']
    if props.get('ExecMainStartTimestamp'):
        journal_args += ['--since', props['ExecMainStartTimestamp']]
    journal = probe_command(*journal_args)
    for line in (journal or '').splitlines():
        try:
            entry = json.loads(line)
            message = str(entry.get('MESSAGE', ''))
            stamp = optional_int(entry.get('__REALTIME_TIMESTAMP'))
            timestamp = dt.datetime.fromtimestamp(stamp / 1e6, dt.timezone.utc).isoformat() if stamp else None
            match = re.search(r'(?:initial snapshot ready|xray started|sing-box started).*?users=(\d+)|started, (\d+) users|users updated, (\d+) users', message)
            if match:
                result['loaded_users'] = int(next(v for v in match.groups() if v is not None))
                result['loaded_at'] = timestamp
            delta = re.search(r'users updated: \+(\d+) -(\d+)|users added: \+(\d+)|users removed: -(\d+)', message)
            if delta and result['loaded_users'] is not None:
                add, remove, only_add, only_remove = delta.groups()
                result['loaded_users'] = max(0, result['loaded_users'] + int(add or only_add or 0) - int(remove or only_remove or 0))
                result['loaded_at'] = timestamp
            if 'report pushed:' in message:
                result['last_report_at'] = timestamp
        except (ValueError, TypeError, OverflowError):
            continue
    return result


def retention_plan(keep_releases=2, keep_snapshots=3, pins=(), proc=Path('/proc')):
    if keep_releases < 1 or keep_snapshots < 1:
        raise Error('至少保留一个版本与一份快照。')
    roots = [LIB / 'releases', ROOT / 'backups']
    if any(p.is_symlink() for p in (ROOT, LIB, *roots)):
        raise Error('管理目录存在符号链接，停止清理。')
    releases = {p.name: p for p in roots[0].glob('*') if p.is_dir() and not p.is_symlink() and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', p.name)}
    protected_versions = set(check_release(p) for p in pins)
    protected_versions.update(check_release(p) for p in read_json(ROOT / 'settings.json', {}).get('pinned_releases', []))
    protected_snapshots = set()
    snapshots = {}
    # Every snapshot has its own rollback edges. Even an unselected snapshot's
    # referenced predecessor is protected; graph traversal must never escape.
    for p in roots[1].glob('*'):
        if p.is_symlink() or not p.is_dir():
            continue
        if (p / 'node.json').is_symlink():
            raise Error('快照元数据存在符号链接，停止清理。')
        meta = read_json(p / 'node.json')
        check_id(meta['node_id']); check_release(meta['release'])
        snapshots[str(p.resolve())] = (p, meta)
    nodes = []
    for p in ROOT.glob('node-*/node.json'):
        if p.is_symlink() or p.parent.is_symlink():
            raise Error('节点目录存在符号链接，停止清理。')
        nodes.append(read_json(p))
    def protect_meta(meta):
        protected_versions.add(check_release(meta['release']))
        previous = meta.get('previous')
        if previous:
            saved = Path(previous)
            if saved.is_symlink() or saved.parent.resolve() != roots[1].resolve():
                raise Error('回退引用在管理目录之外，停止清理。')
            key = str(saved.resolve())
            if key not in snapshots:
                raise Error('回退引用缺失，停止清理以供排查。')
            protected_snapshots.add(key)
    for meta in nodes:
        protect_meta(meta)
    for _, meta in snapshots.values():
        # References are protected regardless of whether this snapshot is kept.
        if meta.get('previous'):
            temp = dict(meta); temp['release'] = meta['release']; protect_meta(temp)
    groups = {}
    for key, (path, meta) in snapshots.items():
        groups.setdefault(meta['node_id'], []).append(key)
    for keys in groups.values():
        protected_snapshots.update(sorted(keys, reverse=True)[:keep_snapshots])
        successful = [key for key in keys if snapshots[key][1].get('last_ready') is True]
        if successful:
            protected_snapshots.add(max(successful))
        # Missing legacy readiness evidence is not permission to discard it.
        protected_snapshots.update(key for key in keys if 'last_ready' not in snapshots[key][1])
    for key in protected_snapshots:
        protected_versions.add(snapshots[key][1]['release'])
    def version_key(value):
        match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', value)
        return tuple(map(int, match.groups())) if match else (-1, -1, -1)
    protected_versions.update(sorted(releases, key=version_key, reverse=True)[:keep_releases])
    # Active executable and unit references protect even older installed copies.
    unknown_process = False
    for path in proc.glob('[0-9]*/exe'):
        try:
            target = Path(re.sub(r' \(deleted\)$', '', os.readlink(path)))
            if roots[0] in target.parents:
                protected_versions.add(target.relative_to(roots[0]).parts[0])
        except FileNotFoundError:
            continue
        except OSError:
            unknown_process = True
    if unknown_process:
        protected_versions.update(releases)
    for unit in UNITS.glob('xbnode-*.service'):
        if unit.is_symlink():
            raise Error('服务文件存在符号链接，停止清理。')
        for release in re.findall(re.escape(str(roots[0])) + r'/(v[0-9A-Za-z.-]+)/', unit.read_text()):
            protected_versions.add(release)
    candidates = [str(path) for name, path in releases.items() if name not in protected_versions]
    candidates += [str(path) for key, (path, _) in snapshots.items() if key not in protected_snapshots]
    # Any release needed by a snapshot left on disk is always protected.
    retained_versions = {meta['release'] for key, (_, meta) in snapshots.items() if str(snapshots[key][0]) not in candidates}
    candidates = [p for p in candidates if Path(p).parent != roots[0] or Path(p).name not in retained_versions]
    return {'preview': True, 'candidates': sorted(candidates), 'protected_releases': sorted(protected_versions | retained_versions),
            'protected_snapshots': sorted(protected_snapshots), 'process_visibility_complete': not unknown_process}


class Terminal:
    def __init__(self):
        try:
            self.tty = open("/dev/tty", "r+", encoding="utf-8")
        except OSError:
            raise Error("交互操作需要终端。请下载脚本后用 bash install.sh 运行。") from None

    def ask(self, text, default="", secret=False):
        if secret:
            return getpass.getpass(text + "：", stream=self.tty)
        self.tty.write(text + (" [" + default + "]" if default else "") + "：")
        self.tty.flush()
        value = self.tty.readline()
        if not value:
            raise Error("终端输入已结束。")
        return value.strip() or default

    def confirm(self, text):
        return self.ask(text + "，输入 yes 继续", "no") == "yes"


class Manager:
    def __init__(self, repo=None, release=VERSION, terminal=None):
        self.repo = repo
        self.release = check_release(release)
        self.terminal = terminal

    @property
    def ui(self):
        if self.terminal is None:
            self.terminal = Terminal()
        return self.terminal

    def settings(self):
        return read_json(ROOT / "settings.json", {})

    def repository(self):
        return check_repo(self.repo or self.settings().get("repo") or self.ui.ask("你的 GitHub 安装仓库（OWNER/REPO）"))

    def install_manager(self):
        LIB.mkdir(parents=True, exist_ok=True, mode=0o755)
        os.chmod(LIB, 0o755)
        atomic(LIB / "xbnode.py", Path(__file__).read_bytes(), 0o755)
        wrapper = "#!/bin/sh\nexec /usr/bin/python3 " + str(LIB / "xbnode.py") + ' "$@"\n'
        atomic(COMMAND, wrapper, 0o755)
        old = self.settings()
        old.update({"repo": self.repository(), "manager_version": VERSION})
        write_json(ROOT / "settings.json", old)

    def profiles(self):
        directory = ROOT / "panels"
        return [(p.stem, read_json(p)) for p in sorted(directory.glob("*.json"))] if directory.exists() else []

    def choose_profile(self):
        profiles = self.profiles()
        for index, (_, profile) in enumerate(profiles, 1):
            print(f"{index}. {profile['url']}")
        if profiles:
            choice = self.ui.ask("选择已有面板，或输入 new 添加", "1")
            if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                return profiles[int(choice) - 1]
            if choice != "new":
                raise Error("面板选项无效。")
        url = check_url(self.ui.ask("面板 HTTPS 根地址", "https://xb.1kb.day"))
        token = check_token(self.ui.ask("服务器通讯密钥（隐藏输入）", secret=True))
        return secrets.token_hex(8), {"url": url, "token": token}

    def choose_certificate(self, node_id, spec, raw):
        if not spec["needs_cert"]:
            return {"cert_mode": "none"}, None
        print("该节点需要 TLS 证书：1. 已有证书  2. HTTP-01 自动签发与续期")
        choice = self.ui.ask("证书方式", "1")
        if choice == "1":
            cert = Path(self.ui.ask("证书 PEM 文件绝对路径"))
            key = Path(self.ui.ask("私钥 PEM 文件绝对路径"))
            if not cert.is_absolute() or not key.is_absolute() or not cert.is_file() or not key.is_file():
                raise Error("证书或私钥路径无效。")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                context.load_cert_chain(str(cert), str(key))
                details = ssl._ssl._test_decode_cert(str(cert))
                if ssl.cert_time_to_seconds(details["notAfter"]) <= time.time():
                    raise Error("证书已过期。")
            except (ssl.SSLError, OSError, KeyError):
                raise Error("证书与私钥无法加载、格式错误或不匹配。") from None
            cred = "/run/credentials/" + service_name(node_id)
            return {"cert_mode": "file", "cert_file": cred + "/fullchain.pem", "key_file": cred + "/privkey.pem"}, (cert.read_bytes(), key.read_bytes())
        if choice == "2":
            domain = self.ui.ask("证书域名（必须解析到此机且公网 TCP 80 可达）").lower()
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
                raise Error("请填写单个有效域名，不含通配符。")
            email = self.ui.ask("ACME 联系邮箱")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise Error("ACME 邮箱格式错误。")
            if spec["port"] == 80:
                raise Error("节点不能与 HTTP-01 同时占用 TCP 80，请更换节点端口或使用已有证书。")
            port_free(80, "tcp")
            try:
                addresses = sorted({r[4][0] for r in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)})
            except OSError:
                raise Error("证书域名尚未解析。") from None
            print("域名解析结果：" + ", ".join(addresses))
            print("自动签发使用 Let's Encrypt；请先阅读 https://letsencrypt.org/repository/ 的当前订户协议。")
            if not self.ui.confirm("确认你已阅读并同意签发机构当前协议，且域名解析与公网 TCP 80 已就绪"):
                raise Error("已取消证书自动签发。")
            return {"cert_mode": "http", "domain": domain, "email": email, "http_port": 80, "acme_agreed": True}, None
        raise Error("证书选项无效。")

    def fetch_spec(self, profile, node_id):
        raw = panel_read(profile, node_id, "config")
        spec = node_spec(raw)
        count = users_count(panel_read(profile, node_id, "user"))
        print(f"识别：{spec['label']} / {spec['kernel']} / {spec['port']} {spec['transport']}，可用用户 {count}")
        if count == 0:
            raise Error("当前可用用户为 0，内核不会监听；请在后台配置权限组/套餐后重试，尚未安装。")
        return raw, spec

    def add(self):
        repo = self.repository()
        profile_id, profile = self.choose_profile()
        node_id = check_id(self.ui.ask("新节点数字 ID（不要使用其他机器正在运行的节点 ID）"))
        directory = node_dir(node_id)
        if directory.exists() or (UNITS / service_name(node_id)).exists():
            raise Error("该节点目录或服务已存在；请使用恢复、更新或连接修改功能。")
        raw, spec = self.fetch_spec(profile, node_id)
        port_free(spec["port"], spec["transport"])
        certificate, cert_files = self.choose_certificate(node_id, spec, raw)
        if not self.ui.confirm(f"安装节点 {node_id}，版本 {self.release}"):
            return
        manifest = release_bundle(repo, self.release)
        # A failed first install remains stopped with its config for diagnosis.
        # It is never declared ready merely because systemd accepted 'start'.
        directory.mkdir(parents=True, mode=0o700)
        meta = {"node_id": node_id, "panel_id": profile_id, "repo": repo, "release": self.release,
                "node_version": manifest["node_version"], "config_schema": SCHEMA, "spec": spec,
                "certificate": certificate, "installed": True, "last_ready": False, "previous": None}
        write_json(directory / "config.yml", make_config(node_id, profile, spec, certificate))
        atomic(directory / "credentials.env", env_text(profile["token"]))
        if cert_files:
            atomic(directory / "tls/fullchain.pem", cert_files[0])
            atomic(directory / "tls/privkey.pem", cert_files[1])
        unit = make_unit(node_id, self.release, spec, certificate)
        atomic(directory / "service.unit", unit)
        write_json(directory / "node.json", meta)
        write_json(ROOT / "panels" / (profile_id + ".json"), profile)
        atomic(UNITS / service_name(node_id), unit, 0o644)
        since = time.time()
        try:
            command("systemctl", "daemon-reload")
            command("systemctl", "enable", "--now", service_name(node_id))
            wait_ready(node_id, spec, since, 180 if certificate["cert_mode"] == "http" else 75)
        except (Error, OSError, KeyboardInterrupt):
            command("systemctl", "disable", "--now", service_name(node_id), check=False)
            print("安装检查失败，已停止此节点；配置保留供排查，没有停止其他服务。")
            raise
        meta["last_ready"] = True
        write_json(directory / "node.json", meta)
        print(f"节点 {node_id} 安装完成。请放行 {spec['transport']} {spec['port']}；客户端连接和设备上报待实际测试。")

    def nodes(self):
        return [read_json(p) for p in sorted(ROOT.glob("node-*/node.json"))]

    def select_node(self, value=None, include_removed=False):
        node_id = check_id(value if value is not None else self.ui.ask("节点数字 ID"))
        meta = read_json(node_dir(node_id) / "node.json")
        if not include_removed and not meta.get("installed"):
            raise Error("节点已卸载并保留配置，可选择恢复。")
        return meta

    def show(self):
        print("\nID       协议         端口/传输       程序版本                 状态")
        for meta in self.nodes():
            state = "运行中" if active(meta["node_id"]) else ("已停止" if meta.get("installed") else "已卸载/保留配置")
            spec = meta["spec"]
            print(f"{meta['node_id']:<8} {spec['label']:<12} {spec['port']}/{spec['transport']:<9} {meta['release']:<24} {state}")
        print("服务状态不等于客户端可用性；上线后需实际连接验证。")

    def update(self, node_id=None, release=None, confirmed=False):
        meta = self.select_node(node_id)
        node_id = meta["node_id"]
        release = check_release(release or self.ui.ask("目标工具 Release 版本，例如 v0.2.1"))
        if release == meta["release"]:
            raise Error("该节点已使用此版本。")
        directory = node_dir(node_id)
        profile = read_json(ROOT / "panels" / (meta["panel_id"] + ".json"))
        _, spec = self.fetch_spec(profile, node_id)
        if spec != meta["spec"]:
            raise Error("面板协议/端口已变化。请先处理配置变化，再单独更新程序。")
        if not confirmed and not self.ui.confirm(f"仅更新节点 {node_id} 到 {release}，会短暂重启此节点"):
            return
        manifest = release_bundle(meta["repo"], release)
        saved = snapshot(node_id)
        was_active = active(node_id)
        try:
            new = dict(meta, release=release, node_version=manifest["node_version"], previous=str(saved), last_ready=False)
            unit = make_unit(node_id, release, spec, meta["certificate"])
            atomic(directory / "service.unit", unit)
            atomic(UNITS / service_name(node_id), unit, 0o644)
            write_json(directory / "node.json", new)
            command("systemctl", "daemon-reload")
            since = time.time()
            command("systemctl", "restart", service_name(node_id))
            wait_ready(node_id, spec, since)
            if not was_active:
                command("systemctl", "stop", service_name(node_id))
            new["last_ready"] = True
            write_json(directory / "node.json", new)
        except (Error, OSError, KeyboardInterrupt) as failure:
            try:
                restore_snapshot(node_id, saved, start=was_active)
            except Error:
                raise Error("更新失败且原版本未通过恢复检查。备份位于 " + str(saved)) from None
            detail = str(failure) if isinstance(failure, Error) else "文件操作失败或用户中断"
            raise Error("更新检查失败，已恢复更新前的程序与配置。原因：" + detail) from None
        print("指定节点已更新，客户端连接待复测；其他节点未重启。")

    def update_all(self, release=None):
        release = check_release(release or self.ui.ask("目标工具 Release 版本"))
        nodes = [m for m in self.nodes() if m.get("installed") and m["release"] != release]
        if not nodes:
            print("没有需要更新的节点。")
            return
        if not self.ui.confirm(f"依次更新 {len(nodes)} 个节点到 {release}；首个失败后停止后续更新"):
            return
        for meta in nodes:
            self.update(meta["node_id"], release, confirmed=True)

    def rollback(self, node_id=None):
        meta = self.select_node(node_id)
        if not meta.get("previous"):
            raise Error("该节点没有保存的上一次更新快照。")
        if self.ui.confirm("恢复此节点更新前的程序与配置"):
            saved = snapshot(meta["node_id"])
            was_active = active(meta["node_id"])
            try:
                restore_snapshot(meta["node_id"], meta["previous"], start=was_active)
            except (Error, OSError, KeyboardInterrupt):
                restore_snapshot(meta["node_id"], saved, start=was_active)
                raise Error("目标旧版本未通过回退检查，已恢复回退操作前的版本。") from None
            print("回退完成，客户端连接待复测。")

    def connection(self, node_id=None):
        meta = self.select_node(node_id)
        node_id = meta["node_id"]
        profile_id, profile = self.choose_profile()
        _, spec = self.fetch_spec(profile, node_id)
        if spec != meta["spec"]:
            raise Error("新面板的协议或端口不同；请先在后台核对，未覆盖本机配置。")
        if not self.ui.confirm(f"替换节点 {node_id} 的面板连接并重启此节点"):
            return
        saved = snapshot(node_id)
        was_active = active(node_id)
        directory = node_dir(node_id)
        try:
            cfg = read_json(directory / "config.yml")
            cfg["panel"]["url"] = profile["url"]
            write_json(directory / "config.yml", cfg)
            atomic(directory / "credentials.env", env_text(profile["token"]))
            new = dict(meta, panel_id=profile_id, previous=str(saved))
            write_json(directory / "node.json", new)
            write_json(ROOT / "panels" / (profile_id + ".json"), profile)
            since = time.time()
            command("systemctl", "restart", service_name(node_id))
            wait_ready(node_id, spec, since)
            if not was_active:
                command("systemctl", "stop", service_name(node_id))
        except (Error, OSError, KeyboardInterrupt):
            restore_snapshot(node_id, saved, start=was_active)
            raise Error("连接变更失败，已恢复原连接。") from None
        print("此节点连接已更新；其他节点的凭据保持。")

    def certificate(self, node_id=None):
        meta = self.select_node(node_id)
        node_id = meta["node_id"]
        profile = read_json(ROOT / "panels" / (meta["panel_id"] + ".json"))
        raw, spec = self.fetch_spec(profile, node_id)
        if spec != meta["spec"]:
            raise Error("面板配置已变化，请先核对节点协议与端口。")
        if not spec["needs_cert"]:
            raise Error("此节点不需要普通 TLS 证书。")
        certificate, files = self.choose_certificate(node_id, spec, raw)
        if not self.ui.confirm(f"更新节点 {node_id} 的证书策略并重启此节点"):
            return
        saved = snapshot(node_id)
        was_active = active(node_id)
        directory = node_dir(node_id)
        try:
            if files:
                atomic(directory / "tls/fullchain.pem", files[0])
                atomic(directory / "tls/privkey.pem", files[1])
            write_json(directory / "config.yml", make_config(node_id, profile, spec, certificate))
            unit = make_unit(node_id, meta["release"], spec, certificate)
            atomic(directory / "service.unit", unit)
            atomic(UNITS / service_name(node_id), unit, 0o644)
            write_json(directory / "node.json", dict(meta, certificate=certificate, previous=str(saved)))
            command("systemctl", "daemon-reload")
            since = time.time()
            command("systemctl", "restart", service_name(node_id))
            wait_ready(node_id, spec, since, 180 if certificate["cert_mode"] == "http" else 75)
            if not was_active:
                command("systemctl", "stop", service_name(node_id))
        except (Error, OSError, KeyboardInterrupt):
            restore_snapshot(node_id, saved, start=was_active)
            raise Error("证书更新失败，已恢复更新前的配置与证书。") from None
        print("此节点证书已更新，客户端 TLS 连接待复测。")

    def control(self, action=None, node_id=None):
        meta = self.select_node(node_id)
        action = action or self.ui.ask("操作：start / stop / restart", "restart")
        if action not in ("start", "stop", "restart"):
            raise Error("服务操作无效。")
        since = time.time()
        command("systemctl", action, service_name(meta["node_id"]))
        if action != "stop":
            wait_ready(meta["node_id"], meta["spec"], since, 180 if meta["certificate"]["cert_mode"] == "http" else 75)
        print("此节点操作完成。")

    def restore(self, node_id=None):
        meta = self.select_node(node_id, include_removed=True)
        if meta.get("installed"):
            raise Error("该节点尚未卸载，可直接启动或排查。")
        spec = meta["spec"]
        profile = read_json(ROOT / "panels" / (meta["panel_id"] + ".json"))
        _, current = self.fetch_spec(profile, meta["node_id"])
        if spec != current:
            raise Error("面板配置已变化，不能直接恢复旧配置。")
        port_free(spec["port"], spec["transport"])
        atomic(UNITS / service_name(meta["node_id"]), (node_dir(meta["node_id"]) / "service.unit").read_bytes(), 0o644)
        command("systemctl", "daemon-reload")
        since = time.time()
        try:
            command("systemctl", "enable", "--now", service_name(meta["node_id"]))
            wait_ready(meta["node_id"], spec, since, 180 if meta["certificate"]["cert_mode"] == "http" else 75)
        except (Error, OSError, KeyboardInterrupt):
            command("systemctl", "disable", "--now", service_name(meta["node_id"]), check=False)
            raise Error("恢复检查失败，服务已停止，保留原配置供排查。") from None
        meta.update(installed=True, last_ready=True)
        write_json(node_dir(meta["node_id"]) / "node.json", meta)
        print("节点已从保留配置恢复。")

    def uninstall(self, node_id=None):
        meta = self.select_node(node_id)
        node_id = meta["node_id"]
        if not self.ui.confirm(f"停止并卸载本机节点 {node_id}，配置、证书及备份保留；后台记录不变"):
            return
        saved = snapshot(node_id)
        command("systemctl", "disable", "--now", service_name(node_id))
        unit = UNITS / service_name(node_id)
        if unit.is_symlink():
            raise Error("拒绝删除异常服务符号链接。")
        unit.unlink()
        command("systemctl", "daemon-reload")
        meta.update(installed=False, last_ready=False)
        write_json(node_dir(node_id) / "node.json", meta)
        print("已卸载此服务，配置与恢复快照保留：" + str(saved))

    def logs(self, node_id=None):
        meta = self.select_node(node_id, include_removed=True)
        data = command("journalctl", "-u", service_name(meta["node_id"]), "-n", "60", "--no-pager", "-o", "cat").stdout
        for _, profile in self.profiles():
            data = data.replace(profile["token"], "[REDACTED]")
        data = re.sub(r"([?&](?:token|key|api_key)=)[^\s&\"']+", r"\1[REDACTED]", data, flags=re.I)
        print(data)

    def diagnose(self, node_id=None, unit=None, port=None, transport='tcp', json_output=False):
        if unit is None:
            meta = self.select_node(node_id, include_removed=True)
            unit = service_name(meta['node_id'])
            port, transport = meta['spec']['port'], meta['spec']['transport']
        report = diagnose_service(unit, port, transport)
        if json_output:
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return report
        labels = {'service':'服务', 'state':'服务状态', 'substate':'运行状态', 'pid':'进程号', 'version':'实际运行版本',
                  'binary_sha256':'实际程序摘要', 'restarts':'重启次数', 'cpu_percent_one_core':'CPU（单核百分比）',
                  'cpu_total_ns':'累计 CPU 纳秒', 'rss_bytes':'RSS 字节', 'pss_bytes':'PSS 字节', 'cgroup_memory_bytes':'cgroup 内存字节',
                  'fds':'句柄数', 'threads':'线程数', 'socket_rows':'该进程 socket 行数', 'listener_owned':'目标监听归属',
                  'loaded_users':'最近日志中的加载用户数', 'loaded_at':'加载时间（UTC）', 'last_report_at':'最近成功 REST 上报（UTC）'}
        for key, label in labels.items():
            print(label + '：' + ('未知/不可用' if report[key] is None else str(report[key])))
        print('连接可用性：未知；服务 active、日志与监听不能代替真实客户连通验收。RSS、PSS 与 cgroup 口径不同，不相加。')
        return report

    def prune(self, keep_releases=2, keep_snapshots=3, pins=(), apply=False):
        plan = retention_plan(keep_releases, keep_snapshots, pins)
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        if not apply or not plan['candidates']:
            print('仅预览，没有删除文件。')
            return plan
        if not self.ui.confirm('确认只删除以上未被引用的旧程序/快照（不涉及运行数据）'):
            return plan
        # Recompute after confirmation while holding the manager mutation lock.
        fresh = retention_plan(keep_releases, keep_snapshots, pins)
        if fresh['candidates'] != plan['candidates']:
            raise Error('保护引用已变化，请重新预览。')
        for value in fresh['candidates']:
            path = Path(value)
            if path.is_symlink() or path.parent not in (LIB / 'releases', ROOT / 'backups'):
                raise Error('候选路径异常，停止清理。')
            shutil.rmtree(path)
        fresh['preview'] = False
        return fresh

    def menu(self):
        while True:
            self.show()
            print("\n1. 添加节点  2. 脱敏日志  3. 启停/重启  4. 更新指定节点")
            print("5. 回退版本  6. 修改节点连接  7. 卸载/保留配置  8. 恢复保留节点  0. 退出")
            print("9. 依次更新全部节点（失败即停）  10. 更新 TLS 证书  11. 本机诊断  12. 清理预览")
            choice = self.ui.ask("请选择", "0")
            if choice == "0":
                return
            actions = {"1": self.add, "2": self.logs, "3": self.control, "4": self.update,
                       "5": self.rollback, "6": self.connection, "7": self.uninstall, "8": self.restore,
                       "9": self.update_all, "10": self.certificate, "11": self.diagnose, "12": self.prune}
            if choice not in actions:
                print("选项无效。")
                continue
            try:
                with mutation_lock():
                    actions[choice]()
            except Error as error:
                print("未完成：" + str(error))


@contextlib.contextmanager
def mutation_lock():
    path = Path("/run/lock/xbnode.lock")
    with path.open("a+") as lock:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("另一项 xbnode 维护操作正在进行。") from None
        yield


def require_host():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise Error("请在 Linux 节点主机上以 root / sudo 运行。")
    architecture()
    if not Path("/run/systemd/system").is_dir():
        raise Error("需要正常运行 systemd 的主机，不能直接用于普通容器或非 systemd 系统。")
    for name in ("systemctl", "journalctl", "ss"):
        if not shutil.which(name):
            raise Error("缺少 " + name + "；Debian/Ubuntu 可安装 systemd 与 iproute2。")
    match = re.search(r"systemd (\d+)", command("systemctl", "--version").stdout)
    if not match or int(match.group(1)) < 247:
        raise Error("需要 systemd 247 或以上版本（例如 Debian 12 / Ubuntu 22.04+）。")


def main():
    parser = argparse.ArgumentParser(description="Xboard-Node 中文节点管理（不自动迁移现有 XrayR）")
    parser.add_argument("action", nargs="?", default="menu", choices=["menu", "add", "list", "logs", "start", "stop", "restart", "update", "update-all", "rollback", "connection", "certificate", "uninstall", "restore", "diagnose", "prune"])
    parser.add_argument("node_id", nargs="?", type=check_id)
    parser.add_argument("--repo")
    parser.add_argument("--release")
    parser.add_argument("--bootstrap-manifest", type=Path)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument('--json', action='store_true', dest='json_output')
    parser.add_argument('--service', help='只读诊断已有 xbnode-ID / xboard-node-ID 服务')
    parser.add_argument('--port', type=int)
    parser.add_argument('--transport', choices=['tcp', 'udp', 'tcp+udp'], default='tcp')
    parser.add_argument('--keep-releases', type=int, default=2)
    parser.add_argument('--keep-snapshots', type=int, default=3)
    parser.add_argument('--pin', action='append', default=[])
    parser.add_argument('--apply', action='store_true', help='预览后还需明确确认才清理')
    args = parser.parse_args()
    require_host()
    os.umask(0o077)
    manager = Manager(args.repo, args.release or VERSION)
    if args.bootstrap_manifest:
        validate_manifest(read_json(args.bootstrap_manifest), args.release)
        if args.release != VERSION:
            raise Error("管理脚本版本与请求的 Release 不一致。")
        with mutation_lock():
            ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
            manager.install_manager()
        print("管理命令已安装：xbnode。尚未创建或启动任何节点。")
    elif args.action != "diagnose" and not (ROOT / "settings.json").exists():
        raise Error("请先通过 install.sh 安装管理命令。")
    if args.action == "menu":
        manager.menu()
    elif args.action == "list":
        manager.show()
    elif args.action == "diagnose":
        manager.diagnose(args.node_id, args.service, args.port, args.transport, args.json_output)
    elif args.action == "logs":
        manager.logs(args.node_id)
    else:
        with mutation_lock():
            if args.action == "prune":
                manager.prune(args.keep_releases, args.keep_snapshots, args.pin, args.apply)
            elif args.action in ("start", "stop", "restart"):
                manager.control(args.action, args.node_id)
            elif args.action == "add":
                manager.add()
            elif args.action == "update":
                manager.update(args.node_id, args.release)
            elif args.action == "update-all":
                manager.update_all(args.release)
            else:
                getattr(manager, args.action)(args.node_id)


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, KeyboardInterrupt) as error:
        print("未完成：" + (str(error) if isinstance(error, Error) else "文件操作失败或用户中断；请用 xbnode list 核对当前状态。"), file=sys.stderr)
        sys.exit(1)
