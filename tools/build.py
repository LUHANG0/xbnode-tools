#!/usr/bin/env python3
"""Build both architectures from an exact upstream commit plus reviewed patches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from prepare_dependencies import prepare

BASE = Path(__file__).resolve().parents[1]


def run(*args, cwd=None, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go")
    parser.add_argument("--arch", action="append", choices=["amd64", "arm64"])
    parser.add_argument("--skip-tests", action="store_true", help="Local reuse of tests already run on identical patched sources; CI never uses this.")
    args = parser.parse_args()
    lock = json.loads((BASE / "release.json").read_text())
    work = BASE / ".build" / "source"
    work.parent.mkdir(exist_ok=True)
    if work.exists():
        for p in work.rglob("*"):
            if p.is_dir() and not p.is_symlink(): p.chmod(0o755)
        shutil.rmtree(work)
    run("git", "init", "-q", str(work))
    run("git", "-C", str(work), "remote", "add", "origin", lock["upstream"])
    run("git", "-C", str(work), "fetch", "--depth=1", "origin", lock["upstream_commit"])
    run("git", "-C", str(work), "checkout", "--detach", "FETCH_HEAD")
    patches = []
    for name in lock["patches"]:
        path = BASE / name
        run("git", "-C", str(work), "apply", "--check", str(path))
        run("git", "-C", str(work), "apply", str(path))
        patches.append({"file": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    modfile=prepare(work,args.go,BASE/'overlays')
    env = dict(os.environ, GOTOOLCHAIN="local")
    actual = subprocess.check_output([args.go, "version"], text=True, env=env)
    if "go" + lock["go_version"] + " " not in actual:
        raise SystemExit("Wrong Go toolchain; expected " + lock["go_version"])
    if not args.skip_tests:
        run(args.go, "test", "-modfile", str(modfile), "-race", "-count=1", "-tags", lock["build_tags"], "./internal/config", "./internal/cert", "./internal/service", "./internal/kernel/xray", "./internal/kernel/singbox", "./internal/tracker", "./internal/panel", "github.com/sagernet/sing-quic/hysteria2", "github.com/sagernet/sing-quic/tuic", cwd=work, env=dict(env, CGO_ENABLED="1"))
    dist = BASE / "dist"
    dist.mkdir(exist_ok=True)
    for arch in args.arch or ["amd64", "arm64"]:
        target = dist / ("xboard-node-linux-" + arch)
        run(args.go, "build", "-modfile", str(modfile), "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", lock["build_tags"],
            "-ldflags", "-s -w -X main.version=" + lock["node_version"] + " -X main.buildTime=2026-10-23",
            "-o", str(target), "./cmd/xboard-node", cwd=work, env=dict(env, CGO_ENABLED="0", GOOS="linux", GOARCH=arch))
    manifest = {"release": lock["release"], "node_version": lock["node_version"], "config_schema": lock["config_schema"],
                "upstream_commit": lock["upstream_commit"], "upstream": lock["upstream"], "go_version": lock["go_version"],
                "build_tags": lock["build_tags"], "maintenance_patches": patches, "manager_schema": 1, "dependency_patches": [{**e,"sha256":hashlib.sha256((BASE/"overlays"/e["file"]).read_bytes()).hexdigest()} for e in json.loads((BASE/"overlays/lock.json").read_text())],
                "features": ["device_snapshot_refresh_v1", "local_cert_override_v1", "singbox_atomic_device_limit_v1", "xray_context_release_v1", "traffic_retirement_delta_v1", "precise_user_revocation_v1", "local_traffic_outbox_v1", "quic_stable_user_identity_v1"]}
    (dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in ("xbnode.py", "install.sh", "LICENSE", "NOTICE"):
        shutil.copyfile(BASE / name, dist / name)
    with tarfile.open(dist / "patched-source.tar.gz", "w:gz") as archive:
        for path in sorted(work.rglob("*")):
            rel = path.relative_to(work)
            if ".git" not in rel.parts and path.is_file():
                archive.add(path, arcname="xboard-node/" + str(rel))
    names = sorted(p.name for p in dist.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (dist / "SHA256SUMS").write_text("".join(hashlib.sha256((dist / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in names))
    print("Release assets: " + str(dist))


if __name__ == "__main__":
    main()
