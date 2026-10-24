#!/usr/bin/env bash
# Only the repository name and release are accepted here. Secrets are entered
# later on /dev/tty; they are never command-line arguments.
set +x
set -Eeuo pipefail
umask 077
xb_repo="${XBN_REPO:-}"
xb_release="v0.2.2"
while (($#)); do
  case "$1" in
    --repo) xb_repo="${2:?--repo 需要 OWNER/REPO}"; shift 2 ;;
    --version) xb_release="${2:?--version 需要版本号}"; shift 2 ;;
    -h|--help)
      printf '%s\n' '用法：sudo bash install.sh --repo OWNER/REPO [--version v0.2.2]'
      printf '%s\n' '仓库需先发布包含 xbnode.py、manifest.json、SHA256SUMS 的公开 Release。'
      exit 0 ;;
    *) printf '未知参数：%s\n' "$1" >&2; exit 2 ;;
  esac
done
if [[ -z "$xb_repo" ]]; then
  read -r -p '请输入你的 GitHub 安装仓库（OWNER/REPO）：' xb_repo </dev/tty
fi
[[ "$xb_repo" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || {
  printf '%s\n' '仓库格式错误，应为 OWNER/REPO。' >&2; exit 2;
}
[[ "$xb_release" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || {
  printf '%s\n' '版本格式错误。' >&2; exit 2;
}
[[ $(id -u) == 0 && $(uname -s) == Linux ]] || {
  printf '%s\n' '请在 Linux 新节点主机上使用 root 或 sudo 运行。' >&2; exit 1;
}
for xb_command in python3 curl sha256sum; do
  command -v "$xb_command" >/dev/null || {
    printf '缺少 %s。Debian/Ubuntu 可先执行：apt-get update && apt-get install -y python3 curl ca-certificates\n' "$xb_command" >&2
    exit 1
  }
done
xb_temp=$(mktemp -d)
trap 'rm -rf -- "$xb_temp"' EXIT
xb_base="https://github.com/${xb_repo}/releases/download/${xb_release}"
for xb_file in SHA256SUMS manifest.json xbnode.py; do
  curl --proto '=https' --proto-redir '=https' -fLsS --retry 3 \
    --connect-timeout 15 --max-time 180 "${xb_base}/${xb_file}" -o "${xb_temp}/${xb_file}"
done
for xb_file in manifest.json xbnode.py; do
  xb_hash=$(awk -v f="$xb_file" '$2 == f { print $1 }' "${xb_temp}/SHA256SUMS")
  [[ "$xb_hash" =~ ^[a-f0-9]{64}$ ]] || { printf '%s\n' '发布校验清单无效。' >&2; exit 1; }
  printf '%s  %s\n' "$xb_hash" "${xb_temp}/${xb_file}" | sha256sum -c -
done
python3 "${xb_temp}/xbnode.py" --repo "$xb_repo" --release "$xb_release" \
  --bootstrap-manifest "${xb_temp}/manifest.json"
