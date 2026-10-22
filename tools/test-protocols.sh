#!/usr/bin/env bash
set -Eeuo pipefail
xb_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
xb_go="${XBN_GO:-go}"
xb_src="$xb_root/.build/source"
[[ -d "$xb_src" && -f "$xb_root/dist/xboard-node-linux-amd64" ]] || {
  printf '%s\n' '先执行 python3 tools/build.py。' >&2; exit 1;
}
# CLI-only dependencies are resolved in a separate modfile. The released
# node's go.mod/go.sum remain byte-for-byte equal to the pinned upstream.
cp "$xb_src/maintenance.mod" "$xb_root/.build/client.mod"
cp "$xb_src/maintenance.sum" "$xb_root/.build/client.sum"
(
  cd "$xb_src"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local "$xb_go" build \
    -mod=mod -modfile="$xb_root/.build/client.mod" -trimpath -buildvcs=false \
    -tags 'with_quic with_utls with_wireguard with_acme with_clash_api' \
    -o "$xb_root/.build/singbox-test-client" github.com/sagernet/sing-box/cmd/sing-box
)
(
  cd "$xb_src"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local "$xb_go" build \
    -mod=mod -modfile="$xb_root/.build/client.mod" -trimpath -buildvcs=false \
    -o "$xb_root/.build/xray-test-client" github.com/xtls/xray-core/main
)
xb_image="${XBN_TEST_IMAGE:-python:3.12-bookworm}"
xb_platform="${XBN_TEST_PLATFORM:-linux/amd64}"
for xb_arch in amd64 arm64; do
  docker run --rm --platform "$xb_platform" --network none --read-only \
    --tmpfs /tmp:rw,nosuid,size=256m \
    -v "$xb_root:/package:ro" \
    -v "$xb_root/.build/singbox-test-client:/test-client:ro" \
    --entrypoint python "$xb_image" /package/tests/protocol_smoke.py \
    --binary "/package/dist/xboard-node-linux-${xb_arch}" --client /test-client
  docker run --rm --platform "$xb_platform" --network none --read-only \
    --tmpfs /tmp:rw,nosuid,size=256m -v "$xb_root:/package:ro" \
    -v "$xb_root/.build/xray-test-client:/xray-client:ro" \
    --entrypoint python "$xb_image" /package/tests/mux_smoke.py \
    --binary "/package/dist/xboard-node-linux-${xb_arch}" --client /xray-client
  docker run --rm --platform "$xb_platform" --network none --read-only \
    --tmpfs /tmp:rw,nosuid,size=256m -v "$xb_root:/package:ro" \
    -v "$xb_root/.build/singbox-test-client:/test-client:ro" \
    --entrypoint python "$xb_image" /package/tests/protocol_smoke.py \
    --binary "/package/dist/xboard-node-linux-${xb_arch}" --client /test-client --only vless --reality
done
