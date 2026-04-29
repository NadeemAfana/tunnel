#!/bin/bash
# Cross-compiles the udp-bridge helper binary for the supported client
# platforms. Output goes to dist/. Upload the contents of dist/ to your
# GitHub release to match the {os}-{arch} naming expected by tunnel.sh.
#
# Version is injected at link time via -ldflags. Override via env:
#   VERSION=1.0 ./build-bridge.sh
set -euo pipefail

VERSION="${VERSION:-1.0}"
mkdir -p dist
targets=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64")

echo "Building udp-bridge version $VERSION"
echo

for t in "${targets[@]}"; do
  os="${t%/*}"
  arch="${t#*/}"
  ext=""
  [[ "$os" == "windows" ]] && ext=".exe"

  out="dist/udp-bridge-${os}-${arch}${ext}"
  echo "Building $out"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 \
    go build -ldflags="-s -w -X main.version=$VERSION" -trimpath \
    -o "$out" \
    ./cmd/udp-bridge
done

echo
echo "Done. Built artifacts:"
ls -la dist/
echo
echo "Upload these to your GitHub release. Then set:"
echo "  export TUNNEL_BRIDGE_URL='https://github.com/<owner>/<repo>/releases/latest/download/udp-bridge-{os}-{arch}'"
