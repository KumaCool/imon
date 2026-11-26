#!/bin/sh
set -eu

[ "$#" = 2 ] || exit 2
arch=$1
case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
out=$(CDPATH='' cd -- "$2" && pwd -P)
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$scratch/src"
cp "$src/go.mod" "$src/go.sum" "$scratch/src/"
cp -R "$src/internal" "$src/cmd" "$src/packaging" "$scratch/src/"
cp "$src/packaging/linux-smoke/Dockerfile" "$src/packaging/linux-smoke/fixture.sh" "$out/"
cd "$scratch/src"
export CGO_ENABLED=0 GOWORK=off GOFLAGS=''

host_os=$("$go_bin" env GOHOSTOS)
host_arch=$("$go_bin" env GOHOSTARCH)
sign() { GOOS="$host_os" GOARCH="$host_arch" "$go_bin" run ./cmd/imon-helper-sign "$@"; }
export_fixture() {
  GOOS="$host_os" GOARCH="$host_arch" "$go_bin" run ./packaging/linux-smoke "$@" "$arch"
}
bundle=internal/firewall/bundles/firewall-read-$arch
rm -f -- "$bundle.json"
GOOS=linux GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath -o "$bundle" ./cmd/imon-firewall
export_fixture script > "$out/legacy-install.sh"

# Always generate a private one-use signing key for this disposable fixture.
umask 077
IMON_HELPER_SIGNING_KEY_FILE="$scratch/smoke-key.pem"
export IMON_HELPER_SIGNING_KEY_FILE
openssl genpkey -algorithm ED25519 -out "$IMON_HELPER_SIGNING_KEY_FILE"
public=$(sign public)
build_signed() {
  release=$1
  # Different build IDs let the smoke test verify the executable was replaced.
  GOOS=linux GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath \
    -ldflags="-s -w -X main.updateBuild=$public -buildid=imon-helper-smoke-$release" \
    -o "$bundle" ./cmd/imon-firewall
  sign sign "$release" "$arch" "$bundle" > "$bundle.json"
}
build_signed v0.1.0
export_fixture script > "$out/migration-install.sh"
export_fixture update > "$out/previous-update"
build_signed v0.1.1
GOOS=linux GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath -o "$out/host-smoke" ./packaging/linux-smoke
