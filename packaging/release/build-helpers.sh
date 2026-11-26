#!/bin/sh
set -eu

tag=$1
go_bin=$2
staged_source=$3
key_file=${IMON_HELPER_SIGNING_KEY_FILE:-}
case "$key_file" in
  /*|'') ;;
  *) key_file="$PWD/$key_file" ;;
esac

if [ -z "$key_file" ] && [ "${IMON_ALLOW_UNSIGNED_HELPER:-0}" != 1 ]; then
  printf '%s\n' 'Set IMON_HELPER_SIGNING_KEY_FILE for a signed release, or IMON_ALLOW_UNSIGNED_HELPER=1 for a local test package.' >&2
  exit 1
fi

cd "$staged_source"
export GOFLAGS='' GOWORK=off CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0
export IMON_HELPER_SIGNING_KEY_FILE="$key_file"
host_os=$("$go_bin" env GOHOSTOS)
host_arch=$("$go_bin" env GOHOSTARCH)
sign() { GOOS="$host_os" GOARCH="$host_arch" "$go_bin" run ./cmd/imon-helper-sign "$@"; }

linker='-s -w'
if [ -n "$key_file" ]; then
  public=$(sign public)
  linker="$linker -X main.updateBuild=$public"
fi

for arch in amd64 arm64; do
  bundle="internal/firewall/bundles/firewall-read-$arch"
  printf 'Building Linux host helper (%s)\n' "$arch"
  GOOS=linux GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath -ldflags="$linker" \
    -o "$bundle" ./cmd/imon-firewall
  if [ -n "$key_file" ]; then
    sign sign "$tag" "$arch" "$bundle" > "$bundle.json"
  else
    rm -- "$bundle.json" 2>/dev/null || :
  fi
done

signed=0
if [ -n "$key_file" ]; then signed=1; fi
GOOS="$host_os" GOARCH="$host_arch" IMON_REQUIRE_BUNDLES=1 IMON_REQUIRE_SIGNED_HELPERS="$signed" \
  "$go_bin" test -count=1 ./internal/firewall
