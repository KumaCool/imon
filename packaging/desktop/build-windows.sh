#!/bin/sh
set -eu

usage() {
  printf 'Usage: WEBVIEW2_SDK_INCLUDE=<SDK_INCLUDE_DIR> %s vMAJOR.MINOR.PATCH [OUTPUT_PARENT]\n' "$0" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
tag=$1
printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$' || usage
version=${tag#v}
sdk=${WEBVIEW2_SDK_INCLUDE:-}
if [ -z "$sdk" ] || [ ! -f "$sdk/WebView2.h" ]; then
  printf 'Set WEBVIEW2_SDK_INCLUDE to the SDK 1.0.1150.38 build/native/include directory.\n' >&2
  exit 1
fi
sdk=$(CDPATH='' cd -- "$sdk" && pwd -P)
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
cc=$(command -v "${CC:-x86_64-w64-mingw32-gcc}")
cxx=$(command -v "${CXX:-x86_64-w64-mingw32-g++}")
windres=$(command -v "${WINDRES:-x86_64-w64-mingw32-windres}")
command -v makensis >/dev/null
if command -v sha256sum >/dev/null; then
  checksum() { sha256sum "$@"; }
else
  checksum() { shasum -a 256 "$@"; }
fi
src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo=$(sh "$src/packaging/release/repository.sh" "$src")
out_parent=${2:-"$src/dist/desktop"}
mkdir -p -- "$out_parent/$tag"
out_parent=$(CDPATH='' cd -- "$out_parent/$tag" && pwd -P)
out="$out_parent/windows-amd64"
if [ -e "$out" ] || [ -L "$out" ]; then
  printf 'Desktop output already exists: %s\n' "$out" >&2
  exit 1
fi
work=$(mktemp -d "$out_parent/.desktop.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/src" "$work/assets" "$work/payload"
cp "$src/go.mod" "$src/go.sum" "$work/src/"
cp -R "$src/cmd" "$src/internal" "$src/web" "$work/src/"
sh "$src/packaging/release/build-helpers.sh" "$tag" "$go_bin" "$work/src"
cd "$work/src"
export GOFLAGS='' GOWORK=off GOAMD64=v1 GOARM64=v8.0
(cd "$src/packaging/desktop" && "$windres" --target=pe-x86-64 --output-format=coff \
  --input=imon-icon.rc --output="$work/src/cmd/imon-desktop/imon_windows_amd64.syso")
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC="$cc" CXX="$cxx" CGO_CXXFLAGS="-I \"$sdk\"" \
  "$go_bin" build -tags desktop -buildvcs=false -trimpath \
  -ldflags="-s -w -H=windowsgui -X main.version=$tag -X main.defaultReleaseRepo=$repo" \
  -o "$work/payload/imon-desktop.exe" ./cmd/imon-desktop
cp "$src/internal/desktop/vendor/LICENSE" "$work/payload/WebView-LICENSE.txt"
cp "$src/docs/guides/backup-and-restore.md" "$work/payload/"
cp "$src/packaging/desktop/installer-windows.nsi" "$work/installer.nsi"
cp "$src/packaging/desktop/imon.ico" "$work/"
exe=imon-desktop_windows_amd64_setup.exe
(cd "$work" && makensis -V2 "-DVERSION=$version" "-DOUTFILE=assets/$exe" installer.nsi)
(cd "$work/assets" && checksum "$exe" > SHA256SUMS)
mv -- "$work/assets" "$out"
printf 'Desktop assets: %s\n' "$out"
