#!/bin/sh
set -eu

usage() {
  printf 'Usage: %s vMAJOR.MINOR.PATCH [OUTPUT_PARENT [amd64|arm64]]\n' "$0" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 3 ] || usage
tag=$1
printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$' || usage
version=${tag#v}
if [ "$(uname -s)" != Darwin ]; then
  printf 'This packager requires macOS with Xcode Command Line Tools.\n' >&2
  exit 1
fi
xcrun --find clang >/dev/null
xcrun --find clang++ >/dev/null
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
arch=${3:-$("$go_bin" env GOHOSTARCH)}
case "$arch" in amd64|arm64) ;; *) usage ;; esac

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
repo=$(sh "$src/packaging/release/repository.sh" "$src")
out_parent=${2:-"$src/dist/desktop"}
mkdir -p -- "$out_parent/$tag"
out_parent=$(CDPATH='' cd -- "$out_parent/$tag" && pwd -P)
out="$out_parent/darwin-$arch"
if [ -e "$out" ] || [ -L "$out" ]; then
  printf 'Desktop output already exists: %s\n' "$out" >&2
  exit 1
fi
work=$(mktemp -d "$out_parent/.desktop.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
app="$work/Imon.app"
mkdir -p "$work/src" "$work/assets" "$app/Contents/MacOS" "$app/Contents/Resources/Licenses"
cp "$src/go.mod" "$src/go.sum" "$work/src/"
cp -R "$src/cmd" "$src/internal" "$src/web" "$work/src/"
sh "$src/packaging/release/build-helpers.sh" "$tag" "$go_bin" "$work/src"
cd "$work/src"
export GOFLAGS='' GOWORK=off GOAMD64=v1 GOARM64=v8.0

CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" MACOSX_DEPLOYMENT_TARGET=13.0 \
  "$go_bin" build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$tag -X main.defaultReleaseRepo=$repo" \
  -o "$app/Contents/MacOS/imon-desktop" ./cmd/imon-desktop
cp "$src/packaging/desktop/Info.plist" "$app/Contents/Info.plist"
cp "$src/packaging/desktop/imon.icns" "$app/Contents/Resources/"
plutil -replace CFBundleShortVersionString -string "$version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$version" "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
cp "$src/internal/desktop/vendor/LICENSE" "$app/Contents/Resources/Licenses/webview.txt"
cp "$src/docs/guides/backup-and-restore.md" "$app/Contents/Resources/"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
archive="imon-desktop_darwin_$arch.zip"
ditto -c -k --keepParent "$app" "$work/assets/$archive"
(cd "$work/assets" && shasum -a 256 "$archive" > SHA256SUMS)
mv -- "$work/assets" "$out"
printf 'Desktop assets: %s\n' "$out"
