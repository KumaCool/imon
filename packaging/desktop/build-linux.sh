#!/bin/sh
set -eu

usage() {
  printf 'Usage: %s vMAJOR.MINOR.PATCH [OUTPUT_PARENT]\n' "$0" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
tag=$1
printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$' || usage
version=${tag#v}
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  printf 'This packager requires an amd64 Linux host.\n' >&2
  exit 1
fi
for tool in pkg-config cc c++ dpkg-deb sha256sum; do
  command -v "$tool" > /dev/null
done
pkg-config --print-errors --exists gtk+-3.0 'webkit2gtk-4.1 >= 2.40'
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
out_parent=${2:-"$src/dist/desktop"}
mkdir -p -- "$out_parent/$tag"
out_parent=$(CDPATH='' cd -- "$out_parent/$tag" && pwd -P)
out="$out_parent/linux-amd64"
if [ -e "$out" ] || [ -L "$out" ]; then
  printf 'Desktop output already exists: %s\n' "$out" >&2
  exit 1
fi
work=$(mktemp -d "$out_parent/.desktop.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
stage="$work/package"
mkdir -p "$work/src" "$work/assets" "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/applications" \
  "$stage/usr/share/doc/imon-desktop"
cp "$src/go.mod" "$src/go.sum" "$work/src/"
cp -R "$src/cmd" "$src/internal" "$src/web" "$work/src/"

cd "$work/src"
export GOFLAGS='' GOWORK=off GOAMD64=v1 GOARM64=v8.0
for target in amd64 arm64; do
  printf 'Building Linux firewall reader (%s)\n' "$target"
  CGO_ENABLED=0 GOOS=linux GOARCH="$target" "$go_bin" build -buildvcs=false -trimpath -ldflags='-s -w' \
    -o "internal/firewall/bundles/firewall-read-$target" ./cmd/imon-firewall
done
IMON_REQUIRE_BUNDLES=1 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go_bin" test -count=1 ./internal/firewall
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "$go_bin" build -tags desktop -buildvcs=false -trimpath \
  -ldflags="-s -w -X main.version=$tag" -o "$stage/usr/bin/imon-desktop" ./cmd/imon-desktop
[ "$("$stage/usr/bin/imon-desktop" --version)" = "$tag" ]

cp "$src/packaging/desktop/imon.desktop" "$stage/usr/share/applications/"
cp "$src/internal/desktop/vendor/LICENSE" "$stage/usr/share/doc/imon-desktop/webview-copyright"
cp "$src/docs/guides/backup-and-restore.md" "$stage/usr/share/doc/imon-desktop/"
installed_size=$(du -sk "$stage" | cut -f1)
printf '%s\n' \
  'Package: imon-desktop' "Version: $version" 'Architecture: amd64' \
  'Maintainer: Imon Project <maintainers@example.invalid>' 'Section: admin' 'Priority: optional' \
  "Installed-Size: $installed_size" \
  'Depends: libwebkit2gtk-4.1-0 (>= 2.40), libgtk-3-0t64 | libgtk-3-0, fonts-noto-cjk | fonts-wqy-zenhei' \
  'Conflicts: infra-monitor-desktop' 'Replaces: infra-monitor-desktop' \
  'Description: Local infrastructure monitoring desktop panel' \
  ' Monitor Linux hosts and Kubernetes clusters without starting a Web server.' \
  > "$stage/DEBIAN/control"
archive='imon-desktop_linux_amd64.deb'
dpkg-deb --root-owner-group --build "$stage" "$work/assets/$archive"
(cd "$work/assets" && sha256sum "$archive" > SHA256SUMS)
mv -- "$work/assets" "$out"
printf 'Desktop assets: %s\n' "$out"
