#!/bin/sh
set -eu

usage() {
  printf 'Usage: %s vMAJOR.MINOR.PATCH [OUTPUT_PARENT [GITHUB_OWNER/REPO]]\n' "$0" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 3 ] || usage
tag=$1
case "$tag" in *[!v.0123456789]*) usage ;; esac
printf '%s\n' "$tag" | LC_ALL=C grep -Eq '^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$' || usage
repo=${3:-}
if [ -n "$repo" ]; then
  case "$repo" in */.|*/..|*[!a-zA-Z0-9_./-]*) usage ;; esac
  printf '%s\n' "$repo" | LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9-]{0,39}/[A-Za-z0-9_.-]{1,100}$' || usage
fi

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
out_parent=${2:-"$src/dist"}
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
command -v tar >/dev/null
command -v zip >/dev/null
if command -v sha256sum >/dev/null; then
  checksum() { sha256sum "$@"; }
elif command -v shasum >/dev/null; then
  checksum() { shasum -a 256 "$@"; }
else
  printf 'A SHA-256 tool (sha256sum or shasum) is required.\n' >&2
  exit 1
fi

mkdir -p -- "$out_parent"
out_parent=$(CDPATH='' cd -- "$out_parent" && pwd -P)
out="$out_parent/$tag"
if [ -e "$out" ] || [ -L "$out" ]; then
  printf 'Release output already exists: %s\n' "$out" >&2
  exit 1
fi
work=$(mktemp -d "$out_parent/.release.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/src" "$work/assets" "$work/package"
cp "$src/go.mod" "$src/go.sum" "$work/src/"
cp -R "$src/cmd" "$src/internal" "$src/web" "$work/src/"
cd "$work/src"
export GOFLAGS='' GOWORK=off CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0
for arch in amd64 arm64; do
  printf 'Building Linux firewall reader (%s)\n' "$arch"
  GOOS=linux GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath -ldflags='-s -w' \
    -o "internal/firewall/bundles/firewall-read-$arch" ./cmd/imon-firewall
done
GOOS=$("$go_bin" env GOHOSTOS) GOARCH=$("$go_bin" env GOHOSTARCH) \
  IMON_REQUIRE_BUNDLES=1 "$go_bin" test -count=1 ./internal/firewall

linker="-s -w -X main.version=$tag"
if [ -n "$repo" ]; then
  linker="$linker -X main.defaultReleaseRepo=$repo"
fi
cp "$src/docs/guides/backup-and-restore.md" "$work/package/"
for os in darwin linux windows; do
  binary=imon
  if [ "$os" = windows ]; then
    binary=imon.exe
  fi
  for arch in amd64 arm64; do
    printf 'Building Web client (%s/%s)\n' "$os" "$arch"
    GOOS="$os" GOARCH="$arch" "$go_bin" build -buildvcs=false -trimpath -ldflags="$linker" \
      -o "$work/package/$binary" ./cmd/imon
    archive="$work/assets/imon-web_${os}_${arch}"
    if [ "$os" = windows ]; then
      (cd "$work/package" && zip -q -X "$archive.zip" "$binary" backup-and-restore.md)
    else
      COPYFILE_DISABLE=1 tar --no-xattrs -czf "$archive.tar.gz" -C "$work/package" "$binary" backup-and-restore.md
    fi
  done
  rm -- "$work/package/$binary"
done

(cd "$work/assets" && checksum imon-web_* > SHA256SUMS)
mv -- "$work/assets" "$out"
printf 'Release assets: %s\n' "$out"
