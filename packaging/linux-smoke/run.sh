#!/bin/sh
set -eu

src=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
tmp=$(mktemp -d)
suffix=$(basename "$tmp" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')
image=imon-linux-smoke:$suffix
container=imon-linux-smoke-$suffix
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || :
  docker image rm "$image" >/dev/null 2>&1 || :
  rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
go_bin=$(command -v "${GO_BIN:-go}")
case "$go_bin" in /*) ;; *) go_bin="$(pwd)/$go_bin" ;; esac
case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf '%s\n' 'Unsupported Docker Linux architecture' >&2; exit 1 ;;
esac
mkdir "$tmp/build" "$tmp/image"
cp "$src/go.mod" "$src/go.sum" "$tmp/build/"
cp -R "$src/internal" "$src/cmd" "$src/packaging" "$tmp/build/"
cp "$src/packaging/linux-smoke/Dockerfile" "$src/packaging/linux-smoke/fixture.sh" "$tmp/image/"
cd "$tmp/build"
export CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off
"$go_bin" build -trimpath -o "internal/firewall/bundles/firewall-read-$arch" ./cmd/imon-firewall
"$go_bin" build -trimpath -o "$tmp/image/host-smoke" ./packaging/linux-smoke
docker build -t "$image" "$tmp/image"
docker run -d --name "$container" --network none --privileged \
  --cgroupns private --tmpfs /run --tmpfs /run/lock "$image" >/dev/null
docker exec "$container" /bin/sh /fixture/fixture.sh
