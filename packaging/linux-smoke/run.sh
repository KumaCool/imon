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
case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf '%s\n' 'Unsupported Docker Linux architecture' >&2; exit 1 ;;
esac
mkdir "$tmp/image"
sh "$src/packaging/linux-smoke/build.sh" "$arch" "$tmp/image"
docker build -t "$image" "$tmp/image"
docker run -d --name "$container" --network none --privileged \
  --cgroupns private --tmpfs /run --tmpfs /run/lock "$image" >/dev/null
docker exec "$container" /bin/sh /fixture/fixture.sh
