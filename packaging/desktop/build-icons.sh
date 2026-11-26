#!/bin/sh
# Rebuild the checked-in package icons from imon.svg on macOS.
set -eu

if [ "$(uname -s)" != Darwin ]; then
  printf 'Rebuilding icons requires macOS (sips and iconutil).\n' >&2
  exit 1
fi
dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/imon-icons.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/Imon.iconset"
sips -s format png "$dir/imon.svg" --out "$work/base.png" >/dev/null

for size in 16 32 128 256 512; do
  double=$((size * 2))
  sips -z "$size" "$size" "$work/base.png" --out "$work/Imon.iconset/icon_${size}x${size}.png" >/dev/null
  sips -z "$double" "$double" "$work/base.png" --out "$work/Imon.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$work/Imon.iconset" -o "$work/imon.icns"
sips -z 64 64 "$work/base.png" --out "$work/imon-64.png" >/dev/null

# sips exports one ICO frame at a time. Combine their directories so Windows
# can choose the appropriate size for Explorer, shortcuts and the taskbar.
for size in 16 24 32 48 64 128 256; do
  sips -z "$size" "$size" -s format ico "$work/base.png" --out "$work/$size.ico" >/dev/null
done
python3 - "$work" <<'PY'
import struct
import sys
from pathlib import Path

work = Path(sys.argv[1])
sizes = (16, 24, 32, 48, 64, 128, 256)
header = struct.pack('<HHH', 0, 1, len(sizes))
entries = bytearray()
images = bytearray()
for size in sizes:
    frame = (work / f'{size}.ico').read_bytes()
    if struct.unpack_from('<HHH', frame) != (0, 1, 1):
        raise ValueError(f'{size}.ico must contain one icon')
    length, position = struct.unpack_from('<II', frame, 14)
    image = frame[position:position + length]
    if len(image) != length:
        raise ValueError(f'Truncated image in {size}.ico')
    offset = len(header) + len(sizes) * 16 + len(images)
    entries += frame[6:18] + struct.pack('<I', offset)
    images += image
(work / 'imon.ico').write_bytes(header + entries + images)
PY

cp "$work/imon.icns" "$work/imon.ico" "$work/imon-64.png" "$dir/"
