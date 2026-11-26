# Imon desktop candidates

The desktop builds share the local monitoring runtime with the separately
distributed Web build. They start a native window without opening a local HTTP
service. Do not run both variants against one data directory at the same time.

All three packages carry the Imon app icon. Edit `imon.svg` and run
`./packaging/desktop/build-icons.sh` on macOS with Python 3 to regenerate the
checked-in macOS, Windows, and Linux icon files.

Set `IMON_HELPER_SIGNING_KEY_FILE` to the Ed25519 PKCS#8 PEM used for the
Web release before running the desktop packagers. Keep using the same key
for later releases so installed Linux helpers can verify updates. Set
`IMON_ALLOW_UNSIGNED_HELPER=1` for a local package without helper self-updates.

## macOS

Build on macOS with the repository's Go toolchain and Xcode Command Line Tools:

```sh
./packaging/desktop/build-macos.sh v0.1.0
```

The default output is `dist/desktop/v0.1.0/darwin-<ARCH>/` (native architecture).
Pass an alternate output parent and `amd64` or `arm64` as optional arguments.
The zip contains `Imon.app`, which opens from Finder. The app has a
local ad-hoc signature, not a Developer ID signature or notarization. The
package declares macOS 13 as the minimum. The package embeds Linux host
helpers for amd64 and arm64.

For isolated runtime testing, unpack the zip, then from the extracted directory:

```sh
dir=$(mktemp -d "${TMPDIR%/}/imon-desktop.XXXXXXXX")
"./Imon.app/Contents/MacOS/imon-desktop" --data-dir "$dir/data"
```

Run `go test -tags desktop_smoke ./internal/desktop` in a macOS graphical session
to exercise the app's in-process bridge against an embedded synthetic fixture.

## Linux

On Debian 12 or Ubuntu 24.04 amd64, use the project's Go toolchain, a C/C++
compiler, `pkg-config`, GTK 3 and WebKitGTK 4.1 development packages:

```sh
sh packaging/desktop/build-linux.sh v0.1.0
sudo apt install ./dist/desktop/v0.1.0/linux-amd64/imon-desktop_linux_amd64.deb
imon-desktop
```

The Debian 12 smoke test uses an isolated Xvfb session to exercise navigation,
bridge reads and writes, and shutdown. It checks that the desktop process opens
its window without a TCP listener and releases the data directory lock on exit.

## Windows

See [Windows build and runtime checks](WINDOWS.md) for the WebView2 prerequisites
and amd64 NSIS candidate. The installer has been cross-built; Windows 11
runtime verification is pending.
