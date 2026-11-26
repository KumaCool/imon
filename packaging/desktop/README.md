# Imon desktop candidates

The desktop builds share the local monitoring runtime with the separately
distributed Web build. They start a native window without opening a local HTTP
service. Do not run both variants against one data directory at the same time.

## macOS

Build on macOS with the repository's Go toolchain and Xcode Command Line Tools:

```sh
./packaging/desktop/build-macos.sh v0.1.0
```

The default output is `dist/desktop/v0.1.0/darwin-<ARCH>/` (native architecture).
Pass an alternate output parent and `amd64` or `arm64` as optional arguments.
The zip contains `Imon.app`, which opens from Finder. The app has a
local ad-hoc signature, not a Developer ID signature or notarization. The
package declares macOS 13 as the minimum; this does not substitute for testing
on that version. The two Linux firewall reader architectures are embedded for
the managed hosts.

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

The `.deb` was installed, launched, and removed on Debian 12 in an isolated
Xvfb session. The test exercised navigation and bridge reads and writes,
confirmed that the desktop process did not listen on TCP, and verified that it
released the data directory lock on exit. Ubuntu 24.04 and native file dialog
interactions still need testing.

## Windows

See [Windows build and runtime checks](WINDOWS.md) for the WebView2 prerequisites
and amd64 NSIS candidate. The installer has been cross-built; Windows 11
runtime verification is pending.
