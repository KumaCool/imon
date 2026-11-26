# Windows desktop candidate

The Windows amd64 desktop shell uses the system Microsoft Edge WebView2
Evergreen Runtime. It does not start the Web edition or an HTTP listener.

## Build

Use Go from `go.mod`, amd64 MinGW-w64 GCC/G++ and windres, NSIS, and a POSIX shell.
Download the `Microsoft.Web.WebView2` NuGet package at version `1.0.1150.38`,
the SDK version pinned by WebView 0.12.0, and extract its
`build/native/include` directory. Only the headers are used; the runtime and
SDK binaries are not packaged. On a case-sensitive cross-build host,
the SDK's `EventToken.h` include may require a link with that capitalization
to the MinGW-w64 `eventtoken.h` header in the extracted include directory.

```sh
WEBVIEW2_SDK_INCLUDE="<SDK_INCLUDE_DIR>" \
  ./packaging/desktop/build-windows.sh v0.1.0
```

The default output is `dist/desktop/v0.1.0/windows-amd64/`. A second argument
sets a different output parent. The installer runs per user, does not install
or download WebView2, and leaves monitoring data intact on uninstall. The
candidate is unsigned.

## Runtime verification

Use a Windows 11 amd64 graphical session and a temporary data directory.
Verify missing and present Evergreen runtime, installation/uninstallation,
default host page and in-window navigation, job-script save and cancellation,
private key selection and cancellation, external navigation isolation, no TCP
listener, and data-directory lock release after exit. Cross-building the
installer does not verify any of these runtime results.
