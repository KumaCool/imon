# Vendored WebView

`webview.h` is the single-file header from upstream `webview/webview` tag
`0.12.0`, commit `3ab4b5d722438fc8a13e6ca830c5e2372d19a01d`.
The adjacent `LICENSE` applies. The one-line Cocoa patch calls
`infra_desktop_configure_cocoa` before `WKWebView` is constructed so
the application can register its bundled-resource scheme.
