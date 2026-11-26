//go:build (!darwin || !cgo) && (!linux || !cgo || !desktop) && (!windows || !amd64 || !cgo || !desktop)

package desktop

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
)

func Available() error {
	return fmt.Errorf("native desktop is unavailable on %s/%s; build with the native toolchain and cgo (Linux and Windows require -tags desktop)", runtime.GOOS, runtime.GOARCH)
}

func Run(context.Context, http.Handler) error { return Available() }

func ShowStartupError(error) {}
