//go:build darwin && cgo

package desktop

/*
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: -framework Cocoa -framework WebKit -lc++
#include <stdlib.h>
#include "cocoa_darwin.h"
*/
import "C"

import (
	"context"
	"fmt"
	"net/http"
	"runtime/cgo"
	"sync"
	"unsafe"

	"imon/web"
)

type desktopState struct {
	ctx     context.Context
	handler http.Handler
	slots   chan struct{}
	pending sync.WaitGroup
}

func Available() error { return nil }

// Run hosts embedded panel resources on the main OS thread without a listener.
func Run(ctx context.Context, handler http.Handler) error {
	assets, err := webAssets()
	if err != nil {
		return err
	}
	return runWithAssets(ctx, handler, assets)
}

func webAssets() ([][]byte, error) {
	assets := make([][]byte, 3)
	for i, name := range []string{"index.html", "app.css", "app.js"} {
		content, err := web.Assets.ReadFile(name)
		if err != nil {
			return nil, err
		}
		assets[i] = content
	}
	return assets, nil
}

func runWithAssets(ctx context.Context, handler http.Handler, assets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	state := &desktopState{ctx: ctx, handler: handler, slots: make(chan struct{}, 16)}
	handle := cgo.NewHandle(state)
	defer handle.Delete()
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			C.infra_desktop_stop()
		case <-done:
		}
	}()
	rc := C.infra_desktop_run(C.uintptr_t(handle),
		(*C.char)(unsafe.Pointer(unsafe.SliceData(assets[0]))), C.size_t(len(assets[0])),
		(*C.char)(unsafe.Pointer(unsafe.SliceData(assets[1]))), C.size_t(len(assets[1])),
		(*C.char)(unsafe.Pointer(unsafe.SliceData(assets[2]))), C.size_t(len(assets[2])))
	close(done)
	<-watcherDone
	cancel()
	state.pending.Wait()
	if rc != 0 {
		return fmt.Errorf("desktop window initialization failed (WebView %d)", rc)
	}
	return nil
}

func ShowStartupError(err error) {
	e := C.CString(err.Error())
	defer C.free(unsafe.Pointer(e))
	C.infra_desktop_alert(e)
}

//export desktopMessage
func desktopMessage(h, reply C.uintptr_t, operation, input *C.char) {
	state := cgo.Handle(h).Value().(*desktopState)
	op, payload := C.GoString(operation), []byte(C.GoString(input))
	select {
	case state.slots <- struct{}{}:
	default:
		sendReply(reply, nil, fmt.Errorf("too many pending desktop requests"))
		return
	}
	state.pending.Add(1)
	go func() {
		defer state.pending.Done()
		defer func() { <-state.slots }()
		switch op {
		case "request":
			output, err := handleRequest(state.ctx, state.handler, payload)
			sendReply(reply, output, err)
		case "saveFirewallScript":
			data, err := firewallScript(state.ctx, state.handler, payload)
			if err != nil {
				sendReply(reply, nil, err)
				return
			}
			C.infra_desktop_save(reply, (*C.char)(unsafe.Pointer(unsafe.SliceData(data))), C.size_t(len(data)))
		default:
			sendReply(reply, nil, fmt.Errorf("unsupported desktop operation"))
		}
	}()
}

func sendReply(reply C.uintptr_t, output []byte, err error) {
	if err != nil {
		msg := C.CString(err.Error())
		defer C.free(unsafe.Pointer(msg))
		C.infra_desktop_reply(reply, nil, msg)
		return
	}
	response := C.CString(string(output))
	defer C.free(unsafe.Pointer(response))
	C.infra_desktop_reply(reply, response, nil)
}
