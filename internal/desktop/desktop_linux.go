//go:build linux && cgo && desktop

package desktop

/*
#cgo pkg-config: gtk+-3.0 webkit2gtk-4.1
#cgo CXXFLAGS: -std=c++17
#cgo LDFLAGS: -lstdc++
#include <stdlib.h>
#include "gtk_linux.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/cgo"
	"unsafe"

	"imon/web"
)

type gtkState struct {
	ctx     context.Context
	cancel  context.CancelFunc
	handler http.Handler
	slots   chan struct{}
}

func Available() error { return nil }

func Run(ctx context.Context, handler http.Handler) error {
	assets := make([][]byte, 3)
	for i, name := range []string{"index.html", "app.css", "app.js"} {
		content, err := web.Assets.ReadFile(name)
		if err != nil {
			return err
		}
		assets[i] = content
	}
	return runGTK(ctx, handler, assets)
}

func runGTK(ctx context.Context, handler http.Handler, assets [][]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	state := &gtkState{ctx: ctx, cancel: cancel, handler: handler, slots: make(chan struct{}, 16)}
	handle := cgo.NewHandle(state)
	defer handle.Delete()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	proof := C.CString(hex.EncodeToString(secret[:]))
	defer C.free(unsafe.Pointer(proof))
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			C.infra_gtk_stop(C.uintptr_t(handle))
		case <-done:
		}
	}()
	code := C.infra_gtk_run(C.uintptr_t(handle), proof,
		unsafe.Pointer(unsafe.SliceData(assets[0])), C.size_t(len(assets[0])),
		unsafe.Pointer(unsafe.SliceData(assets[1])), C.size_t(len(assets[1])),
		unsafe.Pointer(unsafe.SliceData(assets[2])), C.size_t(len(assets[2])))
	close(done)
	<-watcherDone
	if code != 0 {
		return fmt.Errorf("desktop window initialization failed (GTK/WebKit %d)", code)
	}
	return nil
}

func ShowStartupError(err error) {
	message := C.CString(err.Error())
	defer C.free(unsafe.Pointer(message))
	C.infra_gtk_alert(message)
}

//export desktopGTKCancel
func desktopGTKCancel(h C.uintptr_t) {
	cgo.Handle(h).Value().(*gtkState).cancel()
}

//export desktopGTKMessage
func desktopGTKMessage(h, reply C.uintptr_t, operation, input *C.char) {
	state := cgo.Handle(h).Value().(*gtkState)
	op, payload := C.GoString(operation), []byte(C.GoString(input))
	select {
	case state.slots <- struct{}{}:
	default:
		sendGTKReply(reply, nil, fmt.Errorf("too many pending desktop requests"))
		return
	}
	go func() {
		defer func() { <-state.slots }()
		switch op {
		case "request":
			output, err := handleRequest(state.ctx, state.handler, payload)
			sendGTKReply(reply, output, err)
		case "saveFirewallScript":
			data, err := firewallScript(state.ctx, state.handler, payload)
			if err != nil {
				sendGTKReply(reply, nil, err)
				return
			}
			C.infra_gtk_save(reply, unsafe.Pointer(unsafe.SliceData(data)), C.size_t(len(data)))
		default:
			sendGTKReply(reply, nil, fmt.Errorf("unsupported desktop operation"))
		}
	}()
}

func sendGTKReply(reply C.uintptr_t, data []byte, err error) {
	if err != nil {
		message := C.CString(err.Error())
		defer C.free(unsafe.Pointer(message))
		C.infra_gtk_reply(reply, nil, message)
		return
	}
	output := C.CString(string(data))
	defer C.free(unsafe.Pointer(output))
	C.infra_gtk_reply(reply, output, nil)
}
