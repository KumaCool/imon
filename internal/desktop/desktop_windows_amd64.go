//go:build windows && amd64 && cgo && desktop

package desktop

/*
#cgo CXXFLAGS: -std=c++17 -DUNICODE -D_UNICODE
#cgo LDFLAGS: -static -lole32 -luuid -lcomdlg32 -lshell32 -lshlwapi -luser32 -ladvapi32 -lversion -ldwmapi
#include <stdlib.h>
#include "webview2_windows.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"runtime/cgo"
	"sync"
	"unsafe"

	"imon/web"
)

type winState struct {
	ctx     context.Context
	handler http.Handler
	proof   string
	slots   chan struct{}
	pending sync.WaitGroup
}

var winCallID = regexp.MustCompile(`^[a-f0-9-]{36}$`)

func Available() error { return nil }

func Run(ctx context.Context, handler http.Handler) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	assets := make([][]byte, 3)
	for i, file := range []string{"index.html", "app.css", "app.js"} {
		data, err := web.Assets.ReadFile(file)
		if err != nil {
			return err
		}
		assets[i] = data
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	state := &winState{ctx: ctx, handler: handler, proof: hex.EncodeToString(nonce[:]), slots: make(chan struct{}, 16)}
	handle := cgo.NewHandle(state)
	defer handle.Delete()
	proof := C.CString(state.proof)
	defer C.free(unsafe.Pointer(proof))
	done, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			C.infra_windows_stop()
		case <-done:
		}
	}()
	status := C.infra_windows_run(C.uintptr_t(handle), proof,
		winBytes(assets[0]), C.size_t(len(assets[0])), winBytes(assets[1]), C.size_t(len(assets[1])),
		winBytes(assets[2]), C.size_t(len(assets[2])))
	close(done)
	<-watcherDone
	cancel()
	state.pending.Wait()
	if status == -1 {
		return errors.New("WebView2 window initialization failed; install or repair the Microsoft Edge WebView2 Evergreen Runtime")
	}
	if status != 0 {
		return fmt.Errorf("WebView2 desktop initialization failed (stage %d)", -status)
	}
	return nil
}

func winBytes(b []byte) *C.char { return (*C.char)(unsafe.Pointer(unsafe.SliceData(b))) }

func ShowStartupError(err error) {
	msg := C.CString(err.Error())
	defer C.free(unsafe.Pointer(msg))
	C.infra_windows_alert(msg)
}

//export infraWindowsMessage
func infraWindowsMessage(h C.uintptr_t, raw *C.char, size C.size_t) {
	if size > maxRequestBytes+4096 {
		return
	}
	state := cgo.Handle(h).Value().(*winState)
	var msg struct {
		Proof   string          `json:"proof"`
		Call    string          `json:"call"`
		Op      string          `json:"op"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(C.GoBytes(unsafe.Pointer(raw), C.int(size)), &msg) != nil ||
		subtle.ConstantTimeCompare([]byte(msg.Proof), []byte(state.proof)) != 1 || !winCallID.MatchString(msg.Call) {
		return
	}
	if msg.Op == "choosePrivateKey" {
		call := C.CString(msg.Call)
		defer C.free(unsafe.Pointer(call))
		C.infra_windows_choose(call)
		return
	}
	select {
	case state.slots <- struct{}{}:
	default:
		winReply(msg.Call, nil, errors.New("too many pending desktop requests"))
		return
	}
	state.pending.Add(1)
	go func() {
		defer state.pending.Done()
		defer func() { <-state.slots }()
		switch msg.Op {
		case "request":
			output, err := handleRequest(state.ctx, state.handler, msg.Payload)
			winReply(msg.Call, output, err)
		case "saveFirewallScript":
			data, err := firewallScript(state.ctx, state.handler, msg.Payload)
			if err != nil {
				winReply(msg.Call, nil, err)
				return
			}
			call := C.CString(msg.Call)
			defer C.free(unsafe.Pointer(call))
			C.infra_windows_save(call, winBytes(data), C.size_t(len(data)))
		default:
			winReply(msg.Call, nil, errors.New("unsupported desktop operation"))
		}
	}()
}

func winReply(call string, reply json.RawMessage, err error) {
	id := C.CString(call)
	defer C.free(unsafe.Pointer(id))
	var message string
	if err != nil {
		message = err.Error()
	}
	output, _ := json.Marshal(struct {
		Result json.RawMessage `json:"result,omitempty"`
		Error  string          `json:"error,omitempty"`
	}{reply, message})
	C.infra_windows_reply(id, winBytes(output), C.size_t(len(output)))
}
