//go:build linux && cgo && desktop

package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("INFRA_DESKTOP_EDIT_SMOKE") == "1" {
		runtime.LockOSThread()
		if err := smokeEdit(runGTK); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	if os.Getenv("INFRA_DESKTOP_NATIVE_SMOKE") == "1" {
		runtime.LockOSThread()
		if err := smokeGTK(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("GTK native smoke passed: packaged scheme, top-frame proof, history, bridge GET/POST, shutdown")
	}
	os.Exit(m.Run())
}

func smokeGTK() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/smoke", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("source") != "bundle" {
			http.Error(w, "missing argument", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/v1/smoke", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ OK bool }
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || !input.OK {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/smoke-finish", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("failure") {
			done <- fmt.Errorf("GTK smoke test failed: %s", r.URL.Query().Get("failure"))
		} else {
			done <- nil
		}
		w.WriteHeader(http.StatusNoContent)
		cancel()
	})
	assets := [][]byte{
		[]byte(`<!doctype html><title>Native smoke</title><link rel="stylesheet" href="/app.css"><script type="module" src="/app.js"></script>`),
		[]byte(`:root { --smoke: present; }`),
		[]byte(`
const bridge = window.imonDesktop;
const finish = (failure) => bridge.request({request_id: "finish", method: "POST",
  path: "/api/v1/smoke-finish" + (failure ? "?failure=" + encodeURIComponent(failure) : "")});
try {
  if (document.readyState !== "complete") await new Promise((resolve) => addEventListener("load", resolve, { once: true }));
  if (getComputedStyle(document.documentElement).getPropertyValue("--smoke").trim() !== "present")
    throw Error("stylesheet not loaded");
  const get = await bridge.request({request_id: "get", method: "GET", path: "/api/v1/smoke?source=bundle"});
  if (get.request_id !== "get" || get.status !== 200 || !get.body.ok) throw Error("GET");
  history.pushState(null, "", "#?view=services");
  const post = await bridge.request({request_id: "post", method: "POST", path: "/api/v1/smoke", body: get.body});
  if (post.status !== 204 || post.body !== null || location.hash !== "#?view=services") throw Error("POST/history");
  let denied = false;
  try { await window.webkit.messageHandlers.imonNative.postMessage("fake\nrequest\n{}"); } catch (_) { denied = true; }
  if (!denied) throw Error("forged proof accepted");
  denied = false;
  try { await bridge.request({request_id: "denied", method: "POST", path: "/api/v1/session"}); } catch (_) { denied = true; }
  if (!denied) throw Error("Web session accessible");
  await finish();
} catch (error) { await finish(error.message); }
`),
	}
	if err := runGTK(ctx, mux, assets); err != nil {
		return err
	}
	select {
	case result := <-done:
		return result
	default:
		return fmt.Errorf("GTK smoke window closed before bridge checks: %v", ctx.Err())
	}
}
