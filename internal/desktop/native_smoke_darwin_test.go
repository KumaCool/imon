//go:build darwin && cgo && desktop_smoke

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"imon/internal/panelruntime"
	"imon/internal/update"
)

// TestMain drives the native run loop on the initial thread, not a test goroutine.
func init() { runtime.LockOSThread() }

func TestMain(m *testing.M) {
	if os.Getenv("INFRA_DESKTOP_EDIT_SMOKE") == "1" {
		if err := smokeEdit(runWithAssets); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(m.Run())
	}
	if err := smoke(); err != nil {
		fmt.Fprintln(os.Stderr, "desktop smoke:", err)
		os.Exit(1)
	}
	fmt.Println("desktop smoke: bundled ES module, top-frame GET/POST, fragment navigation and blocking scripted external navigation passed")
	if err := smokePanel(); err != nil {
		fmt.Fprintln(os.Stderr, "desktop panel smoke:", err)
		os.Exit(1)
	}
	fmt.Println("desktop panel smoke: default hosts page, in-place services navigation and version v0.1.0 passed")
	os.Exit(m.Run())
}

func smoke() error {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	done := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/smoke", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("from") != "bundle" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /api/v1/smoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			OK bool `json:"ok"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || !body.OK {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/smoke-finish", func(w http.ResponseWriter, r *http.Request) {
		select {
		case done <- struct{}{}:
		default:
		}
		stop()
		w.WriteHeader(http.StatusNoContent)
	})
	assets := [][]byte{
		[]byte(`<!doctype html><html><head><link rel="stylesheet" href="/app.css"><script type="module" src="/app.js"></script></head><body>Smoke fixture</body></html>`),
		[]byte(`body{color:rgb(1,2,3)}`),
		[]byte(`const bridge = window.imonDesktop;
const get = await bridge.request({request_id:'get',method:'GET',path:'/api/v1/smoke?from=bundle'});
if (get.request_id !== 'get' || get.status !== 200 || !get.body.ok ||
     getComputedStyle(document.body).color !== 'rgb(1, 2, 3)') throw Error('broken asset or GET');
location.hash = '?view=services';
const post = await bridge.request({request_id:'post',method:'POST',path:'/api/v1/smoke',body:get.body});
if (location.hash !== '#?view=services' || post.request_id !== 'post' || post.status !== 204 || post.body !== null)
  throw Error('broken POST or fragment');
let refused = false;
try { await bridge.request({request_id:'denied',method:'POST',path:'/api/v1/session'}); }
catch (_) { refused = true; }
if (!refused) throw Error('browser session path reached from desktop');
window.location.href = 'https://example.invalid/';
await new Promise(resolve => setTimeout(resolve, 150));
if (location.protocol !== 'imon:') throw Error('external navigation was allowed');
await bridge.request({request_id:'finish',method:'POST',path:'/api/v1/smoke-finish'});`),
	}
	if err := runWithAssets(ctx, mux, assets); err != nil {
		return err
	}
	select {
	case <-done:
		return nil
	default:
		return errors.New("window closed without verifying script and stylesheet loading and bridge responses")
	}
}

func smokePanel() (err error) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	dir, err := os.MkdirTemp("", "imon-desktop-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	app, err := panelruntime.Open(ctx, filepath.Join(dir, "data"), "v0.1.0", "", update.Options{})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, app.Close()) }()
	assets, err := webAssets()
	if err != nil {
		return err
	}
	// A test-only tail observes the actual frontend, loaded through the native transport.
	assets[2] = append(assets[2], []byte(`
;(async () => {
  const until = async (check) => {
    for (let i = 0; i < 100; i++) {
      if (check()) return;
      await new Promise(resolve => setTimeout(resolve, 40));
    }
    throw Error("Timed out waiting for page");
  };
  let outcome = "passed";
  const page = (title) => content.querySelector("h1")?.textContent === title;
  try {
    await until(() => page("主机管理") && content.textContent.includes("尚未绑定 Linux 主机") &&
                      versionNumber.textContent === "v0.1.0");
    document.querySelector('[data-nav="services"]').click();
    await until(() => page("服务") && content.textContent.includes("尚未绑定主机或集群"));
    if (!location.hash.startsWith("#?view=services")) throw Error("Services did not use the desktop route");
    history.back();
    await until(() => page("主机管理"));
  } catch (e) {
    outcome = String(e);
  }
  await desktop.request({request_id:"panel-smoke",method:"POST",path:"/api/v1/smoke-finish",body:{outcome}});
})();`)...)
	outcomes := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/smoke-finish", func(w http.ResponseWriter, r *http.Request) {
		var result struct {
			Outcome string `json:"outcome"`
		}
		_ = json.NewDecoder(r.Body).Decode(&result)
		outcomes <- result.Outcome
		w.WriteHeader(http.StatusNoContent)
		stop()
	})
	mux.Handle("/", app.Handler)
	if err := runWithAssets(ctx, mux, assets); err != nil {
		return err
	}
	select {
	case outcome := <-outcomes:
		if outcome != "passed" {
			return fmt.Errorf("unexpected panel outcome: %q", outcome)
		}
		return nil
	default:
		return errors.New("window closed before the panel reported a result")
	}
}
