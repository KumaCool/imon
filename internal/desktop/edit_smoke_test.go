//go:build cgo && ((darwin && desktop_smoke) || (linux && desktop))

package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// With INFRA_DESKTOP_EDIT_SMOKE=1, wait for "desktop edit fixture ready".
// After it appears, send Cmd+A, Cmd+C, Tab, Cmd+V, Cmd+A, Cmd+X, Enter, Cmd+V
// to the app window. On Linux use Ctrl instead of Cmd.
func smokeEdit(run func(context.Context, http.Handler, [][]byte) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/edit-ready", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("desktop edit fixture ready")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/edit-finish", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Result string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			body.Result = err.Error()
		}
		select {
		case result <- body.Result:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
		cancel()
	})
	assets := [][]byte{
		[]byte(`<!doctype html><meta charset="utf-8"><script type="module" src="/app.js"></script>
<input id="source" value="fixture-shortcut"><input id="target"><button id="copy">Copy fixture</button><input id="fallback" value="fixture-button" tabindex="-1">`),
		[]byte(``),
		[]byte(`const source = document.getElementById('source');
const target = document.getElementById('target');
const copy = document.getElementById('copy');
const fallback = document.getElementById('fallback');
const request = (path, body) => window.imonDesktop.request({request_id:'edit-smoke', method:'POST', path, body});
const finish = (result) => request('/api/v1/edit-finish', {result});
let selected = false;
let pasted = false;
let cut = false;
source.addEventListener('copy', () => {
  selected = source.selectionStart === 0 && source.selectionEnd === source.value.length;
});
target.addEventListener('input', (event) => {
  if (event.inputType === 'insertFromPaste' && !pasted) {
    pasted = selected && target.value === source.value;
    if (!pasted) finish('select-all, copy, or paste failed');
  } else if (event.inputType === 'deleteByCut' && pasted) {
    cut = target.value === '';
    copy.focus();
  } else if (event.inputType === 'insertFromPaste' && cut) {
    finish(target.value === fallback.value ? 'passed' : 'button text was not copied');
  }
});
copy.addEventListener('click', () => {
  if (!cut) return finish('cut failed');
  fallback.select();
  if (!document.execCommand('copy')) return finish('selection copy fallback failed');
  target.focus();
});
source.focus();
source.setSelectionRange(0, 0);
await request('/api/v1/edit-ready');`),
	}
	if err := run(ctx, mux, assets); err != nil {
		return err
	}
	select {
	case outcome := <-result:
		if outcome != "passed" {
			return fmt.Errorf("desktop edit fixture: %s", outcome)
		}
		fmt.Println("desktop edit smoke: select-all, copy, paste, cut, and copy button fallback passed")
		return nil
	default:
		return fmt.Errorf("desktop edit fixture closed before shortcut verification")
	}
}
