package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"imon/internal/store"
)

const testHost = "127.0.0.1:12345"

type readTargets func(context.Context, string, int) ([]store.Target, string, error)

func (f readTargets) ListTargets(ctx context.Context, cursor string, limit int) ([]store.Target, string, error) {
	return f(ctx, cursor, limit)
}

func newPanel(t *testing.T, targets targetReader) http.Handler {
	t.Helper()
	handler, startup, err := New(testHost, targets)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(startup)
	if err != nil || u.Host != testHost || u.Fragment != "" || u.RawQuery != "" {
		t.Fatal("expected a plain local URL")
	}
	return handler
}

func request(handler http.Handler, method, path string, body string, decorate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+testHost+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:40123"
	if decorate != nil {
		decorate(r)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func exchange(handler http.Handler, origin string) *httptest.ResponseRecorder {
	return request(handler, http.MethodPost, "/api/v1/session", "{}", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
	})
}

func status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("status %d, want %d", w.Code, want)
	}
}

func TestSessionAndTargetList(t *testing.T) {
	calls := 0
	handler := newPanel(t, readTargets(func(_ context.Context, cursor string, limit int) ([]store.Target, string, error) {
		calls++
		if cursor != "h-before" || limit != 2 {
			t.Errorf("store pagination got %q, %d", cursor, limit)
		}
		return []store.Target{{ID: "h-demo", ConnectionRef: "<TEST_CREDENTIAL_REF>"}}, "h-next", nil
	}))
	const origin = "http://" + testHost
	status(t, request(handler, "GET", "/api/v1/targets", "", nil), 401)
	status(t, exchange(handler, ""), 403)
	status(t, exchange(handler, "http://127.0.0.1:12346"), 403)
	for _, input := range []string{`{"token":"test"}`, "{} {}", "null", "[]"} {
		status(t, request(handler, "POST", "/api/v1/session", input, func(r *http.Request) {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
		}), 400)
	}
	login := exchange(handler, origin)
	status(t, login, 204)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" || cookies[0].MaxAge != 0 || !cookies[0].Expires.IsZero() ||
		!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Domain != "" || cookies[0].Path != cookiePath {
		t.Fatal("missing or incorrectly scoped session cookie")
	}
	withCookie := func(r *http.Request) { r.AddCookie(cookies[0]) }
	reuse := request(handler, "POST", "/api/v1/session", "{}", func(r *http.Request) {
		withCookie(r)
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
	})
	status(t, reuse, 204)
	if len(reuse.Result().Cookies()) != 0 {
		t.Fatal("authentic session should be reused")
	}
	for _, site := range []string{"cross-site", "same-site", "none"} {
		status(t, request(handler, "GET", "/api/v1/session", "", func(r *http.Request) {
			withCookie(r)
			r.Header.Set("Sec-Fetch-Site", site)
		}), 403)
	}
	status(t, request(handler, "GET", "/api/v1/session", "", withCookie), 204)
	status(t, request(handler, "GET", "/api/v1/targets?limit=201", "", withCookie), 400)
	status(t, request(handler, "POST", "/api/v1/targets", "", withCookie), 403)
	status(t, request(handler, "GET", "/api/v1/targets", "", func(r *http.Request) {
		withCookie(r)
		r.Header.Set("Origin", "http://127.0.0.1:12346")
	}), 403)
	w := request(handler, "GET", "/api/v1/targets?cursor=h-before&limit=2", "", withCookie)
	status(t, w, 200)
	var payload struct {
		Items []store.Target `json:"items"`
		Next  string         `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || len(payload.Items) != 1 ||
		payload.Items[0].ID != "h-demo" || payload.Next != "h-next" || strings.Contains(w.Body.String(), "TEST_CREDENTIAL_REF") || calls != 1 {
		t.Fatal("target listing did not return exactly the expected public page")
	}
}

func TestReusableSessionAndProcessRestart(t *testing.T) {
	h := newPanel(t, nil)
	const origin = "http://" + testHost
	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 8)
	for range cap(results) {
		wg.Go(func() { results <- exchange(h, origin) })
	}
	wg.Wait()
	close(results)
	var cookie *http.Cookie
	for result := range results {
		cookies := result.Result().Cookies()
		if result.Code != 204 || len(cookies) != 1 {
			t.Fatalf("session setup returned %d with %d cookies", result.Code, len(cookies))
		}
		if cookie != nil && cookie.Value != cookies[0].Value {
			t.Fatal("new tabs must not invalidate sessions")
		}
		cookie = cookies[0]
	}
	h = newPanel(t, nil)
	check := func(c *http.Cookie) *httptest.ResponseRecorder {
		return request(h, "GET", "/api/v1/session", "", func(r *http.Request) { r.AddCookie(c) })
	}
	status(t, check(cookie), 401)
	restart := exchange(h, origin)
	if restart.Code != 204 || len(restart.Result().Cookies()) != 1 {
		t.Fatal("failed to establish session after restart")
	}
	status(t, check(restart.Result().Cookies()[0]), 204)
	status(t, request(h, "GET", "/api/v1/session", "", func(r *http.Request) {
		r.AddCookie(cookie)
		r.AddCookie(restart.Result().Cookies()[0])
	}), 204)
}

func TestHostAndEmbeddedAssets(t *testing.T) {
	h := newPanel(t, nil)
	status(t, request(h, "GET", "/", "", func(r *http.Request) { r.Host = "alias.invalid:12345" }), 403)
	status(t, request(h, "GET", "/", "", func(r *http.Request) { r.RemoteAddr = "192.0.2.10:12345" }), 403)
	for path, media := range map[string]string{"/?view=alerts": "text/html", "/app.js": "text/javascript", "/app.css": "text/css"} {
		w := request(h, "GET", path, "", nil)
		status(t, w, 200)
		if !strings.HasPrefix(w.Header().Get("Content-Type"), media) || w.Body.Len() == 0 ||
			w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("asset %s missing content or expected headers", path)
		}
	}
	status(t, request(h, "GET", "/state.sqlite3", "", nil), 404)
}

func TestStorageErrorDoesNotExposeCause(t *testing.T) {
	h := newPanel(t, readTargets(func(context.Context, string, int) ([]store.Target, string, error) {
		return nil, "", errors.New("<PRIVATE_ERROR_DETAIL>")
	}))
	login := exchange(h, "http://"+testHost)
	if login.Code != 204 {
		t.Fatalf("login status %d", login.Code)
	}
	w := request(h, "GET", "/api/v1/targets", "", func(r *http.Request) { r.AddCookie(login.Result().Cookies()[0]) })
	status(t, w, 503)
	if strings.Contains(w.Body.String(), "PRIVATE_ERROR_DETAIL") || !strings.Contains(w.Body.String(), `"retryable":true`) {
		t.Fatal("storage error was not correctly sanitized")
	}
}
