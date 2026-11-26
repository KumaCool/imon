package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"

	"imon/internal/store"
	"imon/web"
)

const (
	apiPrefix     = "/api/v1/"
	cookiePath    = "/api/v1"
	contentPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)

type targetReader interface {
	ListTargets(context.Context, string, int) ([]store.Target, string, error)
}

type panel struct {
	host, origin, cookieName string
	api                      http.Handler
	session                  string
}

type sessionContextKey struct{}

type businessAPI struct {
	targets    targetReader
	chooseFile func(context.Context) (string, error)
	picker     chan struct{}
}

// New constructs a local Web handler and its reusable URL.
func New(host string, targets targetReader, register ...func(*http.ServeMux)) (http.Handler, string, error) {
	return NewWeb(host, NewAPI(targets, register...), "")
}

// NewWeb protects a business handler with the standalone browser session.
func NewWeb(host string, api http.Handler, session string) (http.Handler, string, error) {
	ip, port, err := net.SplitHostPort(host)
	if err != nil || ip != "127.0.0.1" {
		return nil, "", fmt.Errorf("panel requires a loopback listening address")
	}
	if session == "" {
		session, err = credential()
		if err != nil {
			return nil, "", fmt.Errorf("generate session credential: %w", err)
		}
	}
	p := &panel{
		host: host, origin: "http://" + host,
		cookieName: "imon_" + port,
		api:        api, session: session,
	}
	return p, p.origin + "/", nil
}

// NewAPI builds the shared, in-process business routes. Network callers must
// wrap the result in NewWeb; the desktop bridge calls it without a listener.
func NewAPI(targets targetReader, register ...func(*http.ServeMux)) http.Handler {
	p := &businessAPI{targets: targets, chooseFile: chooseLocalFile, picker: make(chan struct{}, 1)}
	return p.routes(register...)
}

func (p *businessAPI) routes(register ...func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	if p.targets != nil && len(register) == 0 {
		mux.HandleFunc("/api/v1/targets", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				methodError(w, "GET")
				return
			}
			p.listTargets(w, r)
		})
	}
	for _, add := range register {
		add(mux)
	}
	mux.HandleFunc("/api/v1/local/file-picker", p.localFilePicker)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, 404, "not_found", "Unknown API endpoint.", false)
	})
	return mux
}

// SessionCredential is for handlers on the authenticated local API only.
func SessionCredential(r *http.Request) string {
	value, _ := r.Context().Value(sessionContextKey{}).(string)
	return value
}

func credential() (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random[:]), nil
}

func (p *panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", contentPolicy)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(peer).IsLoopback() || r.Host != p.host {
		writeError(w, http.StatusForbidden, "invalid_host", "Expected the local panel address.", false)
		return
	}
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodPost {
		if !p.sameOriginWrite(r) {
			writeError(w, http.StatusForbidden, "invalid_origin", "Expected the panel origin.", false)
			return
		}
		p.exchange(w, r)
		return
	}
	if r.URL.Path == strings.TrimSuffix(apiPrefix, "/") || strings.HasPrefix(r.URL.Path, apiPrefix) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !p.sameOriginWrite(r) {
			writeError(w, http.StatusForbidden, "invalid_origin", "Expected the panel origin.", false)
			return
		}
		origins := r.Header.Values("Origin")
		if (len(origins) != 0 && (len(origins) != 1 || origins[0] != p.origin)) || !sameOriginSite(r) {
			writeError(w, http.StatusForbidden, "invalid_origin", "Expected the panel origin.", false)
			return
		}
		if !p.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "session_required", "Establish a local browser session.", false)
			return
		}
		if r.URL.Path == "/api/v1/session" {
			if r.Method != http.MethodGet {
				methodError(w, "GET, POST")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		p.api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, p.session)))
		return
	}
	p.asset(w, r)
}

func (p *panel) sameOriginWrite(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	return len(origins) == 1 && origins[0] == p.origin && (site == "" || site == "same-origin")
}

func sameOriginSite(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin"
}

func (p *panel) exchange(w http.ResponseWriter, r *http.Request) {
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Expected application/json.", false)
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	var input *struct{}
	if err := decoder.Decode(&input); err != nil || input == nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "Expected one empty JSON object.", false)
		return
	}
	if !p.authenticated(r) {
		http.SetCookie(w, &http.Cookie{
			Name: p.cookieName, Value: p.session, Path: cookiePath,
			HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *panel) authenticated(r *http.Request) bool {
	// During migration a browser can have cookies for both /api/v1/ and /api/v1.
	for _, cookie := range r.CookiesNamed(p.cookieName) {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(p.session)) == 1 {
			return true
		}
	}
	return false
}

func (p *panel) asset(w http.ResponseWriter, r *http.Request) {
	var filename, contentType string
	switch r.URL.Path {
	case "/":
		filename, contentType = "index.html", "text/html"
	case "/app.css":
		filename, contentType = "app.css", "text/css"
	case "/app.js":
		filename, contentType = "app.js", "text/javascript"
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodError(w, "GET, HEAD")
		return
	}
	data, err := web.Assets.ReadFile(filename)
	if err != nil {
		http.Error(w, "Panel asset unavailable.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func (p *businessAPI) listTargets(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := 50
	if query.Has("limit") {
		value, err := strconv.Atoi(query.Get("limit"))
		if err != nil || value < 1 || value > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "Limit must be an integer between 1 and 200.", false)
			return
		}
		limit = value
	}
	items, next, err := p.targets.ListTargets(r.Context(), query.Get("cursor"), limit)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage_unavailable", "Could not read local targets.", true)
		return
	}
	if items == nil {
		items = []store.Target{}
	}
	writeJSON(w, http.StatusOK, struct {
		Items      []store.Target `json:"items"`
		NextCursor string         `json:"next_cursor"`
	}{Items: items, NextCursor: next})
}

func methodError(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.", false)
}

func writeError(w http.ResponseWriter, status int, code, message string, retryable bool) {
	writeJSON(w, status, struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}{Code: code, Message: message, Retryable: retryable})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
