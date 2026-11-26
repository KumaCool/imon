package desktop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
)

const maxRequestBytes = 1 << 20

type bridgeRequest struct {
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	Path      string          `json:"path"`
	Body      json.RawMessage `json:"body,omitempty"`
}

type bridgeResponse struct {
	RequestID string          `json:"request_id"`
	Status    int             `json:"status"`
	Body      json.RawMessage `json:"body"`
}

var (
	requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)
	pathSegment      = regexp.MustCompile(`^[a-zA-Z0-9._~-]+$`)
	scriptPath       = regexp.MustCompile(`^/api/v1/jobs/[a-zA-Z0-9_-]+/firewall-script$`)
)

func handleRequest(ctx context.Context, handler http.Handler, data []byte) ([]byte, error) {
	if len(data) > maxRequestBytes {
		return nil, errors.New("desktop API request is too large")
	}
	var msg bridgeRequest
	if err := json.Unmarshal(data, &msg); err != nil || !requestIDPattern.MatchString(msg.RequestID) {
		return nil, errors.New("invalid desktop API request")
	}
	switch msg.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, errors.New("unsupported desktop API method")
	}
	if !validAPIPath(msg.Path) {
		return nil, errors.New("unsupported desktop API path")
	}
	if msg.Method == http.MethodGet && len(msg.Body) != 0 {
		return nil, errors.New("GET cannot include a request body")
	}
	w, err := callHandler(ctx, handler, msg.Method, msg.Path, msg.Body)
	if err != nil {
		return nil, err
	}
	body := w.Body.Bytes()
	if len(body) == 0 {
		body = []byte("null")
	} else if !json.Valid(body) {
		// ServeMux can return plain-text errors for unrecognized routes or methods.
		body, _ = json.Marshal(map[string]string{"error": http.StatusText(w.Code)})
	}
	return json.Marshal(bridgeResponse{RequestID: msg.RequestID, Status: w.Code, Body: body})
}

func validAPIPath(path string) bool {
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || u.RawPath != "" ||
		!strings.HasPrefix(u.Path, "/api/v1/") || strings.IndexByte(path, '#') >= 0 {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(u.Path, "/api/v1/"), "/") {
		if part == "." || part == ".." || !pathSegment.MatchString(part) {
			return false
		}
	}
	for _, part := range []string{"session", "local"} {
		block := "/api/v1/" + part
		if u.Path == block || strings.HasPrefix(u.Path, block+"/") {
			return false
		}
	}
	// Script downloads are accepted only by the dedicated native save operation.
	if scriptPath.MatchString(u.Path) {
		return false
	}
	_, err = url.ParseQuery(u.RawQuery)
	return err == nil
}

func firewallScript(ctx context.Context, handler http.Handler, data []byte) ([]byte, error) {
	var msg struct {
		Path string `json:"path"`
	}
	if len(data) > maxRequestBytes || json.Unmarshal(data, &msg) != nil || !scriptPath.MatchString(msg.Path) {
		return nil, errors.New("invalid firewall script request")
	}
	w, err := callHandler(ctx, handler, http.MethodGet, msg.Path, nil)
	if err != nil {
		return nil, err
	}
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" || w.Body.Len() == 0 {
		return nil, fmt.Errorf("firewall script unavailable: HTTP %d", w.Code)
	}
	return w.Body.Bytes(), nil
}

func callHandler(ctx context.Context, h http.Handler, method, path string, body []byte) (*httptest.ResponseRecorder, error) {
	r, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) != 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w, nil
}
