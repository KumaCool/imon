package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestBridgeRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/fixture", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("missing JSON body")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(body)
	})
	output, err := handleRequest(context.Background(), mux, []byte(`{"request_id":"fixture-1","method":"POST","path":"/api/v1/fixture","body":{"field":"value"}}`))
	if err != nil || string(output) != `{"request_id":"fixture-1","status":201,"body":{"field":"value"}}` {
		t.Fatalf("response = %s, %v", output, err)
	}
	output, err = handleRequest(context.Background(), mux, []byte(`{"request_id":"missing","method":"GET","path":"/api/v1/unknown"}`))
	if err != nil || !strings.Contains(string(output), `"status":404`) {
		t.Fatalf("404 response = %s, %v", output, err)
	}
}

func TestBridgeRejectsInvalidAPIPaths(t *testing.T) {
	for _, path := range []string{
		"https://example.invalid/api/v1/targets",
		"//example.invalid/api/v1/targets",
		"/api/v1/./targets",
		"/api/v1/targets/../session",
		"/api/v1/%73ession",
		"/api/v1/targets%2Ftest",
		"/api/v1//targets",
		"/api/v1/targets?x=y#fragment",
		"/api/v1/targets?x=%gg",
		"/api/v1/session",
		"/api/v1/local/file-picker",
		"/api/v1/jobs/fixture/firewall-script?a=b",
	} {
		t.Run(path, func(t *testing.T) {
			if validAPIPath(path) {
				t.Fatal("path was accepted")
			}
		})
	}
	if !validAPIPath("/api/v1/targets?kind=host") {
		t.Fatal("canonical query was rejected")
	}
}

func TestFirewallScriptOnlyUsesJobRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/jobs/{id}/firewall-script", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = fmt.Fprintf(w, "script:%s", r.PathValue("id"))
	})
	input := []byte(`{"path":"/api/v1/jobs/fixture/firewall-script","filename":"not-used"}`)
	result, err := firewallScript(context.Background(), mux, input)
	if err != nil || string(result) != "script:fixture" {
		t.Fatalf("script = %q, %v", result, err)
	}
	if _, err := firewallScript(context.Background(), mux, []byte(`{"path":"/etc/passwd"}`)); err == nil {
		t.Fatal("unexpected path accepted")
	}
}
