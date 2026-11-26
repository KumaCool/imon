package collector

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Measures only transport and collector projection. SQLite, UI, remote CPU and WAN behavior are not measured.
func TestSyntheticScopedCollectionProfile(t *testing.T) {
	profiles := []struct {
		name, largeGroup string
		delay            time.Duration
	}{
		{"normal", "", time.Millisecond},
		{"high-latency", "", 15 * time.Millisecond},
		{"large-unrelated", "pods", time.Millisecond},
		{"large-required", "nodes", time.Millisecond},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			payloads := map[string]string{"/api/v1/namespaces/kube-system": `{"metadata":{"name":"kube-system","uid":"fixture"}}`}
			for _, group := range []string{"nodes", "pods"} {
				annotation := ""
				if group == profile.largeGroup {
					annotation = strings.Repeat("x", 512<<10)
				}
				payloads[kubePaths[group]] = fmt.Sprintf(`{"items":[{"metadata":{"name":"fixture","uid":%q,"namespace":"default","annotations":{"fixture":%q}}}]}`, group, annotation)
			}
			var requests, deliveredBytes, connections atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(profile.delay)
				body, exists := payloads[r.URL.Path]
				if !exists {
					body = `{"items":[]}`
				}
				requests.Add(1)
				deliveredBytes.Add(int64(len(body)))
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			t.Cleanup(server.Close)
			root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			configPath := filepath.Join(t.TempDir(), "fixture.json")
			configFile := fmt.Sprintf(`{"apiVersion":"v1","kind":"Config","current-context":"fixture","contexts":[{"name":"fixture","context":{"cluster":"fixture"}}],"clusters":[{"name":"fixture","cluster":{"server":%q,"certificate-authority-data":%q}}]}`, server.URL, base64.StdEncoding.EncodeToString(root))
			if err := os.WriteFile(configPath, []byte(configFile), 0600); err != nil {
				t.Fatal(err)
			}
			config := Config{Kubeconfig: configPath, Context: "fixture"}

			for _, mode := range []struct {
				name         string
				groups       []string
				wantRequests int64
			}{{"scoped", []string{"nodes"}, 2}, {"serial-all", Groups("cluster"), 6}} {
				const repeats = 3
				var first, total []time.Duration
				var sampleBytes int64
				for range repeats {
					requests.Store(0)
					deliveredBytes.Store(0)
					connections.Store(0)
					start := time.Now()
					session, err := Open(t.Context(), "cluster", config, "fixture")
					if err != nil {
						t.Fatal(err)
					}
					for _, group := range mode.groups {
						rows, err := session.CollectWithOptions(t.Context(), group, Options{Manual: true})
						if err != nil {
							session.Close()
							t.Fatalf("%s/%s: %v", mode.name, group, err)
						}
						if group == "nodes" {
							if len(rows) != 1 || rows[0].Key != "nodes" {
								t.Fatalf("different required output: %v", rows)
							}
							first = append(first, time.Since(start))
						}
					}
					total = append(total, time.Since(start))
					session.Close()
					if requests.Load() != mode.wantRequests || connections.Load() != 1 {
						t.Fatalf("%s: requests=%d, connections=%d; want %d and 1", mode.name, requests.Load(), connections.Load(), mode.wantRequests)
					}
					sampleBytes = deliveredBytes.Load()
				}
				slices.Sort(first)
				slices.Sort(total)
				t.Logf("%s: median first=%s total=%s requests=%d connections=1 response_body_bytes=%d repeats=%d", mode.name, first[repeats/2].Round(time.Microsecond), total[repeats/2].Round(time.Microsecond), mode.wantRequests, sampleBytes, repeats)
			}
		})
	}
}
