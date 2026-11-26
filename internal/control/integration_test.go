package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"imon/internal/alert"
	"imon/internal/store"
)

func TestClusterBindingManualCollectionAndUnbind(t *testing.T) {
	ctx := t.Context()
	var nodeLists atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			io.WriteString(w, `{"metadata":{"name":"kube-system","uid":"fixture-cluster"}}`)
		case "/api/v1/nodes":
			nodeLists.Add(1)
			io.WriteString(w, `{"items":[{"metadata":{"name":"fixture-node","uid":"fixture-node-id"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`)
		case "/apis/apps/v1/deployments":
			io.WriteString(w, `{"items":[{"metadata":{"name":"fixture-workload","namespace":"default","uid":"fixture-deployment","generation":1},"spec":{"replicas":2},"status":{"observedGeneration":1,"replicas":2,"readyReplicas":2}}]}`)
		case "/api/v1/namespaces", "/api/v1/pods", "/api/v1/services", "/apis/discovery.k8s.io/v1/endpointslices":
			io.WriteString(w, `{"items":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	if _, err := x509.ParseCertificate(upstream.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "fixture.yaml")
	kube := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "fixture", "contexts": []any{map[string]any{"name": "fixture", "context": map[string]string{"cluster": "fixture"}}}, "clusters": []any{map[string]any{"name": "fixture", "cluster": map[string]string{"server": upstream.URL, "certificate-authority-data": base64.StdEncoding.EncodeToString(root)}}}}
	raw, _ := json.Marshal(kube)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(dir, "fixture.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine, err := alert.New(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	c, err := New(ctx, db, AlertObserver{Engine: engine})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mux := http.NewServeMux()
	c.Register(mux)
	engine.Register(mux)
	call := func(method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	obj := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	call("PUT", "/api/v1/sampling-settings", Settings{Host: 60, Network: 300, Cluster: 60, Timeout: 45}, 200)
	cfg := map[string]any{"kind": "cluster", "name": "fixture", "kubeconfig": file, "context": "fixture"}
	proof := obj(call("POST", "/api/v1/targets/test", cfg, 200))
	cfg["test_token"] = proof["test_token"]
	cfg["context"] = "modified"
	call("POST", "/api/v1/targets", cfg, 409)
	cfg["context"] = "fixture"
	target := obj(call("POST", "/api/v1/targets", cfg, 201))
	id := target["id"].(string)
	call("POST", "/api/v1/targets", cfg, 409)
	linked := call("GET", "/api/v1/targets?kind=cluster", nil, 200)
	if !strings.Contains(linked.Body.String(), id) || strings.Contains(linked.Body.String(), file) {
		t.Fatal("target list leaked connection reference or omitted binding")
	}
	call("PUT", "/api/v1/notification-settings", alert.Channels{}, 200)
	call("POST", "/api/v1/alert-rules", map[string]any{"name": "fixture replica rule", "enabled": true, "severity": "warning", "selector": map[string]any{"target_id": id, "metric": "deployment_state", "uid": "fixture-deployment"}, "condition": map[string]any{"op": "eq", "value": "running"}, "trigger": map[string]any{"consecutive_samples": 1}, "channels": map[string]bool{}}, 201)
	nodeListsAfterBinding := nodeLists.Load()
	if nodeListsAfterBinding == 0 {
		t.Fatal("binding failed to check node-list access")
	}
	req := obj(call("POST", "/api/v1/collection-requests", map[string]string{"view": "cluster", "target_id": id, "group": "deployments"}, 202))
	jobID := req["jobs"].([]any)[0].(map[string]any)["job_id"].(string)
	until := time.Now().Add(5 * time.Second)
	for {
		job := obj(call("GET", "/api/v1/jobs/"+jobID, nil, 200))
		state := job["status"].(string)
		if state == "success" {
			break
		}
		if state == "failed" || state == "partial" || time.Now().After(until) {
			t.Fatalf("collection did not succeed: %v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := nodeLists.Load(); got != nodeListsAfterBinding {
		t.Fatalf("scoped deployment collection unexpectedly listed nodes %d time(s)", got-nodeListsAfterBinding)
	}
	resources := obj(call("GET", "/api/v1/clusters/"+id+"/resources/deployments?namespace=default", nil, 200))
	if len(resources["items"].([]any)) != 1 {
		t.Fatalf("expected one namespaced deployment: %v", resources)
	}
	services := obj(call("GET", "/api/v1/services?source=cluster&state=running", nil, 200))
	list := services["items"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected one running service: %v", services)
	}
	serviceID := list[0].(map[string]any)["id"].(string)
	call("POST", "/api/v1/services/"+serviceID+"/actions", map[string]any{"action": "stop", "connection_rev": 1, "expected_state": "running", "expected_desired": 2}, 403)
	active := obj(call("GET", "/api/v1/alert-events?status=active", nil, 200))
	if len(active["items"].([]any)) != 1 || active["unread_count"] != float64(0) {
		t.Fatalf("expected stored event with all notifications off: %v", active)
	}
	call("DELETE", "/api/v1/targets/"+id, nil, 204)
	call("GET", "/api/v1/clusters/"+id+"/resources/deployments", nil, 404)
	if err := db.Read(context.Background(), func(tx *sql.Tx) error {
		var enabled bool
		return tx.QueryRow(`SELECT enabled FROM targets WHERE target_id=?`, id).Scan(&enabled)
	}); err != nil {
		t.Fatal(err)
	}
	after := obj(call("GET", "/api/v1/alert-events", nil, 200))
	events := after["items"].([]any)
	if len(events) != 1 || events[0].(map[string]any)["status"] != "monitoring_stopped" {
		t.Fatalf("expected preserved event with monitoring stopped: %v", after)
	}
}
