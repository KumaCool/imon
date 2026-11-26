package collector

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientconfig "k8s.io/client-go/tools/clientcmd/api"
)

func kubeFixture(t *testing.T, handler http.HandlerFunc) Config {
	t.Helper()
	api := httptest.NewTLSServer(handler)
	t.Cleanup(api.Close)
	cfg := clientconfig.NewConfig()
	cfg.Clusters["demo"] = &clientconfig.Cluster{Server: api.URL, CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})}
	cfg.AuthInfos["demo"] = &clientconfig.AuthInfo{Token: "synthetic-token"}
	cfg.Contexts["demo"] = &clientconfig.Context{Cluster: "demo", AuthInfo: "demo"}
	cfg.CurrentContext = "demo"
	file := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, file); err != nil {
		t.Fatal(err)
	}
	return Config{Kubeconfig: file, Context: "demo"}
}

func apiFixtureProbe(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/namespaces/kube-system":
		fmt.Fprint(w, `{"metadata":{"uid":"cluster-id"}}`)
	case "/api/v1/nodes":
		fmt.Fprint(w, `{"items":[]}`)
	default:
		return false
	}
	return true
}

func TestKubeIdentityPaginationAndEmpty(t *testing.T) {
	var first atomic.Int32
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if apiFixtureProbe(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api/v1/pods":
			if r.URL.Query().Get("limit") != "200" {
				t.Errorf("bad page: %v", r.URL.Query())
			}
			if r.URL.Query().Get("continue") != "" {
				http.Error(w, "expired", http.StatusGone)
				return
			}
			if first.Add(1) == 1 {
				fmt.Fprint(w, `{"metadata":{"continue":"next"},"items":[{"metadata":{"name":"old","namespace":"demo","uid":"old-id"},"status":{"phase":"Running"}}]}`)
			} else {
				fmt.Fprint(w, `{"items":[{"metadata":{"name":"pod","namespace":"demo","uid":"new-id"},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}]}}]}`)
			}
		case "/api/v1/services":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if s, err := Open(ctx, "cluster", cfg, "other-id"); s != nil || Code(err) != "identity_changed" {
		t.Fatalf("identity: %v, %v", s, err)
	}
	s, err := Open(ctx, "cluster", cfg, "cluster-id")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.Collect(ctx, "pods")
	if err != nil || len(rows) != 1 || rows[0].Key != "new-id" {
		t.Fatalf("paging: %v, %v", rows, err)
	}
	var fields map[string]any
	if json.Unmarshal(rows[0].Data, &fields) != nil || fields["abnormal"] != true {
		t.Fatalf("pod: %v", fields)
	}
	rows, err = s.Collect(ctx, "nodes")
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("empty: %v, %v", rows, err)
	}
	if rows, err := s.Collect(ctx, "services"); rows != nil || Code(err) != "permission_denied" {
		t.Fatalf("forbidden: %v, %v", rows, err)
	}
}

func TestKubeRejectsTLSBypassAndUnapprovedExec(t *testing.T) {
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API connection for invalid config")
	})
	loaded, err := clientcmd.LoadFromFile(cfg.Kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Clusters["demo"].InsecureSkipTLSVerify = true
	if err = clientcmd.WriteToFile(*loaded, cfg.Kubeconfig); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), "cluster", cfg, ""); Code(err) != "insecure_tls" {
		t.Fatalf("TLS: %v", err)
	}
	loaded.Clusters["demo"].InsecureSkipTLSVerify = false
	program := filepath.Join(t.TempDir(), "demo-plugin")
	if err := os.WriteFile(program, []byte("test fixture; not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded.AuthInfos["demo"].Token = ""
	loaded.AuthInfos["demo"].Exec = &clientconfig.ExecConfig{Command: program, APIVersion: "client.authentication.k8s.io/v1", InteractiveMode: clientconfig.NeverExecInteractiveMode}
	if err = clientcmd.WriteToFile(*loaded, cfg.Kubeconfig); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), "cluster", cfg, ""); Code(err) != "exec_approval_required" {
		t.Fatalf("exec: %v", err)
	}
	first, err := KubeExecApproval(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		t.Fatal(err)
	}
	loaded.AuthInfos["demo"].Exec.Args = []string{"changed"}
	if err = clientcmd.WriteToFile(*loaded, cfg.Kubeconfig); err != nil {
		t.Fatal(err)
	}
	second, err := KubeExecApproval(cfg.Kubeconfig, cfg.Context)
	if err != nil || first == second {
		t.Fatalf("approval was reused: %q %q %v", first, second, err)
	}
}

func TestEndpointSliceBackendDerivation(t *testing.T) {
	var mode atomic.Int32
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if apiFixtureProbe(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api/v1/services":
			fmt.Fprint(w, `{"items":[{"metadata":{"uid":"service-id","name":"web","namespace":"demo"},"spec":{"type":"ClusterIP","selector":{"app":"web"},"ports":[{"port":80,"protocol":"TCP"}]}}]}`)
		case "/apis/discovery.k8s.io/v1/endpointslices":
			if mode.Load() == 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `{"items":[
				{"metadata":{"name":"v4","namespace":"demo","labels":{"kubernetes.io/service-name":"web"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.10"],"targetRef":{"kind":"Pod","uid":"demo-pod"}},{"addresses":["192.0.2.11"],"conditions":{"terminating":true}}]},
				{"metadata":{"name":"v6","namespace":"demo","labels":{"kubernetes.io/service-name":"web"}},"addressType":"IPv6","endpoints":[{"addresses":["2001:db8::10"],"targetRef":{"kind":"Pod","uid":"demo-pod"}}]},
				{"metadata":{"name":"old","namespace":"demo","labels":{"kubernetes.io/service-name":"web"},"ownerReferences":[{"kind":"Service","uid":"previous-id"}]},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.12"]}]}
			]}`)
		default:
			http.NotFound(w, r)
		}
	})
	session, err := Open(t.Context(), "cluster", cfg, "cluster-id")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, test := range []struct {
		mode  int32
		ready any
		state string
	}{{0, float64(1), "ok"}, {1, nil, "unreadable"}} {
		mode.Store(test.mode)
		rows, err := session.Collect(t.Context(), "services")
		if err != nil || len(rows) != 1 {
			t.Fatalf("service: %v, %v", rows, err)
		}
		var fields map[string]any
		if json.Unmarshal(rows[0].Data, &fields) != nil || fields["ready_backends"] != test.ready || fields["backends_state"] != test.state {
			t.Fatalf("service fields = %v", fields)
		}
	}
}

func TestKubeDeploymentActionRechecksUIDAndHPA(t *testing.T) {
	var puts, replicas atomic.Int32
	replicas.Store(3)
	var hpa atomic.Bool
	var noScaleSpec atomic.Bool
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if apiFixtureProbe(w, r) {
			return
		}
		switch r.URL.Path {
		case "/apis/apps/v1/namespaces/demo/deployments/web":
			fmt.Fprintf(w, `{"metadata":{"uid":"deployment-id","name":"web","namespace":"demo","generation":1,"resourceVersion":"7"},"spec":{"replicas":%d},"status":{"observedGeneration":1,"readyReplicas":%d,"replicas":%d}}`, replicas.Load(), replicas.Load(), replicas.Load())
		case "/apis/autoscaling/v2/namespaces/demo/horizontalpodautoscalers":
			if hpa.Load() {
				fmt.Fprint(w, `{"items":[{"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"web"}}}]}`)
			} else {
				fmt.Fprint(w, `{"items":[]}`)
			}
		case "/apis/apps/v1/namespaces/demo/deployments/web/scale":
			if r.Method == http.MethodPut {
				puts.Add(1)
				var payload scaleResource
				if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Meta.Version != "7" || payload.Spec == nil {
					t.Errorf("invalid Scale update")
					w.WriteHeader(400)
					return
				}
				replicas.Store(payload.Spec.Replicas)
			}
			body := `{"kind":"Scale","apiVersion":"autoscaling/v1","metadata":{"uid":"deployment-id","name":"web","namespace":"demo","resourceVersion":"7"}`
			if noScaleSpec.Load() {
				fmt.Fprint(w, body+`}`)
			} else if r := replicas.Load(); r == 0 {
				fmt.Fprint(w, body+`,"spec":{}}`)
			} else {
				fmt.Fprintf(w, body+`,"spec":{"replicas":%d}}`, r)
			}
		default:
			http.NotFound(w, r)
		}
	})
	want := int32(3)
	req := ActionRequest{Action: "stop", Key: "deployment-id", Name: "web", Namespace: "demo", ExpectedState: "running", ExpectedDesired: &want}
	hpa.Store(true)
	result, err := RunServiceAction(t.Context(), "cluster", cfg, "cluster-id", req, func(int32) error { t.Fatal("intent recorded despite HPA"); return nil })
	if Code(err) != "autoscaler_present" || result.Sent || puts.Load() != 0 {
		t.Fatalf("blocked = %#v %v", result, err)
	}
	hpa.Store(false)
	req.Key = "old-uid"
	result, err = RunServiceAction(t.Context(), "cluster", cfg, "cluster-id", req, func(int32) error { t.Fatal("intent recorded despite replacement"); return nil })
	if Code(err) != "object_changed" || result.Sent || puts.Load() != 0 {
		t.Fatalf("blocked replacement = %#v %v", result, err)
	}
	req.Key = "deployment-id"
	result, err = RunServiceAction(t.Context(), "cluster", cfg, "cluster-id", req, func(old int32) error {
		if old != 3 || puts.Load() != 0 {
			t.Fatalf("preflight ordering: previous=%d, puts=%d", old, puts.Load())
		}
		return nil
	})
	if err != nil || !result.Confirmed || result.Desired == nil || *result.Desired != 0 || puts.Load() != 1 {
		t.Fatalf("stop = %#v %v", result, err)
	}
	zero := int32(0)
	req.Action, req.ExpectedState, req.ExpectedDesired, req.Replicas = "start", "stopped", &zero, &want
	noScaleSpec.Store(true)
	result, err = RunServiceAction(t.Context(), "cluster", cfg, "cluster-id", req, func(int32) error { t.Fatal("intent recorded without Scale spec"); return nil })
	if Code(err) != "version_conflict" || result.Sent || puts.Load() != 1 {
		t.Fatalf("missing Scale spec = %#v %v", result, err)
	}
	noScaleSpec.Store(false)
	result, err = RunServiceAction(t.Context(), "cluster", cfg, "cluster-id", req, func(old int32) error {
		if old != 0 || puts.Load() != 1 {
			t.Fatalf("preflight ordering: previous=%d, puts=%d", old, puts.Load())
		}
		return nil
	})
	if err != nil || !result.Confirmed || result.Desired == nil || *result.Desired != 3 || puts.Load() != 2 {
		t.Fatalf("start = %#v %v", result, err)
	}
}
