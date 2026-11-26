package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestKubeDeploymentUsage(t *testing.T) {
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if apiFixtureProbe(w, r) {
			return
		}
		switch r.URL.Path {
		case "/apis/apps/v1/deployments":
			fmt.Fprint(w, `{"items":[
				{"metadata":{"uid":"web","name":"web","namespace":"demo"}},
				{"metadata":{"uid":"partial","name":"partial","namespace":"demo"}},
				{"metadata":{"uid":"missing","name":"missing","namespace":"demo"}},
				{"metadata":{"uid":"zero","name":"zero","namespace":"demo"}},
				{"metadata":{"uid":"incomplete","name":"incomplete","namespace":"demo"}},
				{"metadata":{"uid":"stale","name":"stale","namespace":"demo"}}
			]}`)
		case kubePodMetricsPath:
			fmt.Fprint(w, `{"items":[
				{"metadata":{"name":"web-1","namespace":"demo"},"containers":[{"usage":{"cpu":"120m","memory":"2Mi"}},{"usage":{"cpu":"50000000n","memory":"1Mi"}}]},
				{"metadata":{"name":"web-2","namespace":"demo"},"containers":[{"usage":{"cpu":"150m","memory":"1Mi"}}]},
				{"metadata":{"name":"web-1","namespace":"other"},"containers":[{"usage":{"cpu":"8","memory":"1Gi"}}]},
				{"metadata":{"name":"unrelated","namespace":"demo"},"containers":[{"usage":{"cpu":"8","memory":"1Gi"}}]},
				{"metadata":{"name":"partial-1","namespace":"demo"},"containers":[{"usage":{"cpu":"25m"}}]},
				{"metadata":{"name":"missing-1","namespace":"demo","uid":"replaced"},"containers":[{"usage":{"cpu":"8","memory":"1Gi"}}]},
				{"metadata":{"name":"zero-1","namespace":"demo"},"containers":[{"usage":{"cpu":"0","memory":"0"}}]},
				{"metadata":{"name":"incomplete-1","namespace":"demo"},"containers":[{"usage":{"cpu":"200m","memory":"3Mi"}}]},
				{"metadata":{"name":"stale-1","namespace":"demo"},"timestamp":"2025-01-01T00:00:00Z","containers":[{"usage":{"cpu":"100m","memory":"2Mi"}}]}
			]}`)
		case kubeReplicaSetsPath:
			fmt.Fprint(w, `{"items":[
				{"metadata":{"uid":"web-old","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"web","controller":true}]}},
				{"metadata":{"uid":"web-new","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"web","controller":true}]}},
				{"metadata":{"uid":"unrelated","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"web","controller":false}]}},
				{"metadata":{"uid":"partial","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"partial","controller":true}]}},
				{"metadata":{"uid":"missing","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"missing","controller":true}]}},
				{"metadata":{"uid":"zero","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"zero","controller":true}]}},
				{"metadata":{"uid":"incomplete","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"incomplete","controller":true}]}},
				{"metadata":{"uid":"stale","namespace":"demo","ownerReferences":[{"kind":"Deployment","uid":"stale","controller":true}]}}
			]}`)
		case "/api/v1/pods":
			fmt.Fprint(w, `{"items":[
				{"metadata":{"name":"web-1","namespace":"demo","uid":"pod-1","ownerReferences":[{"kind":"ReplicaSet","uid":"web-old","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"web-2","namespace":"demo","uid":"pod-2","ownerReferences":[{"kind":"ReplicaSet","uid":"web-new","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"unrelated","namespace":"demo","uid":"pod-3","ownerReferences":[{"kind":"ReplicaSet","uid":"unrelated","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"partial-1","namespace":"demo","uid":"pod-4","ownerReferences":[{"kind":"ReplicaSet","uid":"partial","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"missing-1","namespace":"demo","uid":"pod-5","ownerReferences":[{"kind":"ReplicaSet","uid":"missing","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"zero-1","namespace":"demo","uid":"pod-6","ownerReferences":[{"kind":"ReplicaSet","uid":"zero","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"incomplete-1","namespace":"demo","uid":"pod-7","ownerReferences":[{"kind":"ReplicaSet","uid":"incomplete","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"incomplete-2","namespace":"demo","uid":"pod-8","ownerReferences":[{"kind":"ReplicaSet","uid":"incomplete","controller":true}]},"status":{"phase":"Running"}},
				{"metadata":{"name":"stale-1","namespace":"demo","uid":"pod-9","creationTimestamp":"2025-01-02T00:00:00Z","ownerReferences":[{"kind":"ReplicaSet","uid":"stale","controller":true}]},"status":{"phase":"Running"}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	})
	rows, err := Collect(t.Context(), "cluster", cfg, "cluster-id", "deployments")
	if err != nil || len(rows) != 6 {
		t.Fatalf("collect deployments = %v, %v", rows, err)
	}
	type usage struct {
		CPU    *float64 `json:"cpu_percent"`
		Memory *uint64  `json:"memory_bytes"`
	}
	result := make(map[string]usage)
	for _, r := range rows {
		var u usage
		if err := json.Unmarshal(r.Data, &u); err != nil {
			t.Fatal(err)
		}
		result[r.Key] = u
	}
	if u := result["web"]; u.CPU == nil || math.Abs(*u.CPU-32) > 1e-6 || u.Memory == nil || *u.Memory != 4<<20 {
		t.Fatalf("web usage = %s", rows[0].Data)
	}
	if u := result["partial"]; u.CPU == nil || math.Abs(*u.CPU-2.5) > 1e-6 || u.Memory != nil {
		t.Fatalf("partial usage = %s", rows[1].Data)
	}
	if u := result["missing"]; u.CPU != nil || u.Memory != nil {
		t.Fatalf("missing usage = %s", rows[2].Data)
	}
	if u := result["zero"]; u.CPU == nil || *u.CPU != 0 || u.Memory == nil || *u.Memory != 0 {
		t.Fatalf("measured zero usage = %s", rows[3].Data)
	}
	if u := result["incomplete"]; u.CPU != nil || u.Memory != nil {
		t.Fatalf("usage was reported as a complete sum without all Pods: %s", rows[4].Data)
	}
	if u := result["stale"]; u.CPU != nil || u.Memory != nil {
		t.Fatalf("usage predates Pod creation: %s", rows[5].Data)
	}
}

func TestKubeDeploymentUsageOptional(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var metricsRequests atomic.Int32
			cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if apiFixtureProbe(w, r) {
					return
				}
				switch r.URL.Path {
				case "/apis/apps/v1/deployments":
					fmt.Fprint(w, `{"items":[{"metadata":{"uid":"web","name":"web","namespace":"demo","generation":1},"status":{"observedGeneration":1,"readyReplicas":1,"replicas":1}}]}`)
				case kubePodMetricsPath:
					metricsRequests.Add(1)
					w.WriteHeader(status)
				default:
					t.Errorf("unexpected request after unavailable metrics: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			rows, err := Collect(t.Context(), "cluster", cfg, "cluster-id", "deployments")
			if err != nil || len(rows) != 1 || metricsRequests.Load() != 1 {
				t.Fatalf("collect deployments = %v, %v, requests = %d", rows, err, metricsRequests.Load())
			}
			var fields map[string]any
			if json.Unmarshal(rows[0].Data, &fields) != nil || fields["state"] != "running" {
				t.Fatalf("deployment state lost: %s", rows[0].Data)
			}
			for _, key := range []string{"cpu_percent", "memory_bytes"} {
				if _, ok := fields[key]; ok {
					t.Fatalf("unavailable metric was included: %s", rows[0].Data)
				}
			}
		})
	}
}

func TestKubeDeploymentUsageTimeoutKeepsRows(t *testing.T) {
	metricsRequested := make(chan struct{}, 1)
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if apiFixtureProbe(w, r) {
			return
		}
		switch r.URL.Path {
		case "/apis/apps/v1/deployments":
			fmt.Fprint(w, `{"items":[{"metadata":{"uid":"web","name":"web","namespace":"demo"}}]}`)
		case kubePodMetricsPath:
			metricsRequested <- struct{}{}
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	})
	session, err := Open(t.Context(), "cluster", cfg, "cluster-id")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	rows, err := session.Collect(ctx, "deployments")
	if err != nil || len(rows) != 1 || ctx.Err() != nil {
		t.Fatalf("optional usage exceeded the outer collection budget: %v, %v, %v", rows, err, ctx.Err())
	}
	select {
	case <-metricsRequested:
	default:
		t.Fatal("metrics API was not requested")
	}
}
