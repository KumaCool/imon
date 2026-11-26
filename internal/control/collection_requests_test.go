package control

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

func setupCollection(t *testing.T) (*Control, *http.ServeMux) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "fixture.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, stop := context.WithCancel(t.Context())
	t.Cleanup(stop)
	c := &Control{db: db, ctx: ctx, wake: make(chan struct{}, 1),
		settings: Settings{Enabled: true, Host: 60, Network: 300, Cluster: 60, Timeout: 45, Revision: 1},
		due:      map[string]map[string]time.Time{}, backoff: map[string]time.Time{}, failures: map[string]int{},
		active: map[string]*collection{}, queued: map[string]*collection{}, streak: map[string]int{}}
	mux := http.NewServeMux()
	c.Register(mux)
	return c, mux
}

func seedCollectionTarget(t *testing.T, c *Control, id, kind string) {
	t.Helper()
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO targets(target_id,kind,name,connection_ref,identity,connection_rev,enabled) VALUES(?,?,?,'{}','fixture',1,1)`, id, kind, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func seedCollectionRule(t *testing.T, c *Control, id, target, group string, rev int64, enabled bool) {
	t.Helper()
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO alert_rules(id,target_id,group_name,connection_rev,revision,enabled,config) VALUES(?,?,?,?,1,?,'{}')`, id, target, group, rev, enabled)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func collectionHTTP(t *testing.T, mux *http.ServeMux, method, path, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s: %d, want %d: %s", method, path, w.Code, want, w.Body.String())
	}
	return w
}

func TestCollectionViewsReuseOnlyMatchingGroups(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "host-a", "host")
	seedCollectionTarget(t, c, "host-b", "host")
	seedCollectionTarget(t, c, "cluster-a", "cluster")
	path := "/api/v1/collection-requests"
	collectionHTTP(t, mux, "POST", path, `{"view":"network","target_id":"cluster-a","group":"listeners"}`, 400)
	collectionHTTP(t, mux, "POST", path, `{"view":"network","target_id":"unknown","group":"listeners"}`, 404)
	collectionHTTP(t, mux, "POST", path, `{"view":"network","target_id":"host-a","group":"systemd"}`, 400)
	collectionHTTP(t, mux, "POST", path, `{"view":"hosts","groups":["systemd"]}`, 400)
	collectionHTTP(t, mux, "POST", "/api/v1/targets/host-a/collect", `{}`, 404)
	collectionHTTP(t, mux, "POST", path, `{"view":"host_metrics","target_id":"host-a"}`, 202)
	c.active["host-a"] = c.queued["host-a"]
	delete(c.queued, "host-a")
	w := collectionHTTP(t, mux, "POST", path, `{"view":"hosts","limit":1}`, 202)
	var out struct{ Jobs []map[string]string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Jobs) != 2 {
		t.Fatalf("expected reused metrics plus new OS job: %s (%v)", w.Body.String(), err)
	}
	if out.Jobs[0]["job_id"] != c.active["host-a"].job.ID || out.Jobs[1]["job_id"] != c.queued["host-a"].job.ID || len(c.queued["host-a"].groups) != 1 || !c.queued["host-a"].manual["os_info"] || c.queued["host-b"] != nil {
		t.Fatalf("wrong deduplication or pagination: %s / %+v", w.Body.String(), c.queued)
	}
	collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"cluster"}`, 202)
	if q := c.queued["cluster-a"]; q == nil || len(q.groups) != 1 || !q.manual["deployments"] {
		t.Fatalf("expected only the deployments group, got %#v", q)
	}
}

func TestServiceCollectionPaginatesBindings(t *testing.T) {
	c, mux := setupCollection(t)
	for i := range 33 {
		seedCollectionTarget(t, c, fmt.Sprintf("host-%02d", i), "host")
	}
	path := "/api/v1/collection-requests"
	first := collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"host"}`, 202)
	var response struct {
		Jobs []map[string]string `json:"jobs"`
		Next string              `json:"next_cursor"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &response); err != nil || len(response.Jobs) != 32 || response.Next != "host-31" {
		t.Fatalf("unexpected first page: %s (%v)", first.Body.String(), err)
	}
	second := collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"host","cursor":"host-31"}`, 202)
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil || len(response.Jobs) != 1 || response.Jobs[0]["target_id"] != "host-32" {
		t.Fatalf("unexpected second page: %s (%v)", second.Body.String(), err)
	}
	empty := collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"host","cursor":"host-32"}`, 200)
	if strings.TrimSpace(empty.Body.String()) != `{"jobs":[]}` {
		t.Fatalf("unexpected empty page: %s", empty.Body.String())
	}
}

func TestAutomaticCollectionFollowsRulesAndScopesProgress(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "active", "host")
	seedCollectionTarget(t, c, "paused", "host")
	seedCollectionTarget(t, c, "unmonitored", "cluster")
	seedCollectionRule(t, c, "cpu", "active", "metrics", 1, true)
	seedCollectionRule(t, c, "port", "active", "listeners", 1, true)
	seedCollectionRule(t, c, "service", "paused", "systemd", 1, false)
	seedCollectionRule(t, c, "wrong-revision", "unmonitored", "nodes", 2, true)
	now := time.Now()
	c.plan(now)
	q := c.queued["active"]
	if len(c.queued) != 1 || q == nil || len(q.groups) != 2 || !q.groups["host_metrics"] || !q.groups["listeners"] {
		t.Fatalf("automatic plan scheduled missing, extra or stale dependencies: %+v", q)
	}
	check := func(view, want string) {
		t.Helper()
		w := collectionHTTP(t, mux, "GET", "/api/v1/collection-status?"+view, "", 200)
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("unexpected status for %s: %s (want %s)", view, w.Body.String(), want)
		}
	}
	check("view=hosts", `"active":{"total":1,"completed":0}`)
	check("view=services", `"next_run_at":null,"active":null`)
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE alert_rules SET enabled=0 WHERE id='port'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c.plan(now)
	if len(q.groups) != 1 || !q.groups["host_metrics"] {
		t.Fatalf("disabled rule retained queued group: %v", q.groups)
	}
	check("view=network&target_id=active&group=listeners", `"next_run_at":null,"active":null`)
	c.finishPlanned(q)
	delete(c.queued, "active")
	c.clearFinishedRound()
	check("view=hosts", fmt.Sprintf(`"next_run_at":%d,"active":null`, now.Add(time.Minute).UnixMilli()))
	c.plan(now.Add(time.Minute))
	check("view=hosts", `"active":{"total":1,"completed":0}`)
	collectionHTTP(t, mux, "PUT", "/api/v1/sampling-settings", `{"poll_enabled":false,"host_interval":60,"network_interval":300,"cluster_interval":60,"timeout":45}`, 200)
	check("view=hosts", `"next_run_at":null,"active":null`)
	if c.queued["active"] != nil {
		t.Fatal("automatic-only job survived disabling polling")
	}
}

func TestProbeOnlyFailureEndsAutomaticRound(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedCollectionRule(t, c, "reachability", "fixture", "probe", 1, true)
	c.plan(time.Now())
	q := c.queued["fixture"]
	if q == nil || len(q.groups) != 1 || !q.groups["probe"] {
		t.Fatal("a standalone probe must not request data groups")
	}
	c.mu.Lock()
	c.dispatch()
	c.mu.Unlock()
	c.wg.Wait()
	w := collectionHTTP(t, mux, "GET", "/api/v1/jobs/"+q.job.ID, "", 200)
	var job Job
	if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil || job.Status != "failed" || job.Results["probe"] == "" || job.CompletedAt == nil {
		t.Fatalf("invalid SSH config should yield a terminal probe failure: %s (%v)", w.Body.String(), err)
	}
	if task := c.round["fixture"].groups["probe"]; !task.done {
		t.Fatal("failed probe did not finish its round entry")
	}
	if c.backoff["fixture"].IsZero() {
		t.Fatal("failed probe did not schedule connection backoff")
	}
}

func TestScheduledCollectionWaitsForRunningOnDemandSample(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", `{"view":"host_metrics","target_id":"fixture"}`, 202)
	manual := c.queued["fixture"]
	c.active["fixture"] = manual
	delete(c.queued, "fixture")
	seedCollectionRule(t, c, "cpu", "fixture", "metrics", 1, true)
	now := time.Now()
	c.plan(now)
	if c.queued["fixture"] != nil || manual.groups["host_metrics"] {
		t.Fatal("due schedule overlapped or relabeled a running on-demand sample")
	}
	delete(c.active, "fixture")
	c.plan(now)
	if scheduled := c.queued["fixture"]; scheduled == nil || !scheduled.groups["host_metrics"] || scheduled.job.ID == manual.job.ID {
		t.Fatal("due schedule did not start a separate sample after the on-demand one")
	}
}

func TestServiceObservationDistinguishesUncollectedEmptyAndStale(t *testing.T) {
	c, _ := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	ctx := t.Context()
	observe := func() serviceObservation {
		t.Helper()
		summary := map[string]any{}
		if err := c.db.Read(ctx, func(tx *sql.Tx) error {
			return addServiceObservation(ctx, tx, store.Target{ID: "fixture", Kind: "host", ConnectionRev: 1}, c.settings, summary)
		}); err != nil {
			t.Fatal(err)
		}
		return summary["service_observation"].(serviceObservation)
	}
	if v := observe(); v.Group != "systemd" || v.HasItems != nil || v.ObservedAt != nil || v.ErrorCode != "" {
		t.Fatalf("uncollected service group looks observed: %+v", v)
	}
	now := time.Now().UnixMilli()
	key := store.SnapshotKey{TargetID: "fixture", ConnectionRev: 1, Group: "systemd", BatchID: "empty"}
	if err := c.db.StartSnapshot(ctx, key, now); err != nil {
		t.Fatal(err)
	}
	if err := c.db.PublishSnapshot(ctx, key, now, now, nil); err != nil {
		t.Fatal(err)
	}
	if v := observe(); v.HasItems == nil || *v.HasItems || v.ObservedAt == nil || *v.ObservedAt != now || v.Stale {
		t.Fatalf("published empty group not distinguishable from missing: %+v", v)
	}
	key.BatchID = "failed"
	if err := c.db.StartSnapshot(ctx, key, now+1); err != nil {
		t.Fatal(err)
	}
	if err := c.db.FailSnapshotWith(ctx, key, now+1, "timeout", nil); err != nil {
		t.Fatal(err)
	}
	if v := observe(); v.HasItems == nil || *v.HasItems || v.ObservedAt == nil || *v.ObservedAt != now || !v.Stale || v.ErrorCode != "timeout" {
		t.Fatalf("failed attempt hid the older published empty result: %+v", v)
	}
	key.BatchID = "recovered"
	if err := c.db.StartSnapshot(ctx, key, now+2); err != nil {
		t.Fatal(err)
	}
	if err := c.db.PublishSnapshot(ctx, key, now+2, now+2, nil); err != nil {
		t.Fatal(err)
	}
	if v := observe(); v.ErrorCode != "" || v.Stale {
		t.Fatalf("successful attempt retained a service collection error: %+v", v)
	}
}

func TestCollectionDispatchRunsDistinctClustersWithinConcurrentLimit(t *testing.T) {
	c, mux := setupCollection(t)
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/namespaces/kube-system" {
			started <- struct{}{}
			select {
			case <-release:
				io.WriteString(w, `{"metadata":{"name":"kube-system","uid":"fixture"}}`)
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, `{"items":[]}`)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { c.wg.Wait() })
	t.Cleanup(func() { close(release) })
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	kubeconfig := filepath.Join(t.TempDir(), "fixture.json")
	configFile := fmt.Sprintf(`{"apiVersion":"v1","kind":"Config","current-context":"fixture","contexts":[{"name":"fixture","context":{"cluster":"fixture"}}],"clusters":[{"name":"fixture","cluster":{"server":%q,"certificate-authority-data":%q}}]}`, server.URL, base64.StdEncoding.EncodeToString(root))
	if err := os.WriteFile(kubeconfig, []byte(configFile), 0600); err != nil {
		t.Fatal(err)
	}
	config := collector.Config{Kubeconfig: kubeconfig, Context: "fixture"}
	cfg, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"cluster-a", "cluster-b", "cluster-c"} {
		seedCollectionTarget(t, c, id, "cluster")
		if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE targets SET connection_ref=? WHERE target_id=?`, string(cfg), id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", fmt.Sprintf(`{"view":"cluster","target_id":%q,"group":"nodes"}`, id), 202)
	}
	c.mu.Lock()
	c.dispatch()
	active, queued := len(c.active), len(c.queued)
	var runningID string
	for id := range c.active {
		runningID = id
		break
	}
	c.mu.Unlock()
	if active != 2 || queued != 1 {
		t.Fatalf("expected two active Kubernetes jobs and one queued, got %d/%d", active, queued)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("two distinct clusters did not begin their requests concurrently")
		}
	}
	collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", fmt.Sprintf(`{"view":"cluster","target_id":%q,"group":"pods"}`, runningID), 202)
	c.mu.Lock()
	c.dispatch()
	q := c.queued[runningID]
	c.mu.Unlock()
	if q == nil || !q.manual["pods"] {
		t.Fatal("second group of an active target did not wait for its existing job")
	}
}
