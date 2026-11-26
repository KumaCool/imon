package control

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"imon/internal/store"
)

func seedForegroundAttempt(t *testing.T, c *Control, id, group string, started, completed time.Time, failed bool) {
	t.Helper()
	key := store.SnapshotKey{TargetID: id, ConnectionRev: 1, Group: group, BatchID: newID()}
	if err := c.db.StartSnapshot(t.Context(), key, started.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	at := completed.UnixMilli()
	var err error
	if failed {
		err = c.db.FailSnapshotWith(t.Context(), key, at, "fixture_error", nil)
	} else {
		err = c.db.PublishSnapshot(t.Context(), key, at, at, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func checkForegroundStatus(t *testing.T, mux *http.ServeMux, scope string, due bool, next time.Time) {
	t.Helper()
	checkForegroundProgress(t, mux, scope, due, next, nil)
}

func checkForegroundProgress(t *testing.T, mux *http.ServeMux, scope string, due bool, next time.Time, active *collectionProgress) {
	t.Helper()
	w := collectionHTTP(t, mux, "GET", "/api/v1/collection-status?"+scope, "", 200)
	var out struct {
		Due    *bool               `json:"foreground_due"`
		Next   *int64              `json:"next_foreground_at"`
		Active *collectionProgress `json:"active"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Due == nil || *out.Due != due ||
		next.IsZero() != (out.Next == nil) || out.Next != nil && *out.Next != next.UnixMilli() ||
		(active == nil) != (out.Active == nil) || active != nil && *active != *out.Active {
		t.Fatalf("%s: due %t, next %v, active %+v; got %s (%v)", scope, due, next, active, w.Body.String(), err)
	}
}

func TestForegroundIntervalsUseLatestAttemptAndSeparateGroups(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "host", "host")
	seedCollectionTarget(t, c, "cluster", "cluster")
	c.settings.Host, c.settings.Network, c.settings.Cluster = 60, 120, 240
	now := time.Now().Add(-5 * time.Second)
	old := now.Add(-5 * time.Minute)
	seedForegroundAttempt(t, c, "host", "host_metrics", old, now, true)
	seedForegroundAttempt(t, c, "host", "listeners", now, now, false)
	seedForegroundAttempt(t, c, "host", "routes", old, old, false)
	seedForegroundAttempt(t, c, "cluster", "pods", now, now, false)
	checkForegroundStatus(t, mux, "view=hosts", true, now.Add(time.Minute))
	checkForegroundStatus(t, mux, "view=host_metrics&target_id=host", false, now.Add(time.Minute))
	checkForegroundStatus(t, mux, "view=network&target_id=host&group=listeners", false, now.Add(2*time.Minute))
	checkForegroundStatus(t, mux, "view=network&target_id=host&group=routes", true, time.Time{})
	checkForegroundStatus(t, mux, "view=cluster&target_id=cluster&group=pods", false, now.Add(4*time.Minute))
	path := "/api/v1/collection-requests"
	collectionHTTP(t, mux, "POST", path, `{"view":"host_metrics","target_id":"host","due_only":true}`, 200)
	collectionHTTP(t, mux, "POST", path, `{"view":"cluster","target_id":"cluster","group":"pods","due_only":true}`, 200)
	collectionHTTP(t, mux, "POST", path, `{"view":"hosts","due_only":true}`, 202)
	if queued := c.queued["host"]; len(queued.groups) != 1 || !queued.manual["os_info"] {
		t.Fatalf("first visit should only queue the missing OS group: %+v", queued)
	}
	collectionHTTP(t, mux, "POST", path, `{"view":"network","target_id":"host","group":"routes","due_only":true}`, 202)
	if queued := c.queued["host"]; len(queued.groups) != 2 || !queued.manual["routes"] {
		t.Fatalf("routes should be due independently of other network groups: %+v", queued)
	}
}

func TestForegroundDisabledOnlyAllowsInitialAttemptAtCurrentRevision(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "host", "host")
	c.settings.Enabled = false
	old := time.Now().Add(-24 * time.Hour)
	seedForegroundAttempt(t, c, "host", "host_metrics", old, old, true)
	path := "/api/v1/collection-requests"
	request := `{"view":"host_metrics","target_id":"host","due_only":true}`
	checkForegroundStatus(t, mux, "view=host_metrics&target_id=host", false, time.Time{})
	collectionHTTP(t, mux, "POST", path, request, 200)
	collectionHTTP(t, mux, "POST", path, `{"view":"host_metrics","target_id":"host"}`, 202)
	delete(c.queued, "host")
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE targets SET connection_rev=2 WHERE target_id='host'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	checkForegroundStatus(t, mux, "view=host_metrics&target_id=host", true, time.Time{})
	collectionHTTP(t, mux, "POST", path, request, 202)
	if c.queued["host"].target.ConnectionRev != 2 {
		t.Fatal("older connection revision blocked the initial collection")
	}
}

func TestForegroundRequestReusesWorkWithoutPromotingNonDueGroups(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "host", "host")
	now := time.Now()
	seedForegroundAttempt(t, c, "host", "host_metrics", now, now, false)
	seedForegroundAttempt(t, c, "host", "os_info", now, now, false)
	target, err := c.target(t.Context(), "host")
	if err != nil {
		t.Fatal(err)
	}
	active, err := c.enqueueGroups(t.Context(), target, map[string]bool{"host_metrics": true}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	c.active["host"] = c.queued["host"]
	delete(c.queued, "host")
	queued, err := c.enqueueGroups(t.Context(), target, map[string]bool{"os_info": true}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	w := collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", `{"view":"hosts","due_only":true}`, 202)
	var out struct {
		Jobs []struct {
			ID string `json:"job_id"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Jobs) != 2 || out.Jobs[0].ID != active[0] || out.Jobs[1].ID != queued[0] {
		t.Fatalf("expected original active and queued jobs, got %s (%v)", w.Body.String(), err)
	}
	if len(c.queued["host"].manual) != 0 {
		t.Fatal("non-due foreground refresh must not change queued alarm ownership")
	}
}

func TestForegroundStatusScopesQueuedAndRunningWork(t *testing.T) {
	c, mux := setupCollection(t)
	c.settings.Enabled = false
	seedCollectionTarget(t, c, "a", "host")
	seedCollectionTarget(t, c, "b", "host")
	now := time.Now()
	seedForegroundAttempt(t, c, "a", "os_info", now, now, false)
	path := "/api/v1/collection-requests"
	input := `{"view":"host_metrics","target_id":"a","due_only":true}`
	scope := "view=host_metrics&target_id=a"
	checkForegroundStatus(t, mux, scope, true, time.Time{})
	first := collectionHTTP(t, mux, "POST", path, input, 202)
	checkForegroundProgress(t, mux, scope, false, time.Time{}, &collectionProgress{Total: 1})
	if repeat := collectionHTTP(t, mux, "POST", path, input, 202); repeat.Body.String() != first.Body.String() {
		t.Fatalf("queued group got a second job: %s then %s", first.Body.String(), repeat.Body.String())
	}
	c.active["a"] = c.queued["a"]
	delete(c.queued, "a")
	checkForegroundProgress(t, mux, scope, false, time.Time{}, &collectionProgress{Total: 1})
	// The first page is fully covered; the wider view still has an untouched target.
	checkForegroundProgress(t, mux, "view=hosts&limit=1", false, time.Time{}, &collectionProgress{Total: 1})
	checkForegroundProgress(t, mux, "view=hosts", true, time.Time{}, &collectionProgress{Total: 1})
	checkForegroundStatus(t, mux, "view=network&target_id=a&group=routes", true, time.Time{})
	collectionHTTP(t, mux, "POST", path, `{"view":"hosts","due_only":true}`, 202)
	checkForegroundProgress(t, mux, "view=hosts", false, time.Time{}, &collectionProgress{Total: 2})
	if c.queued["a"] != nil {
		t.Fatal("covered or fresh groups queued another job")
	}
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE targets SET connection_rev=2 WHERE target_id='a'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	checkForegroundStatus(t, mux, scope, true, time.Time{})
}

func TestForegroundProgressCountsTargetsOnceAcrossQueuesAndAlertRound(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "a", "host")
	seedCollectionTarget(t, c, "b", "host")
	for _, id := range []string{"a", "b"} {
		seedCollectionRule(t, c, "cpu-"+id, id, "metrics", 1, true)
	}
	now := time.Now()
	c.plan(now)
	collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", `{"view":"hosts","due_only":true}`, 202)
	if q := c.queued["a"]; len(q.groups) != 2 || q.manual["host_metrics"] || !q.manual["os_info"] {
		t.Fatalf("already scheduled metrics must not gain manual ownership: %+v", q)
	}
	c.finishPlanned(c.queued["b"])
	delete(c.queued, "b")
	seedForegroundAttempt(t, c, "b", "host_metrics", now, now, false)
	seedForegroundAttempt(t, c, "b", "os_info", now, now, false)
	checkForegroundProgress(t, mux, "view=hosts", false, now.Add(time.Minute), &collectionProgress{Total: 2, Completed: 1})
}

func TestForegroundIntervalStartsAfterDispatchCompletes(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	path := "/api/v1/collection-requests"
	input := `{"view":"host_metrics","target_id":"fixture","due_only":true}`
	scope := "view=host_metrics&target_id=fixture"
	checkForegroundStatus(t, mux, scope, true, time.Time{})
	collectionHTTP(t, mux, "POST", path, input, 202)
	checkForegroundProgress(t, mux, scope, false, time.Time{}, &collectionProgress{Total: 1})
	c.mu.Lock()
	c.dispatch()
	c.mu.Unlock()
	c.wg.Wait()
	var completed int64
	if err := c.db.Read(t.Context(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT completed_at FROM snapshot_batches WHERE target_id='fixture' AND group_name='host_metrics'`).Scan(&completed)
	}); err != nil {
		t.Fatal(err)
	}
	next := time.UnixMilli(completed).Add(time.Minute)
	checkForegroundStatus(t, mux, scope, false, next)
	collectionHTTP(t, mux, "POST", path, input, 200)
	selection, err := c.collectionScope(t.Context(), collectionRequest{View: "host_metrics", TargetID: "fixture"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.foregroundGroups(t.Context(), selection, next, func(_, _ string, state foregroundGroupStatus) {
		if !state.due || state.pending || state.next != nil {
			t.Fatalf("sample should become due at the deadline: %+v", state)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestForegroundServicesPageAndStatusCoverSameGroups(t *testing.T) {
	c, mux := setupCollection(t)
	now := time.Now()
	for i := range 33 {
		id := fmt.Sprintf("host-%02d", i)
		seedCollectionTarget(t, c, id, "host")
		if i < 32 {
			seedForegroundAttempt(t, c, id, "systemd", now, now, false)
		}
	}
	seedCollectionTarget(t, c, "cluster", "cluster")
	seedForegroundAttempt(t, c, "cluster", "nodes", now, now, false)
	checkForegroundStatus(t, mux, "view=services", true, now.Add(time.Minute))
	checkForegroundStatus(t, mux, "view=services&source=cluster", true, time.Time{})
	checkForegroundStatus(t, mux, "view=services&source=host&target_id=host-00", false, now.Add(time.Minute))
	path := "/api/v1/collection-requests"
	w := collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"host","due_only":true}`, 200)
	var out struct {
		Next string `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Next != "host-31" || len(c.queued) != 0 {
		t.Fatalf("expected empty fresh page with a next cursor, got %s (%v)", w.Body.String(), err)
	}
	collectionHTTP(t, mux, "POST", path, `{"view":"services","source":"host","cursor":"host-31","due_only":true}`, 202)
	if queued := c.queued["host-32"]; len(c.queued) != 1 || len(queued.groups) != 1 || !queued.manual["systemd"] {
		t.Fatalf("expected only the overdue service page item, got %+v", c.queued)
	}
}
