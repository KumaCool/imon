package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"imon/internal/store"
)

type fixture struct {
	db  *store.Store
	e   *Engine
	mux *http.ServeMux
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := t.Context()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "alerts.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	err = db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO targets(target_id,kind,name,connection_ref,connection_rev,enabled) VALUES('host-demo','host','Example host','<REF>',1,1)`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{db: db, now: time.Now, slots: make(chan struct{}, 2)}
	mux := http.NewServeMux()
	e.Register(mux)
	return fixture{db, e, mux}
}

func (f fixture) req(t *testing.T, method, path, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/api/v1/"+path, strings.NewReader(body))
	out := httptest.NewRecorder()
	f.mux.ServeHTTP(out, req)
	if out.Code != status {
		t.Fatalf("%s %s: got %d want %d: %s", method, path, out.Code, status, out.Body.String())
	}
	return out
}

func output[T any](t *testing.T, res *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (f fixture) diskRule(t *testing.T, trigger, channels string) Rule {
	t.Helper()
	return output[Rule](t, f.req(t, "POST", "alert-rules", `{"name":"Disk threshold","enabled":true,"severity":"warning","selector":{"target_id":"host-demo","metric":"disk_usage_percent","mountpoint":"/"},"condition":{"op":"gt","value":90},"trigger":`+trigger+`,"channels":`+channels+`}`, 201))
}

func (f fixture) entries(t *testing.T, query string) ([]Event, int) {
	t.Helper()
	res := output[struct {
		Items  []Event `json:"items"`
		Unread int     `json:"unread_count"`
	}](t, f.req(t, "GET", "alert-events"+query, "", 200))
	return res.Items, res.Unread
}

func (f fixture) observe(t *testing.T, o Observation) {
	t.Helper()
	err := f.db.Write(t.Context(), func(tx *sql.Tx) error { return f.e.Observe(t.Context(), tx, o) })
	if err != nil {
		t.Fatal(err)
	}
}

func disk(batch string, at time.Time, usage float64) Observation {
	return Observation{
		TargetID: "host-demo", Group: "metrics", BatchID: batch, ObservedAt: at,
		Scheduled: true, PollingEnabled: true, CurrentSettings: true, Complete: true, Period: 60 * time.Second,
		Values: []Value{{Selector: Selector{Metric: "disk_usage_percent", Mountpoint: "/"}, ObjectName: "/", Value: usage}},
	}
}

func TestDiskReplayAndReadReceipts(t *testing.T) {
	f := newFixture(t)
	rule := f.diskRule(t, `{"consecutive_samples":2}`, `{"panel":true}`)
	at := time.Now()
	f.observe(t, disk("b1", at, 92))
	if events, _ := f.entries(t, ""); len(events) != 0 {
		t.Fatal(events)
	}
	b2 := disk("b2", at.Add(time.Minute), 93)
	f.observe(t, b2)
	f.observe(t, b2)
	items, unread := f.entries(t, "?status=active")
	if len(items) != 1 || unread != 1 || items[0].LatestValue != float64(93) || items[0].PanelRevision != 1 {
		t.Fatalf("unexpected trigger: %+v unread=%d", items, unread)
	}
	id := items[0].ID
	stale := disk("b3", at.Add(2*time.Minute), 87)
	stale.Complete = false
	f.observe(t, stale)
	items, _ = f.entries(t, "?status=active")
	if len(items) != 1 || items[0].DetailState != "unknown" || items[0].LatestValue != float64(93) {
		t.Fatalf("failed sample changed event: %+v", items)
	}
	f.observe(t, disk("b4", at.Add(3*time.Minute), 87))
	f.observe(t, b2)
	f.req(t, "POST", "alert-events/"+id+"/read", `{"through_revision":1}`, 200)
	items, unread = f.entries(t, "?status=recovered&unread=true")
	if len(items) != 1 || unread != 1 || items[0].ID != id || items[0].LatestValue != float64(87) || items[0].PanelRevision != 2 {
		t.Fatalf("recovery lost or replayed: %+v unread=%d", items, unread)
	}
	detail := output[Event](t, f.req(t, "GET", "alert-events/"+id, "", 200))
	if detail.RuleID != rule.ID || len(detail.Deliveries) != 6 {
		t.Fatalf("detail=%+v", detail)
	}
	f.req(t, "POST", "alert-events/"+id+"/read", `{"through_revision":3}`, 400)
	f.req(t, "POST", "alert-events/"+id+"/read", `{"through_revision":2}`, 200)
	if items, unread := f.entries(t, "?unread=true"); len(items) != 0 || unread != 0 {
		t.Fatalf("read receipt failed: %+v %d", items, unread)
	}
}

func TestManualSamplingAndDisabledChannels(t *testing.T) {
	f := newFixture(t)
	f.req(t, "PUT", "notification-settings", `{"panel":false,"telegram":false,"email":false}`, 200)
	f.diskRule(t, `{"consecutive_samples":2}`, `{"panel":true}`)
	f.diskRule(t, `{"duration_seconds":30}`, `{"panel":true}`)
	at := time.Now()
	sample := func(batch string, seconds int, poll, scheduled, current bool, usage float64) {
		o := disk(batch, at.Add(time.Duration(seconds)*time.Second), usage)
		o.PollingEnabled, o.Scheduled, o.CurrentSettings = poll, scheduled, current
		f.observe(t, o)
	}
	sample("b1", 0, false, false, true, 92)
	sample("b2", 160, false, false, true, 92)
	sample("b3", 185, false, false, false, 92)
	if events, _ := f.entries(t, ""); len(events) != 0 {
		t.Fatalf("stale manual sample advanced rule: %+v", events)
	}
	sample("b4", 195, false, false, true, 95)
	if events, unread := f.entries(t, ""); len(events) != 1 || unread != 0 || events[0].Trigger.ConsecutiveSamples == nil {
		t.Fatalf("unexpected manual event: %+v unread=%d", events, unread)
	}
	sample("b5", 210, false, false, true, 80)
	if events, _ := f.entries(t, "?status=recovered"); len(events) != 1 {
		t.Fatalf("manual recovery failed: %+v", events)
	}
	sample("b6", 230, true, true, true, 92)
	sample("b7", 300, true, false, true, 98)
	sample("b8", 360, true, true, true, 94)
	if events, _ := f.entries(t, "?status=active"); len(events) != 0 {
		t.Fatalf("manual anomaly bridged interrupted plan: %+v", events)
	}
	sample("b9", 420, true, true, true, 94)
	if events, _ := f.entries(t, "?status=active"); len(events) != 2 {
		t.Fatalf("planned series failed: %+v", events)
	}
}

func TestPortAbsenceAndUnbind(t *testing.T) {
	f := newFixture(t)
	rule := output[Rule](t, f.req(t, "POST", "alert-rules", `{"name":"Listener missing","enabled":true,"severity":"critical","selector":{"target_id":"host-demo","metric":"port_listening","protocol":"tcp","family":"ipv4","address":"*","port":8080},"condition":{"op":"eq","value":false},"trigger":{"consecutive_samples":1},"channels":{}}`, 201))
	o := Observation{TargetID: "host-demo", Group: "listeners", BatchID: "p1", ObservedAt: time.Now(), Complete: true, CurrentSettings: true}
	o.CompleteListenerKinds = []string{"tcp/ipv6"}
	f.observe(t, o)
	if events, _ := f.entries(t, ""); len(events) != 0 {
		t.Fatal(events)
	}
	o.BatchID = "p2"
	o.ObservedAt = o.ObservedAt.Add(time.Minute)
	o.CompleteListenerKinds = []string{"tcp/ipv4"}
	f.observe(t, o)
	events, _ := f.entries(t, "")
	if len(events) != 1 || events[0].LatestValue != false || events[0].Selector.Address != "0.0.0.0" {
		t.Fatalf("port absent: %+v", events)
	}
	ctx := t.Context()
	err := f.db.Write(ctx, func(tx *sql.Tx) error {
		if err := f.e.StopTarget(ctx, tx, o.TargetID, "monitoring_stopped"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE targets SET enabled=0,connection_rev=2 WHERE target_id=?`, o.TargetID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	event := output[Event](t, f.req(t, "GET", "alert-events/"+events[0].ID, "", 200))
	if event.Status != "monitoring_stopped" || event.SourceAvailable || event.RecoveredAt != nil || len(event.Deliveries) != 3 {
		t.Fatalf("event after unbind: %+v", event)
	}
	rules := output[struct {
		Items []Rule `json:"items"`
	}](t, f.req(t, "GET", "alert-rules", "", 200))
	if len(rules.Items) != 1 || rules.Items[0].Enabled || rules.Items[0].Revision != rule.Revision+1 {
		t.Fatalf("rules after unbind: %+v", rules)
	}
}

func TestProbeBackoffAndRestart(t *testing.T) {
	f := newFixture(t)
	f.req(t, "POST", "alert-rules", `{"name":"Probe failure","enabled":true,"severity":"warning","selector":{"target_id":"host-demo","metric":"target_reachable"},"condition":{"op":"eq","value":false},"trigger":{"consecutive_samples":2},"channels":{}}`, 201)
	o := Observation{
		TargetID: "host-demo", Group: "probe", BatchID: "p1", ObservedAt: time.Now(), Period: time.Minute,
		Complete: true, CurrentSettings: true, PollingEnabled: true, Scheduled: true,
		Values: []Value{{Selector: Selector{Metric: "target_reachable"}, Value: false}},
	}
	f.observe(t, o)
	ctx := t.Context()
	e, err := New(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	o.BatchID = "p2"
	o.ObservedAt = o.ObservedAt.Add(4 * time.Minute)
	f.observe(t, o)
	if events, _ := f.entries(t, ""); len(events) != 0 {
		t.Fatal(events)
	}
	o.BatchID = "p3"
	o.ObservedAt = o.ObservedAt.Add(8 * time.Minute)
	f.observe(t, o)
	if events, _ := f.entries(t, "?status=active"); len(events) != 1 {
		t.Fatal(events)
	}
}

func TestDeliveryOrderingAndConfigurationSnapshot(t *testing.T) {
	f := newFixture(t)
	f.req(t, "PUT", "notification-settings", `{"panel":false,"telegram":true,"email":false}`, 200)
	ref := filepath.Join(t.TempDir(), "telegram-token")
	target := output[notificationTarget](t, f.req(t, "POST", "notification-targets", `{"name":"Test channel","channel":"telegram","chat_id":"-123","credential_ref":`+mustMarshal(t, ref)+`}`, 201))
	f.req(t, "POST", "alert-rules", `{"name":"Disk threshold","enabled":true,"severity":"warning","selector":{"target_id":"host-demo","metric":"disk_usage_percent","mountpoint":"/"},"condition":{"op":"gt","value":90},"trigger":{"consecutive_samples":1},"channels":{"telegram":true},"notification_target_ids":{"telegram":[`+mustMarshal(t, target.ID)+`]}}`, 201)
	now := time.Now()
	f.e.now = func() time.Time { return now }
	f.observe(t, disk("b1", now, 92))
	f.req(t, "PATCH", "notification-targets/"+target.ID, `{"proxy_url":"http://192.0.2.9:8888"}`, 200)
	f.observe(t, disk("b2", now.Add(time.Second), 89))
	ctx := t.Context()
	job, err := f.e.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if job.config.ProxyURL != "" || job.address != "-123" || !strings.Contains(job.message, "trigger") {
		t.Fatalf("queue changed snapshot: %+v", job)
	}
	now = now.Add(time.Second)
	if _, err := f.e.claim(ctx); err != sql.ErrNoRows {
		t.Fatalf("recovery ran before trigger: %v", err)
	}
	result := temporary("test_limit", 50*time.Second)
	if err := f.db.Write(ctx, func(tx *sql.Tx) error { return finishDelivery(ctx, tx, job, result, now) }); err != nil {
		t.Fatal(err)
	}
	now = now.Add(49 * time.Second)
	if _, err := f.e.claim(ctx); err != sql.ErrNoRows {
		t.Fatalf("retry too early: %v", err)
	}
	now = now.Add(time.Second)
	retry, err := f.e.claim(ctx)
	if err != nil || retry.id != job.id || retry.attempt != 2 {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}
	if err := f.db.Write(ctx, func(tx *sql.Tx) error { return finishDelivery(ctx, tx, retry, unknown("reply_lost"), now) }); err != nil {
		t.Fatal(err)
	}
	recovery, err := f.e.claim(ctx)
	if err != nil || recovery.config.ProxyURL == "" || !strings.Contains(recovery.message, "recovery") {
		t.Fatalf("recovery=%+v err=%v", recovery, err)
	}
	e, err := New(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if _, err := f.e.claim(ctx); err != sql.ErrNoRows {
		t.Fatalf("ambiguous send replayed: %v", err)
	}
	items, _ := f.entries(t, "")
	detail := output[Event](t, f.req(t, "GET", "alert-events/"+items[0].ID, "", 200))
	count := 0
	for _, delivery := range detail.Deliveries {
		if delivery.Channel == "telegram" && delivery.Status == "unknown" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("unknown results missing: %+v", detail.Deliveries)
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	out, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTestNotificationHasNoEvent(t *testing.T) {
	f := newFixture(t)
	f.e.send = func(_ context.Context, target notificationTarget, address, message string) sendResult {
		if target.Channel != "telegram" || address != "111" || !strings.Contains(message, "test") {
			t.Errorf("unexpected test request")
		}
		return accepted()
	}
	ref := filepath.Join(t.TempDir(), "telegram-token")
	target := output[notificationTarget](t, f.req(t, "POST", "notification-targets", `{"name":"Test channel","channel":"telegram","chat_id":"111","credential_ref":`+mustMarshal(t, ref)+`}`, 201))
	res := output[map[string]any](t, f.req(t, "POST", "notification-targets/"+target.ID+"/test", "", 200))
	if res["result"] != "accepted" {
		t.Fatal(res)
	}
	if items, count := f.entries(t, ""); len(items) != 0 || count != 0 {
		t.Fatalf("test notification changed user events: %+v %d", items, count)
	}
}
