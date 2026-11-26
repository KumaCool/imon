package alert

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func TestCollectionEventsDeduplicateRecoverAndStop(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	at := time.Now()
	observe := func(rev int64, group, code string, offset time.Duration) {
		t.Helper()
		err := f.db.Write(ctx, func(tx *sql.Tx) error {
			return f.e.ObserveCollection(ctx, tx, "host-demo", rev, group, code, at.Add(offset))
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	observe(1, "interfaces", "timeout", 0)
	observe(1, "interfaces", "<PRIVATE_DIAGNOSTIC>", time.Second)
	observe(1, "firewall", "firewall_not_configured", 2*time.Second)
	events, unread := f.entries(t, "")
	if len(events) != 1 || unread != 1 || events[0].Source != "collection" || events[0].Group != "interfaces" ||
		events[0].ErrorCategory != "collection_failed" || events[0].TriggeredAt != at.UnixMilli() ||
		events[0].ObservedAt != at.Add(time.Second).UnixMilli() || !events[0].SourceAvailable {
		t.Fatalf("unexpected event summary: %+v, unread %d", events, unread)
	}
	raw := f.req(t, "GET", "alert-events/"+events[0].ID, "", 200)
	if strings.Contains(raw.Body.String(), "PRIVATE_DIAGNOSTIC") || len(output[Event](t, raw).Deliveries) != 3 {
		t.Fatal("repeated failure should not repeat delivery or persist raw diagnostics")
	}
	observe(1, "interfaces", "", 3*time.Second)
	events, _ = f.entries(t, "")
	if len(events) != 1 || events[0].Status != "recovered" || events[0].RecoveredAt == nil {
		t.Fatalf("success did not recover existing event: %+v", events)
	}
	observe(1, "interfaces", "timeout", 4*time.Second)
	if err := f.db.Write(ctx, func(tx *sql.Tx) error {
		if err := f.e.StopTarget(ctx, tx, "host-demo", "configuration_changed"); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE targets SET connection_rev=2 WHERE target_id='host-demo'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	observe(1, "interfaces", "timeout", 5*time.Second)
	events, _ = f.entries(t, "")
	if len(events) != 2 || events[0].Status != "configuration_changed" || events[0].RecoveredAt != nil {
		t.Fatalf("old revision should end without becoming recovered: %+v", events)
	}
}
