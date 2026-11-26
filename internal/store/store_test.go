package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state #%.sqlite")
	s, err := Open(t.Context(), path)
	must(t, err)
	t.Cleanup(func() { s.Close() })
	return s, path
}

func target(id string) Target {
	return Target{ID: id, Kind: "host", Name: "Host " + id, ConnectionRef: "<CONNECTION_REF>", ConnectionRev: 1, Enabled: true}
}

func TestTargetsPersistAndPaginate(t *testing.T) {
	s, path := openTestStore(t)
	ctx := t.Context()
	for _, id := range []string{"h-second", "h-first"} {
		must(t, s.CreateTarget(ctx, target(id)))
	}
	disabled := target("h-disabled")
	disabled.Enabled = false
	must(t, s.CreateTarget(ctx, disabled))
	must(t, s.Close())
	s, err := Open(ctx, path)
	must(t, err)
	defer s.Close()
	items, next, err := s.ListTargets(ctx, "", 1)
	must(t, err)
	if len(items) != 1 || items[0].ID != "h-first" || next != "h-first" {
		t.Fatalf("unexpected first page: %+v, %q", items, next)
	}
	items, next, err = s.ListTargets(ctx, next, 1)
	must(t, err)
	want := target("h-second")
	want.ConnectionRef = ""
	if len(items) != 1 || items[0] != want || next != "" {
		t.Fatalf("unexpected second page: %+v, %q", items, next)
	}
	encoded, err := json.Marshal(target("h-demo"))
	must(t, err)
	if strings.Contains(string(encoded), "CONNECTION_REF") || strings.Contains(string(encoded), `"connection_ref"`) {
		t.Fatal("encoded target exposed internal connection reference")
	}
	var mode string
	must(t, s.reader.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode))
	if mode != "wal" {
		t.Fatalf("journal mode = %q", mode)
	}
	if _, err := s.reader.ExecContext(ctx, `DELETE FROM targets`); err == nil {
		t.Fatal("reader allowed a write")
	}
}

func TestFirewallAuthorizationObservationAcceptsNativeStatus(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := t.Context()
	must(t, s.CreateTarget(ctx, target("native-host")))
	must(t, s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO firewall_authorization_observations
			(target_id,connection_rev,status,version,architecture,markers_absent,app_version,observed_at)
			VALUES (?,?,?,?,?,?,?,?)`, "native-host", 1, "native", "", "amd64", 0, "v0.1.0", 1)
		return err
	}))
	var status string
	must(t, s.Read(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT status FROM firewall_authorization_observations WHERE target_id=?`, "native-host").Scan(&status)
	}))
	if status != "native" {
		t.Fatalf("status = %q, want native", status)
	}
}

func stage(t *testing.T, s *Store, key SnapshotKey, objectKeys ...string) {
	t.Helper()
	must(t, s.StartSnapshot(t.Context(), key, 100))
	for _, objectKey := range objectKeys {
		must(t, s.StageSnapshotRows(t.Context(), key, []SnapshotRow{{objectKey, json.RawMessage(`{"state":"running"}`)}}))
	}
}

func TestSnapshotPublishesWholeGeneration(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := t.Context()
	must(t, s.CreateTarget(ctx, target("h-demo")))
	key := SnapshotKey{"h-demo", 1, "host_services", "batch-a"}
	read := func(cursor *SnapshotCursor) SnapshotPage {
		page, err := s.ReadSnapshot(ctx, key.TargetID, key.Group, cursor, 1)
		must(t, err)
		return page
	}
	assertRowCount := func(want int) {
		t.Helper()
		var count int
		must(t, s.reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM snapshot_rows WHERE target_id = ? AND group_name = ?`, key.TargetID, key.Group).Scan(&count))
		if count != want {
			t.Fatalf("snapshot row count = %d; want %d", count, want)
		}
	}
	if page := read(nil); page.BatchID != "" || len(page.Rows) != 0 || page.Attempt != nil {
		t.Fatalf("new group: %+v", page)
	}
	stage(t, s, key, "demo-b.service", "demo-a.service")
	if page := read(nil); page.BatchID != "" || len(page.Rows) != 0 || page.Attempt.Status != "staging" {
		t.Fatalf("staged rows visible: %+v", page)
	}
	stop := errors.New("synthetic side-effect transaction failure")
	err := s.PublishSnapshot(ctx, key, 110, 105, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE targets SET name = 'uncommitted'`)
		if err != nil {
			return err
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("publish rollback error = %v", err)
	}
	if page := read(nil); page.BatchID != "" || len(page.Rows) != 0 || page.Attempt.Status != "staging" {
		t.Fatalf("failed transaction changed publication: %+v", page)
	}
	targets, _, err := s.ListTargets(ctx, "", 0)
	must(t, err)
	if targets[0].Name != target(key.TargetID).Name {
		t.Fatal("failed transaction committed a related write")
	}
	calls := 0
	apply := func(*sql.Tx) error { calls++; return nil }
	must(t, s.PublishSnapshot(ctx, key, 110, 105, apply))
	must(t, s.PublishSnapshot(ctx, key, 110, 105, apply))
	if calls != 1 {
		t.Fatalf("duplicate publish ran callback %d times", calls)
	}
	first := read(nil)
	if first.BatchID != key.BatchID || first.Attempt.Status != "ok" || first.ObservedAt == nil || *first.ObservedAt != 105 ||
		len(first.Rows) != 1 || first.Rows[0].ObjectKey != "demo-a.service" || first.Next == nil {
		t.Fatalf("invalid first published page: %+v", first)
	}
	second := read(first.Next)
	if len(second.Rows) != 1 || second.Rows[0].ObjectKey != "demo-b.service" || second.Next != nil {
		t.Fatalf("invalid second published page: %+v", second)
	}
	key.BatchID = "batch-failed"
	stage(t, s, key, "partial.service")
	assertRowCount(3)
	if err := s.FailSnapshotWith(ctx, key, 120, "synthetic_failure", func(*sql.Tx) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("failure rollback error = %v", err)
	}
	assertRowCount(3)
	must(t, s.FailSnapshot(ctx, key, 120, "synthetic_failure"))
	assertRowCount(2)
	failed := read(nil)
	if failed.BatchID != first.BatchID || failed.Attempt.Status != "failed" || failed.Attempt.ErrorCode != "synthetic_failure" ||
		len(failed.Rows) != 1 || failed.Rows[0].ObjectKey != "demo-a.service" {
		t.Fatalf("failure did not retain published data: %+v", failed)
	}
	key.BatchID = "batch-empty"
	stage(t, s, key)
	if err := s.PublishSnapshot(ctx, key, 125, 123, func(*sql.Tx) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("replacement rollback error = %v", err)
	}
	assertRowCount(2)
	if page := read(first.Next); page.BatchID != first.BatchID || len(page.Rows) != 1 {
		t.Fatalf("failed replacement changed published data: %+v", page)
	}
	must(t, s.PublishSnapshot(ctx, key, 125, 123, nil))
	assertRowCount(0)
	empty := read(nil)
	if empty.BatchID != key.BatchID || empty.Attempt.Status != "ok" || len(empty.Rows) != 0 {
		t.Fatalf("complete empty result: %+v", empty)
	}
	if _, err := s.ReadSnapshot(ctx, key.TargetID, key.Group, first.Next, 1); !errors.Is(err, ErrSnapshotMoved) {
		t.Fatalf("outdated cursor error = %v", err)
	}
}

func TestSnapshotRestartAndStaleRevision(t *testing.T) {
	s, path := openTestStore(t)
	ctx := t.Context()
	must(t, s.CreateTarget(ctx, target("h-demo")))
	key := SnapshotKey{"h-demo", 1, "host_services", "batch-published"}
	stage(t, s, key, "demo.service")
	must(t, s.PublishSnapshot(ctx, key, 110, 105, nil))
	key.BatchID = "batch-interrupted"
	stage(t, s, key, "partial.service")
	must(t, s.Close())
	s, err := Open(ctx, path)
	must(t, err)
	defer s.Close()
	page, err := s.ReadSnapshot(ctx, key.TargetID, key.Group, nil, 0)
	must(t, err)
	if page.BatchID != "batch-published" || page.Attempt.Status != "interrupted" || len(page.Rows) != 1 || page.Rows[0].ObjectKey != "demo.service" {
		t.Fatalf("unexpected restarted snapshot: %+v", page)
	}
	if err := s.PublishSnapshot(ctx, key, 110, 105, nil); !errors.Is(err, ErrSnapshotClosed) {
		t.Fatalf("interrupted snapshot publish error = %v", err)
	}
	removed, err := s.PruneSnapshotRows(ctx, 0)
	must(t, err)
	if removed != 1 {
		t.Fatalf("interrupted snapshot cleanup removed %d rows; want 1", removed)
	}
	key.BatchID = "batch-stale"
	stage(t, s, key, "partial.service")
	must(t, s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE targets SET connection_rev = 2 WHERE target_id = ?`, key.TargetID)
		return err
	}))
	if err := s.PublishSnapshot(ctx, key, 110, 105, nil); !errors.Is(err, ErrStaleTarget) {
		t.Fatalf("stale snapshot publish error = %v", err)
	}
	page, err = s.ReadSnapshot(ctx, key.TargetID, key.Group, nil, 0)
	must(t, err)
	if page.ConnectionRev != 2 || page.BatchID != "" || len(page.Rows) != 0 {
		t.Fatalf("old revision leaked into current snapshot: %+v", page)
	}
}

func TestMigrationFailurePreservesOriginalAndBackup(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.sqlite")
	legacy, err := sql.Open("sqlite", dsn(path, "rwc", "wal_autocheckpoint(0)"))
	must(t, err)
	defer legacy.Close()
	_, err = legacy.ExecContext(ctx, `PRAGMA journal_mode = WAL;
		CREATE TABLE legacy_user_data (value TEXT);
		INSERT INTO legacy_user_data VALUES ('synthetic original row');
		CREATE TABLE snapshot_rows (conflict TEXT);`)
	must(t, err)
	opened, err := Open(ctx, path)
	if opened != nil {
		opened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "apply SQLite migration 1") {
		t.Fatalf("wanted migration failure, got %v", err)
	}
	check := func(db *sql.DB) {
		t.Helper()
		var version, addedTables int
		var value string
		must(t, db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version))
		must(t, db.QueryRowContext(ctx, `SELECT value FROM legacy_user_data`).Scan(&value))
		must(t, db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema
			WHERE name IN ('targets', 'group_state', 'snapshot_batches')`).Scan(&addedTables))
		if version != 0 || value != "synthetic original row" || addedTables != 0 {
			t.Fatalf("original schema/data changed: version=%d, value=%q, added=%d", version, value, addedTables)
		}
	}
	check(legacy)
	backups, err := filepath.Glob(filepath.Join(dir, "*.bak"))
	must(t, err)
	if len(backups) != 1 {
		t.Fatalf("found %d migration backups; want 1", len(backups))
	}
	copy, err := sql.Open("sqlite", dsn(backups[0], "ro"))
	must(t, err)
	defer copy.Close()
	check(copy)
}

func TestRejectFutureSchema(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := sql.Open("sqlite", dsn(path, "rwc"))
	must(t, err)
	defer db.Close()
	_, err = db.ExecContext(ctx, `PRAGMA user_version = 1000`)
	must(t, err)
	opened, err := Open(ctx, path)
	if opened != nil {
		opened.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "unsupported SQLite schema version 1000") {
		t.Fatalf("wanted future schema rejection, got %v", err)
	}
}

func TestWriterTransactionCancellation(t *testing.T) {
	s, _ := openTestStore(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- s.Write(t.Context(), func(*sql.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := s.CreateTarget(ctx, target("not-written"))
	close(release)
	must(t, <-finished)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("queued writer error = %v", err)
	}
	targets, _, err := s.ListTargets(t.Context(), "", 0)
	must(t, err)
	if len(targets) != 0 {
		t.Fatal("canceled writer performed the write")
	}
}
