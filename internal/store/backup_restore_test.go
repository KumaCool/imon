package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupIncludesWALAndRestoreKeepsRollback(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	source := filepath.Join(dir, "state.sqlite3")
	db, err := Open(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.CreateTarget(ctx, Target{ID: "demo", Kind: "host", Name: "Example host", ConnectionRef: "<REF>", ConnectionRev: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(source + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected active WAL: %v", err)
	}
	err = db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_events(id,rule_id,target_id,connection_rev,status,snapshot,latest_value,observed_at,triggered_at) VALUES('event','rule','demo',1,'active','{}','93',1,1)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO deliveries(id,event_id,phase,channel,address,status,due_at,updated_at,config,message) VALUES('delivery','event','trigger','telegram','123','queued',1,1,'{}','example')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(dir, "snapshot.bak")
	if err := BackupFile(ctx, source, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := BackupFile(ctx, source, backupPath); err == nil {
		t.Fatal("overwrote an existing backup")
	}
	if stat, err := os.Stat(backupPath); err != nil || stat.Size() == 0 {
		t.Fatalf("invalid backup: %v", err)
	}
	if _, err := os.Stat(backupPath + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup included a WAL sidecar: %v", err)
	}

	destination := filepath.Join(dir, "restore.sqlite3")
	old, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.CreateTarget(ctx, Target{ID: "other", Kind: "host", Name: "Other host", ConnectionRef: "<REF>", ConnectionRev: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	rollback, err := RestoreFile(ctx, backupPath, destination)
	if err != nil || rollback == "" {
		t.Fatalf("restore rollback=%q err=%v", rollback, err)
	}
	restored, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	assertTarget(t, ctx, restored, "demo")
	err = restored.Read(ctx, func(tx *sql.Tx) error {
		var state, detail string
		if err := tx.QueryRowContext(ctx, `SELECT status,detail FROM deliveries WHERE id='delivery'`).Scan(&state, &detail); err != nil {
			return err
		}
		if state != "unknown" || detail != "restored_backup" {
			t.Fatalf("restored send state %s %s", state, detail)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := RestoreFile(ctx, rollback, destination)
	if err != nil || second == "" {
		t.Fatalf("rollback restore backup=%q err=%v", second, err)
	}
	original, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	assertTarget(t, ctx, original, "other")
}

func assertTarget(t *testing.T, ctx context.Context, s *Store, id string) {
	t.Helper()
	items, _, err := s.ListTargets(ctx, "", 50)
	if err != nil || len(items) != 1 || items[0].ID != id {
		t.Fatalf("result=%v err=%v", items, err)
	}
}

func TestRestoreRejectsWrongInputBeforeReplacement(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	destination := filepath.Join(dir, "restore.sqlite3")
	s, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTarget(ctx, Target{ID: "other", Kind: "host", Name: "Other host", ConnectionRef: "<REF>", ConnectionRev: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "invalid.bak")
	if err := os.WriteFile(source, []byte("Example invalid backup"), 0600); err != nil {
		t.Fatal(err)
	}
	if rollback, err := RestoreFile(ctx, source, destination); err == nil || rollback != "" {
		t.Fatalf("restore accepted wrong input: %s %v", rollback, err)
	}
	if rollback, err := RestoreFile(ctx, destination, destination); err == nil || rollback != "" {
		t.Fatalf("restore accepted itself: %s %v", rollback, err)
	}
	s, err = Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertTarget(t, ctx, s, "other")
}
