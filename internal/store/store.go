// Package store owns the local SQLite database and serializes its writes.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("store: object not found")
	ErrStaleTarget    = errors.New("store: target disabled or connection revision changed")
	ErrSnapshotClosed = errors.New("store: snapshot already finalized")
	ErrSnapshotMoved  = errors.New("store: published snapshot changed; restart pagination")
	errStoreClosed    = errors.New("store: closed")
)

type Store struct {
	writer     *sql.DB
	reader     *sql.DB
	writes     chan writeRequest
	stopWriter chan struct{}
	writerDone chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

type writeRequest struct {
	ctx    context.Context
	run    func(*sql.Tx) error
	result chan error
}

// Open expects the caller to hold the exclusive lock for the private data directory.
func Open(ctx context.Context, path string) (*Store, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	existing, err := prepareFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("prepare state database: %w", err)
	}

	writer, err := sql.Open("sqlite", dsn(absolutePath, "rw", "foreign_keys(1)", "busy_timeout(5000)"))
	if err != nil {
		return nil, err
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	if err := migrate(ctx, writer, absolutePath, existing); err != nil {
		writer.Close()
		return nil, err
	}
	var mode string
	if err := writer.QueryRowContext(ctx, `PRAGMA journal_mode = WAL`).Scan(&mode); err != nil {
		writer.Close()
		return nil, fmt.Errorf("enable SQLite WAL: %w", err)
	}
	if mode != "wal" {
		writer.Close()
		return nil, fmt.Errorf("enable SQLite WAL: got %q", mode)
	}
	reader, err := sql.Open("sqlite", dsn(absolutePath, "ro", "query_only(1)", "busy_timeout(5000)"))
	if err != nil {
		writer.Close()
		return nil, err
	}
	reader.SetMaxOpenConns(4)
	reader.SetMaxIdleConns(1)
	s := &Store{
		writer: writer, reader: reader,
		writes: make(chan writeRequest), stopWriter: make(chan struct{}), writerDone: make(chan struct{}),
	}
	go s.runWriter()
	if err := reader.PingContext(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("open SQLite reader: %w", err)
	}
	if err := s.interruptSnapshots(ctx); err != nil {
		s.Close()
		return nil, fmt.Errorf("recover interrupted snapshot batches: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopWriter)
		<-s.writerDone
		s.closeErr = errors.Join(s.reader.Close(), s.writer.Close())
	})
	return s.closeErr
}

// Write runs a short, local transaction on the sole write connection.
// Callbacks must use the supplied transaction, do no network I/O, and not call Write.
func (s *Store) Write(ctx context.Context, run func(*sql.Tx) error) error {
	request := writeRequest{ctx: ctx, run: run, result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopWriter:
		return errStoreClosed
	case s.writes <- request:
		return <-request.result
	}
}

// Read runs a consistent transaction on a query-only connection.
func (s *Store) Read(ctx context.Context, run func(*sql.Tx) error) error {
	return transact(ctx, s.reader, run)
}

func (s *Store) runWriter() {
	defer close(s.writerDone)
	for {
		select {
		case <-s.stopWriter:
			return
		case request := <-s.writes:
			select {
			case <-s.stopWriter:
				request.result <- errStoreClosed
				return
			default:
				request.result <- transact(request.ctx, s.writer, request.run)
			}
		}
	}
}

func transact(ctx context.Context, db *sql.DB, run func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := run(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func prepareFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return false, errors.New("database path is not a regular file")
		}
		return info.Size() > 0, nil
	case errors.Is(err, os.ErrNotExist):
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return false, err
		}
		return false, file.Close()
	default:
		return false, err
	}
}

func dsn(path, mode string, pragmas ...string) string {
	name := filepath.ToSlash(path)
	if len(name) > 1 && name[1] == ':' {
		name = "/" + name
	}
	q := url.Values{"mode": {mode}, "_pragma": pragmas}
	return "file:" + (&url.URL{Path: name, RawQuery: q.Encode()}).String()
}

func migrate(ctx context.Context, db *sql.DB, path string, existing bool) error {
	var from int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&from); err != nil {
		return fmt.Errorf("read SQLite schema version: %w", err)
	}
	if from < 0 || from > len(migrations) {
		return fmt.Errorf("unsupported SQLite schema version %d", from)
	}
	if from == len(migrations) {
		return nil
	}

	var backupPath string
	if existing {
		var err error
		backupPath, err = backup(ctx, db, path, from)
		if err != nil {
			return fmt.Errorf("back up SQLite schema version %d: %w", from, err)
		}
	}
	err := transact(ctx, db, func(tx *sql.Tx) error {
		for i := from; i < len(migrations); i++ {
			if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
				return fmt.Errorf("apply SQLite migration %d: %w", i+1, err)
			}
		}
		_, err := tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
		return err
	})
	if err != nil && backupPath != "" {
		return fmt.Errorf("migration failed; original backup %s: %w", filepath.Base(backupPath), err)
	}
	return err
}

func backup(ctx context.Context, db *sql.DB, path string, version int) (string, error) {
	dest, err := os.CreateTemp(filepath.Dir(path), fmt.Sprintf("%s.pre-migrate-v%d-*.bak", filepath.Base(path), version))
	if err != nil {
		return "", err
	}
	destPath := dest.Name()
	keep := false
	defer func() {
		if !keep {
			os.Remove(destPath)
		}
	}()
	if err := dest.Close(); err != nil {
		return "", err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	err = conn.Raw(func(driverConn any) (err error) {
		source := driverConn.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		copy, err := source.NewBackup(dsn(destPath, "rw", "journal_mode(DELETE)"))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, copy.Finish()) }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := copy.Step(256)
			if err != nil || !more {
				return err
			}
		}
	})
	if err != nil {
		return "", err
	}
	keep = true
	return destPath, nil
}

func pageLimit(n int) int {
	if n <= 0 {
		return 50
	}
	return min(n, 200)
}

type Target struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	ConnectionRef string `json:"-"`
	ConnectionRev int64  `json:"connection_rev"`
	Enabled       bool   `json:"enabled"`
}

func (s *Store) CreateTarget(ctx context.Context, target Target) error {
	if strings.TrimSpace(target.ID) == "" || strings.TrimSpace(target.Name) == "" {
		return errors.New("store: target ID and name are required")
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO targets
			(target_id, kind, name, connection_ref, connection_rev, enabled) VALUES (?, ?, ?, ?, ?, ?)`,
			target.ID, target.Kind, target.Name, target.ConnectionRef, target.ConnectionRev, target.Enabled)
		return err
	})
}

// ListTargets returns enabled bindings in ascending target ID order.
func (s *Store) ListTargets(ctx context.Context, afterID string, limit int) (items []Target, nextID string, err error) {
	limit = pageLimit(limit)
	rows, err := s.reader.QueryContext(ctx, `SELECT target_id, kind, name, connection_rev, enabled
		FROM targets WHERE enabled = 1 AND target_id > ? ORDER BY target_id LIMIT ?`, afterID, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items = make([]Target, 0, limit)
	for rows.Next() {
		if len(items) == limit {
			nextID = items[len(items)-1].ID
			break
		}
		var target Target
		if err := rows.Scan(&target.ID, &target.Kind, &target.Name, &target.ConnectionRev, &target.Enabled); err != nil {
			return nil, "", err
		}
		items = append(items, target)
	}
	return items, nextID, rows.Err()
}
