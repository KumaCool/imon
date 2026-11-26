package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// BackupFile saves the committed SQLite state, including data still in WAL.
// The destination must not already exist.
func BackupFile(ctx context.Context, sourceDB, destination string) error {
	source, err := filepath.Abs(sourceDB)
	if err != nil {
		return err
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err := backupPathAvailable(dest); err != nil {
		return err
	}
	db, err := openBackupSource(ctx, source)
	if err != nil {
		return err
	}
	defer db.Close()
	temp, err := backup(ctx, db, filepath.Join(filepath.Dir(dest), ".imon-backup"), len(migrations))
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	if err := syncDatabase(temp); err != nil {
		return err
	}
	// The same-directory link publishes a completed file without replacing an
	// existing backup, including a file created after the initial check.
	return os.Link(temp, dest)
}

// RestoreFile replaces a stopped application's state database. The caller
// holds the application directory lock and must close any Store before calling.
// It returns the pre-restore database copy when prior state exists.
func RestoreFile(ctx context.Context, backupPath, destinationDB string) (string, error) {
	source, err := filepath.Abs(backupPath)
	if err != nil {
		return "", err
	}
	dest, err := filepath.Abs(destinationDB)
	if err != nil {
		return "", err
	}
	from, err := os.Stat(source)
	if err != nil {
		return "", err
	}
	to, err := os.Lstat(dest)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if to != nil && (!to.Mode().IsRegular() || os.SameFile(from, to)) {
		return "", errors.New("restore requires a distinct regular destination file")
	}

	db, err := openBackupSource(ctx, source)
	if err != nil {
		return "", err
	}
	temp, copyErr := backup(ctx, db, filepath.Join(filepath.Dir(dest), ".imon-restore"), len(migrations))
	if err := errors.Join(copyErr, db.Close()); err != nil {
		if temp != "" {
			os.Remove(temp)
		}
		return "", err
	}
	defer os.Remove(temp)
	if err := prepareRestoredState(ctx, temp); err != nil {
		return "", err
	}
	if err := syncDatabase(temp); err != nil {
		return "", err
	}

	var rollback string
	if to != nil && to.Size() > 0 {
		rollback, err = prepareOriginalState(ctx, dest)
		if err != nil {
			return rollback, err
		}
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(dest + suffix); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("database still has an active %s sidecar", suffix)
			}
			return rollback, err
		}
	}
	if err := ctx.Err(); err != nil {
		return rollback, err
	}
	return rollback, os.Rename(temp, dest)
}

func backupPathAvailable(path string) error {
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	default:
		return errors.New("backup destination already exists")
	}
}

func openBackupSource(ctx context.Context, path string) (*sql.DB, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, errors.New("backup source must be a nonempty database file")
	}
	db, err := sql.Open("sqlite", dsn(path, "ro", "query_only(1)", "busy_timeout(5000)"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := checkDatabase(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func checkDatabase(ctx context.Context, db *sql.DB) error {
	var version, tables int
	var check string
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version < 1 || version > len(migrations) {
		return fmt.Errorf("unsupported state database schema version %d", version)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema
		WHERE type='table' AND name IN ('targets','snapshot_batches','group_state','snapshot_rows')`).Scan(&tables); err != nil {
		return err
	}
	if tables != 4 {
		return errors.New("the input is missing Imon state tables")
	}
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return errors.New("SQLite state database integrity check failed")
	}
	return nil
}

func prepareRestoredState(ctx context.Context, path string) (err error) {
	db, err := sql.Open("sqlite", dsn(path, "rw"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if err := checkDatabase(ctx, db); err != nil {
		return err
	}
	var hasDeliveries int
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='deliveries')`).Scan(&hasDeliveries); err != nil {
		return err
	}
	if hasDeliveries != 0 {
		// An archived job may have been sent after the backup. Its outcome
		// cannot be verified from the copy and it must not be replayed.
		if _, err := db.ExecContext(ctx, `UPDATE deliveries SET status='unknown', detail='restored_backup'
			WHERE status IN ('queued','sending')`); err != nil {
			return err
		}
	}
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode); err != nil {
		return err
	}
	if mode != "delete" {
		return errors.New("could not create a standalone restored database")
	}
	return nil
}

func prepareOriginalState(ctx context.Context, path string) (rollback string, err error) {
	db, err := sql.Open("sqlite", dsn(path, "rw", "busy_timeout(5000)"))
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return "", err
	}
	rollback, err = backup(ctx, db, path+".pre-restore", version)
	if err != nil {
		return "", err
	}
	if err := syncDatabase(rollback); err != nil {
		return rollback, err
	}
	var mode string
	if err := db.QueryRowContext(ctx, `PRAGMA journal_mode=DELETE`).Scan(&mode); err != nil {
		return rollback, err
	}
	if mode != "delete" {
		return rollback, errors.New("close the database before restoring")
	}
	return rollback, nil
}

func syncDatabase(path string) (err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.Sync()
}
