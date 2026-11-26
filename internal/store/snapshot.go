package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type SnapshotKey struct {
	TargetID      string
	ConnectionRev int64
	Group         string
	BatchID       string
}

func (k SnapshotKey) args(extra ...any) []any {
	return append([]any{k.TargetID, k.ConnectionRev, k.Group, k.BatchID}, extra...)
}

type SnapshotRow struct {
	ObjectKey string          `json:"object_key"`
	Payload   json.RawMessage `json:"payload"`
}

type SnapshotAttempt struct {
	BatchID     string `json:"batch_id"`
	Status      string `json:"status"`
	StartedAt   int64  `json:"started_at"`
	CompletedAt *int64 `json:"completed_at"`
	ErrorCode   string `json:"error_code,omitempty"`
	Source      string `json:"source"`
}

type SnapshotCursor struct {
	ConnectionRev int64  `json:"connection_rev"`
	BatchID       string `json:"batch_id"`
	AfterObject   string `json:"after_object"`
	Namespace     string `json:"namespace,omitempty"`
}

type SnapshotPage struct {
	ConnectionRev int64            `json:"connection_rev"`
	Attempt       *SnapshotAttempt `json:"attempt"`
	BatchID       string           `json:"batch_id,omitempty"`
	ObservedAt    *int64           `json:"observed_at"`
	Rows          []SnapshotRow    `json:"items"`
	Next          *SnapshotCursor  `json:"next_cursor"`
}

// StartSnapshot stages a previously unseen batch. There is at most one in-flight batch per group and connection revision.
func (s *Store) StartSnapshot(ctx context.Context, key SnapshotKey, startedAt int64) error {
	if key.Group == "" || key.BatchID == "" {
		return errors.New("store: snapshot group and batch ID are required")
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		if err := checkTarget(ctx, tx, key); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO snapshot_batches
			(target_id, connection_rev, group_name, batch_id, started_at, status)
			VALUES (?, ?, ?, ?, ?, 'staging')
			ON CONFLICT (target_id, connection_rev, group_name, batch_id) DO NOTHING`, key.args(startedAt)...)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err != nil || n == 0 {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO group_state
			(target_id, connection_rev, group_name, attempt_batch_id) VALUES (?, ?, ?, ?)
			ON CONFLICT (target_id, connection_rev, group_name) DO UPDATE
			SET attempt_batch_id = excluded.attempt_batch_id`, key.args()...)
		return err
	})
}

// StageSnapshotRows writes a single page without changing the published generation.
func (s *Store) StageSnapshotRows(ctx context.Context, key SnapshotKey, page []SnapshotRow) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		status, err := snapshotStatus(ctx, tx, key)
		if err != nil {
			return err
		}
		if status != "staging" {
			return ErrSnapshotClosed
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO snapshot_rows
			(target_id, connection_rev, group_name, batch_id, object_key, payload) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (target_id, connection_rev, group_name, batch_id, object_key) DO UPDATE
			SET payload = excluded.payload WHERE snapshot_rows.payload = excluded.payload`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, row := range page {
			if row.ObjectKey == "" {
				return errors.New("store: snapshot object key is required")
			}
			result, err := stmt.ExecContext(ctx, key.args(row.ObjectKey, string(row.Payload))...)
			if err != nil {
				return err
			}
			if n, err := result.RowsAffected(); err != nil {
				return err
			} else if n == 0 {
				return errors.New("store: conflicting contents for duplicate snapshot object")
			}
		}
		return nil
	})
}

// PublishSnapshot commits a successful generation only after the caller receives all pages.
// The optional local callback commits related samples or alerts in that same transaction.
func (s *Store) PublishSnapshot(ctx context.Context, key SnapshotKey, completedAt, observedAt int64, apply func(*sql.Tx) error) error {
	return s.finishSnapshot(ctx, key, "ok", completedAt, &observedAt, "", apply)
}

func (s *Store) FailSnapshot(ctx context.Context, key SnapshotKey, completedAt int64, errorCode string) error {
	return s.FailSnapshotWith(ctx, key, completedAt, errorCode, nil)
}

// FailSnapshotWith records an unavailable observation in the same transaction.
func (s *Store) FailSnapshotWith(ctx context.Context, key SnapshotKey, completedAt int64, errorCode string, apply func(*sql.Tx) error) error {
	if errorCode == "" {
		return errors.New("store: snapshot failure code is required")
	}
	return s.finishSnapshot(ctx, key, "failed", completedAt, nil, errorCode, apply)
}

func (s *Store) finishSnapshot(ctx context.Context, key SnapshotKey, finalStatus string, completedAt int64, observedAt *int64, errorCode string, apply func(*sql.Tx) error) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		status, err := snapshotStatus(ctx, tx, key)
		if err != nil {
			return err
		}
		if status == finalStatus {
			return nil
		}
		if status != "staging" {
			return ErrSnapshotClosed
		}
		if _, err := tx.ExecContext(ctx, `UPDATE snapshot_batches
			SET status = ?5, completed_at = ?6, observed_at = ?7, error_code = ?8
			WHERE target_id = ?1 AND connection_rev = ?2 AND group_name = ?3 AND batch_id = ?4`,
			key.args(finalStatus, completedAt, observedAt, errorCode)...); err != nil {
			return err
		}
		discardBatch := sql.NullString{String: key.BatchID, Valid: true}
		if finalStatus == "ok" {
			// Keep the published rows until a complete replacement commits.
			if err := tx.QueryRowContext(ctx, `SELECT published_batch_id FROM group_state
				WHERE target_id = ?1 AND connection_rev = ?2 AND group_name = ?3 AND attempt_batch_id = ?4`,
				key.args()...).Scan(&discardBatch); err != nil {
				return err
			}
			result, err := tx.ExecContext(ctx, `UPDATE group_state SET published_batch_id = ?4
				WHERE target_id = ?1 AND connection_rev = ?2 AND group_name = ?3 AND attempt_batch_id = ?4`, key.args()...)
			if err != nil {
				return err
			}
			if n, err := result.RowsAffected(); err != nil {
				return err
			} else if n != 1 {
				return ErrSnapshotClosed
			}
		}
		if discardBatch.Valid {
			discard := key
			discard.BatchID = discardBatch.String
			if _, err := tx.ExecContext(ctx, `DELETE FROM snapshot_rows
				WHERE target_id = ? AND connection_rev = ? AND group_name = ? AND batch_id = ?`, discard.args()...); err != nil {
				return err
			}
		}
		if apply != nil {
			return apply(tx)
		}
		return nil
	})
}

func checkTarget(ctx context.Context, tx *sql.Tx, key SnapshotKey) error {
	var rev int64
	var enabled bool
	err := tx.QueryRowContext(ctx, `SELECT connection_rev, enabled FROM targets WHERE target_id = ?`, key.TargetID).
		Scan(&rev, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err == nil && (!enabled || rev != key.ConnectionRev) {
		return ErrStaleTarget
	}
	return err
}

func snapshotStatus(ctx context.Context, tx *sql.Tx, key SnapshotKey) (string, error) {
	if err := checkTarget(ctx, tx, key); err != nil {
		return "", err
	}
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM snapshot_batches
		WHERE target_id = ? AND connection_rev = ? AND group_name = ? AND batch_id = ?`, key.args()...).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return status, err
}

func (s *Store) interruptSnapshots(ctx context.Context) error {
	return s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE snapshot_batches
			SET status = 'interrupted', completed_at = ?, error_code = 'process_restarted' WHERE status = 'staging'`,
			time.Now().UnixMilli())
		return err
	})
}

// ReadSnapshot reads attempt metadata and the last successful generation consistently.
// A nil cursor starts a new listing; if a newer generation appears, an old cursor is rejected.
func (s *Store) ReadSnapshot(ctx context.Context, targetID, group string, cursor *SnapshotCursor, limit int) (SnapshotPage, error) {
	var page SnapshotPage
	err := s.Read(ctx, func(tx *sql.Tx) error {
		var err error
		page, err = ReadSnapshotTx(ctx, tx, targetID, group, "", cursor, limit)
		return err
	})
	return page, err
}

// ReadSnapshotTx reads a page and its metadata in the caller's read transaction.
// An optional namespace is applied before pagination.
func ReadSnapshotTx(ctx context.Context, tx *sql.Tx, targetID, group, namespace string, cursor *SnapshotCursor, limit int) (SnapshotPage, error) {
	limit = pageLimit(limit)
	page := SnapshotPage{Rows: make([]SnapshotRow, 0, limit)}
	err := func() error {
		var attempt SnapshotAttempt
		var batchID, attemptID, status, errorCode, source sql.NullString
		var startedAt sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT t.connection_rev, a.batch_id, a.status, a.started_at,
			a.completed_at, a.error_code, a.source, p.batch_id, p.observed_at
			FROM targets t
			LEFT JOIN group_state g ON (g.target_id, g.connection_rev, g.group_name) = (t.target_id, t.connection_rev, ?)
			LEFT JOIN snapshot_batches a ON (a.target_id, a.connection_rev, a.group_name, a.batch_id) =
				(g.target_id, g.connection_rev, g.group_name, g.attempt_batch_id)
			LEFT JOIN snapshot_batches p ON (p.target_id, p.connection_rev, p.group_name, p.batch_id) =
				(g.target_id, g.connection_rev, g.group_name, g.published_batch_id)
			WHERE t.target_id = ? AND t.enabled = 1`, group, targetID).
			Scan(&page.ConnectionRev, &attemptID, &status, &startedAt, &attempt.CompletedAt, &errorCode, &source, &batchID, &page.ObservedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if attemptID.Valid {
			attempt.BatchID, attempt.Status, attempt.StartedAt, attempt.ErrorCode = attemptID.String, status.String, startedAt.Int64, errorCode.String
			attempt.Source = source.String
			page.Attempt = &attempt
		}
		page.BatchID = batchID.String
		var after string
		if cursor != nil {
			if cursor.ConnectionRev != page.ConnectionRev || cursor.BatchID != page.BatchID || cursor.Namespace != namespace {
				return ErrSnapshotMoved
			}
			after = cursor.AfterObject
		}
		if !batchID.Valid {
			return nil
		}
		query := `SELECT object_key, payload FROM snapshot_rows
			WHERE target_id = ? AND connection_rev = ? AND group_name = ? AND batch_id = ? AND object_key > ?`
		args := []any{targetID, page.ConnectionRev, group, page.BatchID, after}
		if namespace != "" {
			query += ` AND json_extract(payload,'$.namespace') = ?`
			args = append(args, namespace)
		}
		rows, err := tx.QueryContext(ctx, query+` ORDER BY object_key LIMIT ?`, append(args, limit+1)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if len(page.Rows) == limit {
				page.Next = &SnapshotCursor{
					ConnectionRev: page.ConnectionRev, BatchID: page.BatchID, AfterObject: page.Rows[len(page.Rows)-1].ObjectKey,
					Namespace: namespace,
				}
				break
			}
			var row SnapshotRow
			var payload []byte
			if err := rows.Scan(&row.ObjectKey, &payload); err != nil {
				return err
			}
			row.Payload = payload
			page.Rows = append(page.Rows, row)
		}
		return rows.Err()
	}()
	if err != nil {
		return SnapshotPage{}, err
	}
	return page, nil
}

// PruneSnapshotRows deletes one small batch of obsolete rows, retaining metadata
// to make retries of finalized batches idempotent.
func (s *Store) PruneSnapshotRows(ctx context.Context, limit int) (removed int64, err error) {
	err = s.Write(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM snapshot_rows WHERE rowid IN (
			SELECT r.rowid FROM snapshot_rows r
			JOIN snapshot_batches b USING (target_id, connection_rev, group_name, batch_id)
			JOIN targets t USING (target_id)
			LEFT JOIN group_state g ON (g.target_id, g.connection_rev, g.group_name) = (r.target_id, r.connection_rev, r.group_name)
			WHERE t.enabled = 0 OR t.connection_rev != r.connection_rev OR
				(b.status != 'staging' AND r.batch_id IS NOT g.published_batch_id)
			LIMIT ?)`, pageLimit(limit))
		if err == nil {
			removed, err = result.RowsAffected()
		}
		return err
	})
	return removed, err
}
