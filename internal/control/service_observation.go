package control

import (
	"context"
	"database/sql"
	"errors"

	"imon/internal/store"
)

type serviceObservation struct {
	Group      string `json:"group"`
	ObservedAt *int64 `json:"observed_at"`
	Stale      bool   `json:"stale"`
	HasItems   *bool  `json:"has_items"`
	ErrorCode  string `json:"error_code,omitempty"`
}

func addServiceObservation(ctx context.Context, tx *sql.Tx, t store.Target, settings Settings, summary map[string]any) error {
	value := serviceObservation{Group: "systemd"}
	if t.Kind == "cluster" {
		value.Group = "deployments"
	}
	var status string
	err := tx.QueryRowContext(ctx, `SELECT p.observed_at,a.status,a.error_code,
		CASE WHEN p.batch_id IS NOT NULL THEN EXISTS (
			SELECT 1 FROM snapshot_rows r WHERE (r.target_id,r.connection_rev,r.group_name,r.batch_id)=(p.target_id,p.connection_rev,p.group_name,p.batch_id)
		) END
		FROM group_state g
		JOIN snapshot_batches a ON (a.target_id,a.connection_rev,a.group_name,a.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id)
		LEFT JOIN snapshot_batches p ON (p.target_id,p.connection_rev,p.group_name,p.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
		WHERE g.target_id=? AND g.connection_rev=? AND g.group_name=?`, t.ID, t.ConnectionRev, value.Group).
		Scan(&value.ObservedAt, &status, &value.ErrorCode, &value.HasItems)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	value.Stale = observationStale(value.ObservedAt, status, settings, t.Kind, value.Group)
	summary["service_observation"] = value
	return nil
}
