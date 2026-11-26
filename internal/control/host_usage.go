package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/bits"
	"strings"

	"imon/internal/store"
)

type resourceUsage struct {
	Used    uint64  `json:"used_bytes"`
	Total   uint64  `json:"total_bytes"`
	Percent float64 `json:"percent"`
}

type processorUsage struct {
	Used    float64 `json:"used_cores"`
	Total   int     `json:"total_cores"`
	Percent float64 `json:"percent"`
}

type hostUsage struct {
	ObservedAt *int64          `json:"observed_at"`
	CPU        *processorUsage `json:"cpu"`
	Memory     *resourceUsage  `json:"memory"`
	Disk       *resourceUsage  `json:"disk"`
}

func addHostUsage(ctx context.Context, tx *sql.Tx, t store.Target, settings Settings, summary map[string]any) error {
	var usage hostUsage
	summary["os_info"] = nil
	var display string
	var observed int64
	var attempt string
	err := tx.QueryRowContext(ctx, `SELECT json_extract(r.payload,'$.display_name'),p.observed_at,a.status
		FROM group_state g
		JOIN snapshot_batches p ON (p.target_id,p.connection_rev,p.group_name,p.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
		JOIN snapshot_batches a ON (a.target_id,a.connection_rev,a.group_name,a.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id)
		JOIN snapshot_rows r ON (r.target_id,r.connection_rev,r.group_name,r.batch_id,r.object_key)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id,'os')
		WHERE g.target_id=? AND g.connection_rev=? AND g.group_name='os_info'`, t.ID, t.ConnectionRev).Scan(&display, &observed, &attempt)
	if err == nil {
		summary["os_info"] = map[string]any{"display_name": display, "observed_at": observed, "stale": observationStale(&observed, attempt, settings, t.Kind, "os_info")}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var batch string
	err = tx.QueryRowContext(ctx, `SELECT b.observed_at,b.batch_id FROM group_state g JOIN snapshot_batches b
		ON (b.target_id,b.connection_rev,b.group_name,b.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
		WHERE g.target_id=? AND g.connection_rev=? AND g.group_name='host_metrics'`, t.ID, t.ConnectionRev).Scan(&usage.ObservedAt, &batch)
	if errors.Is(err, sql.ErrNoRows) {
		summary["host_usage"] = usage
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT object_key,payload FROM snapshot_rows WHERE target_id=? AND connection_rev=?
		AND group_name='host_metrics' AND batch_id=? AND (object_key IN ('cpu','memory') OR object_key GLOB 'disk:*') ORDER BY object_key`, t.ID, t.ConnectionRev, batch)
	if err != nil {
		return err
	}
	defer rows.Close()
	var diskUsed, diskTotal uint64
	var diskOverflow bool
	sharedFilesystems := make(map[string]bool)
	for rows.Next() {
		var key, payload string
		if err := rows.Scan(&key, &payload); err != nil {
			return err
		}
		if key == "cpu" {
			var f struct {
				Used  *float64 `json:"used_cores"`
				Total int      `json:"total_cores"`
				Ratio *float64 `json:"cpu_percent"`
			}
			if json.Unmarshal([]byte(payload), &f) == nil && f.Total > 0 && f.Used != nil && f.Ratio != nil &&
				*f.Used >= 0 && *f.Used <= float64(f.Total) && *f.Ratio >= 0 && *f.Ratio <= 100 {
				usage.CPU = &processorUsage{Used: *f.Used, Total: f.Total, Percent: *f.Ratio}
			}
			continue
		}
		var f struct {
			Used             *uint64 `json:"used_bytes"`
			Total            uint64  `json:"total_bytes"`
			Mountpoint       string  `json:"mountpoint"`
			SharedFilesystem string  `json:"shared_filesystem"`
		}
		if json.Unmarshal([]byte(payload), &f) != nil || f.Used == nil || f.Total == 0 || *f.Used > f.Total {
			continue
		}
		if key == "memory" {
			usage.Memory = &resourceUsage{Used: *f.Used, Total: f.Total, Percent: 100 * float64(*f.Used) / float64(f.Total)}
			continue
		}
		if !strings.HasPrefix(f.Mountpoint, "/") || diskOverflow {
			continue
		}
		if f.SharedFilesystem != "" {
			if sharedFilesystems[f.SharedFilesystem] {
				continue
			}
			sharedFilesystems[f.SharedFilesystem] = true
		}
		var carry uint64
		diskTotal, carry = bits.Add64(diskTotal, f.Total, 0)
		diskOverflow = carry != 0
		diskUsed += *f.Used // Used never exceeds total for a valid row.
	}
	if diskTotal > 0 && !diskOverflow {
		usage.Disk = &resourceUsage{Used: diskUsed, Total: diskTotal, Percent: 100 * float64(diskUsed) / float64(diskTotal)}
	}
	summary["host_usage"] = usage
	return rows.Err()
}
