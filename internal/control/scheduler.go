package control

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

type Settings struct {
	Enabled  bool  `json:"poll_enabled"`
	Host     int   `json:"host_interval"`
	Network  int   `json:"network_interval"`
	Cluster  int   `json:"cluster_interval"`
	Timeout  int   `json:"timeout"`
	Revision int64 `json:"revision"`
}

func (s Settings) period(kind, group string) time.Duration {
	seconds := s.Host
	if kind == "cluster" {
		seconds = s.Cluster
	} else if group == "probe" {
		seconds = min(s.Host, s.Network)
	} else if group != "host_metrics" && group != "systemd" && group != "os_info" {
		seconds = s.Network
	}
	return time.Duration(seconds) * time.Second
}

type Job struct {
	*firewallJob
	ID          string            `json:"job_id"`
	TargetID    string            `json:"target_id"`
	Kind        string            `json:"kind"`
	Status      string            `json:"status"`
	Results     map[string]string `json:"results"`
	Error       string            `json:"error_code,omitempty"`
	QueuedAt    int64             `json:"queued_at"`
	CompletedAt *int64            `json:"completed_at"`
}

type collection struct {
	job      Job
	target   binding
	groups   map[string]bool // true when due on the automatic schedule
	manual   map[string]bool // retained if settings invalidate the automatic portion
	revision int64
	rules    map[string]map[string]int64
	cancel   context.CancelFunc
}

func randID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

func (c *Control) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *Control) getSettings(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	s := c.settings
	c.mu.Unlock()
	send(w, 200, s)
}
func (c *Control) putSettings(w http.ResponseWriter, r *http.Request) {
	var s Settings
	if !decode(w, r, &s) {
		return
	}
	if s.Host < 10 || s.Host > 86400 || s.Network < 10 || s.Network > 86400 || s.Cluster < 10 || s.Cluster > 86400 || s.Timeout < 10 || s.Timeout > 900 {
		report(w, errInvalid)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.Revision != 0 && s.Revision != c.settings.Revision {
		report(w, errConflict)
		return
	}
	s.Revision = c.settings.Revision
	if s == c.settings {
		send(w, 200, s)
		return
	}
	s.Revision++
	err := c.db.Write(r.Context(), func(tx *sql.Tx) error {
		ctx := r.Context()
		_, err := tx.ExecContext(ctx, `UPDATE sampling_settings SET poll_enabled=?,host_interval=?,network_interval=?,cluster_interval=?,timeout=?,revision=? WHERE id=1`, s.Enabled, s.Host, s.Network, s.Cluster, s.Timeout, s.Revision)
		if err != nil {
			return err
		}
		for _, q := range c.queued {
			if len(q.manual) == 0 {
				if err := finishJob(ctx, tx, q.job.ID, "canceled", nil, "settings_changed"); err != nil {
					return err
				}
			}
		}
		if c.observer != nil {
			return c.observer.Reset(ctx, tx)
		}
		return nil
	})
	if err != nil {
		report(w, err)
		return
	}
	c.settings = s
	c.due = map[string]map[string]time.Time{}
	c.backoff = map[string]time.Time{}
	c.failures = map[string]int{}
	for id, q := range c.queued {
		c.finishPlanned(q)
		if len(q.manual) == 0 {
			delete(c.queued, id)
			continue
		}
		q.groups = map[string]bool{}
		for group := range q.manual {
			q.groups[group] = false
		}
		q.revision = s.Revision
	}
	c.signal()
	send(w, 200, s)
}

func (c *Control) getJob(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var job Job
	var raw string
	ctx := r.Context()
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT job_id,target_id,kind,status,results,error_code,queued_at,completed_at FROM collection_jobs WHERE job_id=?`, r.PathValue("id")).Scan(&job.ID, &job.TargetID, &job.Kind, &job.Status, &raw, &job.Error, &job.QueuedAt, &job.CompletedAt); err != nil {
			return err
		}
		if job.Kind == "firewall" {
			job.firewallJob = &firewallJob{}
			_, err := c.firewallDetails(ctx, tx, job.ID, job.firewallJob)
			return err
		}
		return nil
	})
	if err == nil {
		err = json.Unmarshal([]byte(raw), &job.Results)
	}
	if err != nil {
		report(w, err)
		return
	}
	if job.Kind == "collect" && (job.Status == "queued" || job.Status == "running") && !hasJob(c.queued[job.TargetID], job.ID) && !hasJob(c.active[job.TargetID], job.ID) {
		// The scheduler already retired this job; a failed status write cannot leave clients polling forever.
		job.Status, job.Error = "failed", "storage_unavailable"
		at := time.Now().UnixMilli()
		job.CompletedAt = &at
	}
	send(w, 200, job)
}

func hasJob(q *collection, id string) bool { return q != nil && q.job.ID == id }

// enqueue retains the single-job interface for refreshes that request one group.
func (c *Control) enqueue(ctx context.Context, b binding, groups map[string]bool, manual bool) (string, error) {
	// A refresh after a mutation must observe a state after that mutation.
	ids, err := c.enqueueGroups(ctx, b, groups, manual, false)
	if err != nil || len(ids) == 0 {
		return "", err
	}
	return ids[0], nil
}

// enqueueGroups is called with mu held. Each target has at most one queued job.
func (c *Control) enqueueGroups(ctx context.Context, b binding, groups map[string]bool, manual, reuseActive bool) ([]string, error) {
	var ids []string
	if current := c.active[b.ID]; reuseActive && current != nil && current.target.ConnectionRev == b.ConnectionRev {
		remaining := map[string]bool{}
		for g, scheduled := range groups {
			if _, ok := current.groups[g]; !ok {
				remaining[g] = scheduled
			}
		}
		if len(remaining) != len(groups) {
			ids = append(ids, current.job.ID)
		}
		groups = remaining
	}
	if len(groups) == 0 {
		return ids, nil
	}
	q := c.queued[b.ID]
	if q == nil {
		q = &collection{target: b, job: Job{ID: newID(), TargetID: b.ID, Kind: "collect", Status: "queued", QueuedAt: time.Now().UnixMilli()}, groups: map[string]bool{}, manual: map[string]bool{}, revision: c.settings.Revision}
		if err := c.db.Write(ctx, func(tx *sql.Tx) error { return insertJob(ctx, tx, q.job, b.ConnectionRev) }); err != nil {
			return nil, err
		}
		c.queued[b.ID] = q
	}
	for g, scheduled := range groups {
		q.groups[g] = q.groups[g] || scheduled
		if manual {
			q.manual[g] = true
		}
	}
	return append(ids, q.job.ID), nil
}

func insertJob(ctx context.Context, tx *sql.Tx, job Job, rev int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO collection_jobs(job_id,target_id,connection_rev,kind,status,queued_at) VALUES(?,?,?,?,?,?)`, job.ID, job.TargetID, rev, job.Kind, job.Status, job.QueuedAt)
	return err
}

func finishJob(ctx context.Context, tx *sql.Tx, id, status string, results map[string]string, code string) error {
	if results == nil {
		results = map[string]string{}
	}
	raw, _ := json.Marshal(results)
	_, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status=?,results=?,error_code=?,completed_at=? WHERE job_id=? AND status IN ('queued','running')`, status, string(raw), code, time.Now().UnixMilli(), id)
	return err
}

func (c *Control) cancelCollection(id string) {
	if target := c.round[id]; target != nil {
		for _, task := range target.groups {
			if !hasJob(c.active[id], task.jobID) {
				task.done = true
			}
		}
	}
	delete(c.queued, id)
	delete(c.failures, id)
	delete(c.backoff, id)
	if active := c.active[id]; active != nil {
		active.cancel()
	}
}

func (c *Control) loop() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	cleanup := time.NewTicker(time.Minute)
	defer cleanup.Stop()
	last := time.Now()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-cleanup.C:
			c.prune()
		case <-tick.C:
			c.flushCollectionIncidents()
			now := time.Now()
			c.mu.Lock()
			if now.Sub(last) > 5*time.Second && c.observer != nil {
				_ = c.db.Write(c.ctx, func(tx *sql.Tx) error { return c.observer.Reset(c.ctx, tx) })
			}
			last = now
			c.plan(now)
			c.dispatch()
			c.mu.Unlock()
		case <-c.wake:
			c.mu.Lock()
			c.plan(time.Now())
			c.dispatch()
			c.mu.Unlock()
		}
	}
}

func (c *Control) dispatch() {
	for kind, cap := range map[string]int{"host": 4, "cluster": 2} {
		for _, running := range c.active {
			if running.target.Kind == kind {
				cap--
			}
		}
		for range cap {
			var manual, automatic *collection
			for id, q := range c.queued {
				if q.target.Kind != kind || c.active[id] != nil {
					continue
				}
				pick := &manual
				if len(q.manual) == 0 {
					pick = &automatic
				} else if c.isPlanned(q) {
					pick = &automatic
				}
				if *pick == nil || q.job.QueuedAt < (*pick).job.QueuedAt || q.job.QueuedAt == (*pick).job.QueuedAt && q.job.ID < (*pick).job.ID {
					*pick = q
				}
			}
			next := manual
			if next == nil || automatic != nil && c.streak[kind] >= 3 {
				next = automatic
			}
			if next == nil {
				break
			}
			if next == automatic {
				c.streak[kind] = 0
			} else {
				c.streak[kind]++
			}
			settings := c.settings
			next.rules = c.ruleSet[next.target.ID].groups
			ctx, cancel := context.WithTimeout(c.ctx, time.Duration(settings.Timeout)*time.Second)
			err := c.db.Write(c.ctx, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(c.ctx, `UPDATE collection_jobs SET status='running' WHERE job_id=? AND status='queued'`, next.job.ID)
				return err
			})
			if err != nil {
				cancel()
				delete(c.queued, next.target.ID)
				c.finishPlanned(next)
				continue
			}
			next.cancel = cancel
			delete(c.queued, next.target.ID)
			c.active[next.target.ID] = next
			for group, scheduled := range next.groups {
				if scheduled && c.due[next.target.ID] != nil {
					c.due[next.target.ID][group] = time.Now().Add(settings.period(kind, group))
				}
			}
			c.wg.Go(func() { c.runCollection(ctx, next, settings) })
		}
	}
}

func (c *Control) runCollection(ctx context.Context, q *collection, s Settings) {
	defer q.cancel()
	defer func() {
		c.mu.Lock()
		delete(c.active, q.target.ID)
		c.finishPlanned(q)
		c.mu.Unlock()
		c.signal()
	}()
	results := map[string]string{}
	observed := time.Now()
	session, probeErr := collector.Open(ctx, q.target.Kind, q.target.Config, q.target.Identity)
	if session != nil {
		defer session.Close()
	}
	scheduled := false
	for _, planned := range q.groups {
		scheduled = scheduled || planned
	}
	code := collectionError(probeErr)
	c.mu.Lock()
	if q.revision == c.settings.Revision && ctx.Err() != context.Canceled && c.active[q.target.ID] == q {
		if probeErr == nil {
			delete(c.failures, q.target.ID)
			delete(c.backoff, q.target.ID)
		} else if scheduled {
			count := min(c.failures[q.target.ID]+1, 3)
			c.failures[q.target.ID] = count
			period := s.period(q.target.Kind, "probe")
			c.backoff[q.target.ID] = time.Now().Add(period + min(period*((1<<count)-1), 300*time.Second))
		}
	}
	c.mu.Unlock()
	probeResult := probeErr
	if ctx.Err() != context.Canceled {
		if err := c.recordProbe(q, s, q.groups["probe"], probeErr); err != nil && !errors.Is(err, store.ErrStaleTarget) && !errors.Is(err, store.ErrNotFound) {
			code = "storage_unavailable"
			if probeResult == nil {
				probeResult = err
			}
		}
		c.observeCollection(q, "probe", collectionError(probeErr))
	}
	success := 0
	if _, included := q.groups["probe"]; included {
		if probeResult == nil {
			success++
		}
		results["probe"] = collectionError(probeResult)
		if probeErr == nil && probeResult != nil {
			results["probe"] = "storage_unavailable"
		}
		c.markGroupDone(q, "probe")
	}
	for _, group := range collector.Groups(q.target.Kind) {
		planned, included := q.groups[group]
		if !included {
			continue
		}
		results[group] = ""
		if err := c.runGroup(ctx, q, s, group, planned, session, probeErr, observed); err != nil {
			if errors.Is(err, store.ErrStaleTarget) || errors.Is(err, store.ErrNotFound) {
				results[group] = "canceled"
			} else if errors.Is(err, errSnapshotStorage) {
				results[group] = "storage_unavailable"
			} else {
				results[group] = collectionError(err)
			}
		} else {
			success++
		}
		if probeErr == nil && ctx.Err() != context.Canceled {
			c.observeCollection(q, group, results[group])
		}
		c.markGroupDone(q, group)
	}
	status := "success"
	if c.ctx.Err() != nil || errors.Is(ctx.Err(), context.Canceled) {
		status = "canceled"
	} else if success == 0 && len(results) > 0 {
		status = "failed"
	} else if success < len(results) || code == "storage_unavailable" {
		status = "partial"
	}
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.db.Write(finish, func(tx *sql.Tx) error { return finishJob(finish, tx, q.job.ID, status, results, code) })
}

func (c *Control) recordProbe(q *collection, s Settings, scheduled bool, probeErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.db.Write(ctx, func(tx *sql.Tx) error {
		var b binding
		if err := readBinding(ctx, tx, q.target.ID, &b); err != nil {
			return err
		}
		if b.ConnectionRev != q.target.ConnectionRev {
			return store.ErrStaleTarget
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO target_probe VALUES(?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET connection_rev=excluded.connection_rev,observed_at=excluded.observed_at,reachable=excluded.reachable,error_code=excluded.error_code`, b.ID, b.ConnectionRev, time.Now().UnixMilli(), probeErr == nil, collectionError(probeErr)); err != nil {
			return err
		}
		if c.observer == nil {
			return nil
		}
		data, _ := json.Marshal(map[string]bool{"reachable": probeErr == nil})
		return c.observer.Observe(ctx, tx, Observation{TargetID: b.ID, TargetName: b.Name, Group: "probe", BatchID: q.job.ID, At: time.Now(), Period: s.period(b.Kind, "probe"), Scheduled: scheduled, PollingEnabled: s.Enabled, CurrentSettings: isCurrent(ctx, tx, q.revision) && currentRules(ctx, tx, q, "probe"), Complete: true, Rows: []collector.Row{{Key: "probe", Data: data}}})
	})
}

func isCurrent(ctx context.Context, tx *sql.Tx, expected int64) bool {
	var rev int64
	return tx.QueryRowContext(ctx, `SELECT revision FROM sampling_settings WHERE id=1`).Scan(&rev) == nil && rev == expected
}

var errSnapshotStorage = errors.New("snapshot storage unavailable")

func snapshotStorageError(err error) error {
	return fmt.Errorf("%w: %w", errSnapshotStorage, err)
}

func (c *Control) runGroup(ctx context.Context, q *collection, s Settings, group string, scheduled bool, session *collector.Session, probeErr error, started time.Time) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	key := store.SnapshotKey{TargetID: q.target.ID, ConnectionRev: q.target.ConnectionRev, Group: group, BatchID: q.job.ID}
	finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := c.db.StartSnapshot(finish, key, started.UnixMilli())
	cancel()
	if err != nil {
		return snapshotStorageError(err)
	}
	source := "manual"
	if scheduled {
		source = "scheduled"
	}
	opts := collector.Options{Manual: !scheduled, MaxWindow: 2 * s.period(q.target.Kind, group), SampledAt: time.Now()}
	if !scheduled {
		opts.MaxWindow = 10 * time.Minute
	}
	var rows []collector.Row
	readErr := probeErr
	if readErr == nil {
		readErr = ctx.Err()
	}
	if readErr == nil && group == "host_metrics" {
		readErr = c.db.Read(ctx, func(tx *sql.Tx) error {
			var previous string
			err := tx.QueryRowContext(ctx, `SELECT payload FROM sampling_baselines WHERE target_id=? AND connection_rev=? AND source=?`, key.TargetID, key.ConnectionRev, source).Scan(&previous)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			return json.Unmarshal([]byte(previous), &opts.Previous)
		})
		if readErr != nil {
			readErr = snapshotStorageError(readErr)
		}
	}
	if readErr == nil && group == "systemd" {
		for cursor := (*store.SnapshotCursor)(nil); ; {
			page, err := c.db.ReadSnapshot(ctx, key.TargetID, group, cursor, 200)
			if err != nil {
				readErr = snapshotStorageError(err)
				break
			}
			for _, row := range page.Rows {
				opts.Previous = append(opts.Previous, collector.Row{Key: row.ObjectKey, Data: row.Payload})
			}
			cursor = page.Next
			if cursor == nil {
				break
			}
		}
	}
	if readErr == nil && group == "deployments" {
		for cursor := (*store.SnapshotCursor)(nil); ; {
			page, err := c.db.ReadSnapshot(ctx, key.TargetID, group, cursor, 200)
			if err != nil {
				readErr = snapshotStorageError(err)
				break
			}
			for _, row := range page.Rows {
				opts.Previous = append(opts.Previous, collector.Row{Key: row.ObjectKey, Data: row.Payload})
			}
			cursor = page.Next
			if cursor == nil {
				break
			}
		}
	}
	if readErr == nil {
		rows, readErr = session.CollectWithOptions(ctx, group, opts)
	}
	finish, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if readErr == nil {
		for page := range slices.Chunk(rows, 200) {
			staged := make([]store.SnapshotRow, 0, len(page))
			for _, row := range page {
				staged = append(staged, store.SnapshotRow{ObjectKey: row.Key, Payload: row.Data})
			}
			if err := c.db.StageSnapshotRows(finish, key, staged); err != nil {
				readErr = snapshotStorageError(err)
				break
			}
		}
	}
	at := time.Now()
	apply := func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(finish, `UPDATE snapshot_batches SET source=? WHERE target_id=? AND connection_rev=? AND group_name=? AND batch_id=?`, source, key.TargetID, key.ConnectionRev, key.Group, key.BatchID); err != nil {
			return err
		}
		if readErr == nil && group == "host_metrics" {
			raw, err := json.Marshal(rows)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(finish, `INSERT INTO sampling_baselines VALUES(?,?,?,?) ON CONFLICT(target_id,connection_rev,source) DO UPDATE SET payload=excluded.payload`, key.TargetID, key.ConnectionRev, source, string(raw)); err != nil {
				return err
			}
			if err := writeSamples(finish, tx, key, at, rows); err != nil {
				return err
			}
		}
		if c.observer != nil && !errors.Is(readErr, context.Canceled) {
			return c.observer.Observe(finish, tx, Observation{TargetID: key.TargetID, TargetName: q.target.Name, Group: group, BatchID: key.BatchID, At: at, Period: s.period(q.target.Kind, group), Scheduled: scheduled, PollingEnabled: s.Enabled, CurrentSettings: isCurrent(finish, tx, q.revision) && currentRules(finish, tx, q, group), Complete: readErr == nil, Rows: rows})
		}
		return nil
	}
	if readErr == nil {
		if err := c.db.PublishSnapshot(finish, key, at.UnixMilli(), at.UnixMilli(), apply); err == nil {
			return nil
		} else {
			readErr = snapshotStorageError(err)
		}
	}
	code := collectionError(readErr)
	if errors.Is(readErr, errSnapshotStorage) {
		code = "storage_unavailable"
	}
	if err := c.db.FailSnapshotWith(finish, key, at.UnixMilli(), code, apply); err != nil {
		return snapshotStorageError(err)
	}
	return readErr
}

func (c *Control) prune() {
	_, _ = c.db.PruneSnapshotRows(c.ctx, 200)
	cutoff := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	_ = c.db.Write(c.ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM performance_samples WHERE rowid IN (SELECT rowid FROM performance_samples WHERE observed_at<? LIMIT 2000)`, cutoff); err != nil {
			return err
		}
		// Keep unresolved remote files and the latest authorization observation
		// for each active binding, including an install that supersedes a removal.
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM collection_jobs
			WHERE completed_at<? AND status NOT IN ('unknown','awaiting_admin')
			AND NOT EXISTS (SELECT 1 FROM firewall_maintenance m
				WHERE m.job_id=collection_jobs.job_id AND m.stage_path<>'')
			AND rowid NOT IN (
				SELECT MAX(j.rowid) FROM firewall_maintenance m
				JOIN collection_jobs j USING(job_id) JOIN targets t ON t.target_id=m.target_id AND t.connection_rev=m.connection_rev
				WHERE j.status='success' AND json_extract(j.results,'$.firewall_status') IN ('installed','uninstalled')
				GROUP BY m.target_id
			)`, cutoff); err != nil {
			return err
		}
		_, err := tx.ExecContext(c.ctx, `DELETE FROM snapshot_batches WHERE rowid IN (SELECT b.rowid FROM snapshot_batches b WHERE b.status<>'staging' AND b.completed_at<? AND NOT EXISTS (SELECT 1 FROM group_state g WHERE g.target_id=b.target_id AND g.connection_rev=b.connection_rev AND g.group_name=b.group_name AND b.batch_id IN (g.attempt_batch_id,g.published_batch_id)) AND NOT EXISTS (SELECT 1 FROM snapshot_rows r WHERE (r.target_id,r.connection_rev,r.group_name,r.batch_id)=(b.target_id,b.connection_rev,b.group_name,b.batch_id)) LIMIT 2000)`, cutoff)
		return err
	})
}
