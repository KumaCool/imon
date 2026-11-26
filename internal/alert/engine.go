package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"imon/internal/store"
)

type Engine struct {
	db     *store.Store
	now    func() time.Time
	send   func(context.Context, notificationTarget, string, string) sendResult
	cancel context.CancelFunc
	worker sync.WaitGroup
	slots  chan struct{}
}

func New(ctx context.Context, db *store.Store) (*Engine, error) {
	e := &Engine{db: db, now: time.Now, send: sendNotification, slots: make(chan struct{}, 2)}
	if err := db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET status='unknown',detail='sending_interrupted',updated_at=? WHERE status='sending'`, e.now().UnixMilli()); err != nil {
			return err
		}
		return e.ResetPending(ctx, tx)
	}); err != nil {
		return nil, err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	for range 2 {
		e.worker.Add(1)
		go func() { defer e.worker.Done(); e.work(workerCtx) }()
	}
	return e, nil
}

func (e *Engine) Close() { e.cancel(); e.worker.Wait() }

func (e *Engine) ResetPending(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE rule_state SET pending_count=0,pending_start=0 WHERE pending_count<>0`)
	return err
}

func (e *Engine) StopTarget(ctx context.Context, tx *sql.Tx, id, reason string) error {
	status := "monitoring_stopped"
	if reason == "configuration_changed" {
		status = reason
	}
	if _, err := tx.ExecContext(ctx, `UPDATE alert_events SET status=?,ended_at=?,detail_state='' WHERE target_id=? AND status='active'`, status, e.now().UnixMilli(), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rule_state WHERE rule_id IN (SELECT id FROM alert_rules WHERE target_id=?)`, id); err != nil {
		return err
	}
	if status == "configuration_changed" {
		// Control invalidates the old connection before incrementing its revision.
		// It has verified the destination is still the same target.
		_, err := tx.ExecContext(ctx, `UPDATE alert_rules SET connection_rev=connection_rev+1 WHERE target_id=?`, id)
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE alert_rules SET enabled=0,revision=revision+1,
		config=json_set(config,'$.enabled',json('false'),'$.revision',revision+1) WHERE target_id=? AND enabled=1`, id)
	return err
}

// Observe runs inside the same transaction that finalizes a collection attempt.
func (e *Engine) Observe(ctx context.Context, tx *sql.Tx, o Observation) error {
	if !o.CurrentSettings || o.BatchID == "" || o.ObservedAt.IsZero() || (o.Scheduled && !o.PollingEnabled) {
		return nil
	}
	var targetRev int64
	var targetName string
	err := tx.QueryRowContext(ctx, `SELECT connection_rev,name FROM targets WHERE target_id=? AND enabled=1`, o.TargetID).Scan(&targetRev, &targetName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT config FROM alert_rules WHERE enabled=1 AND target_id=? AND connection_rev=? AND group_name=?`, o.TargetID, targetRev, o.Group)
	if err != nil {
		return err
	}
	rules, err := readRows[Rule](rows)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return nil
	}
	values := make(map[Selector]Value, len(o.Values))
	for _, value := range o.Values {
		value.Selector.TargetID = o.TargetID
		values[canonicalSelector(value.Selector)] = value
	}
	completeKinds := make(map[string]bool, len(o.CompleteListenerKinds))
	for _, kind := range o.CompleteListenerKinds {
		completeKinds[kind] = true
	}
	for _, rule := range rules {
		key := canonicalSelector(rule.Selector)
		value := values[key]
		if key.Metric == "port_listening" && value.Value == nil && o.Complete && completeKinds[key.Protocol+"/"+key.Family] {
			value = Value{Value: false, ObjectName: fmt.Sprintf("%s %s:%d", key.Protocol, key.Address, key.Port)}
		}
		if err := e.advance(ctx, tx, o, rule, value, targetName, targetRev); err != nil {
			return err
		}
	}
	return nil
}

type pending struct {
	count                          int
	start, observed, latestPending int64
	batch                          string
}

func (e *Engine) advance(ctx context.Context, tx *sql.Tx, o Observation, rule Rule, value Value, targetName string, targetRev int64) error {
	var state pending
	err := tx.QueryRowContext(ctx, `SELECT pending_count,pending_start,last_observed,last_batch,last_pending FROM rule_state WHERE rule_id=?`, rule.ID).Scan(&state.count, &state.start, &state.observed, &state.batch, &state.latestPending)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	at := o.ObservedAt.UnixMilli()
	// Also reject out-of-order completions. A completed snapshot may be replayed,
	// but its replay must never replace a later observation or open another event.
	if state.batch == o.BatchID || (state.batch != "" && at < state.observed) {
		return nil
	}
	if state.count > 0 && o.Group != "probe" && o.Period > 0 && at-state.latestPending > 2*o.Period.Milliseconds() {
		state.count, state.start = 0, 0
	}
	state.batch, state.observed = o.BatchID, at
	save := func() error {
		_, err := tx.ExecContext(ctx, `INSERT INTO rule_state (rule_id,pending_count,pending_start,last_observed,last_batch,last_pending) VALUES(?,?,?,?,?,?)
			ON CONFLICT(rule_id) DO UPDATE SET pending_count=excluded.pending_count,pending_start=excluded.pending_start,last_observed=excluded.last_observed,last_batch=excluded.last_batch,last_pending=excluded.last_pending`, rule.ID, state.count, state.start, state.observed, state.batch, state.latestPending)
		return err
	}
	var activeID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM alert_events WHERE rule_id=? AND status='active'`, rule.ID).Scan(&activeID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	abnormal, valid := compare(metrics[rule.Selector.Metric].valueType, rule.Condition, value.Value)
	if !valid || !o.Complete {
		state.count, state.start = 0, 0
		detail := "unknown"
		if o.Complete && value.Value == nil {
			detail = "object_missing"
		}
		if activeID != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE alert_events SET detail_state=? WHERE id=?`, detail, activeID); err != nil {
				return err
			}
		}
		return save()
	}
	raw, err := marshal(value.Value)
	if err != nil {
		return err
	}
	if activeID != "" {
		state.count, state.start = 0, 0
		if abnormal {
			_, err = tx.ExecContext(ctx, `UPDATE alert_events SET latest_value=?,observed_at=?,detail_state='' WHERE id=?`, raw, at, activeID)
		} else {
			if _, err = tx.ExecContext(ctx, `UPDATE alert_events SET latest_value=?,observed_at=?,detail_state='',status='recovered',recovered_at=?,ended_at=? WHERE id=?`, raw, at, at, at, activeID); err == nil {
				err = e.enqueue(ctx, tx, activeID, "recovery", rule, targetName, value, at)
			}
		}
		if err != nil {
			return err
		}
		return save()
	}
	if !abnormal {
		state.count, state.start = 0, 0
		return save()
	}
	count := 1
	if rule.Trigger.ConsecutiveSamples != nil {
		count = *rule.Trigger.ConsecutiveSamples
	}
	duration := 0
	if rule.Trigger.DurationSeconds != nil {
		duration = *rule.Trigger.DurationSeconds
	}
	if duration > 0 && !o.PollingEnabled {
		return save()
	}
	if o.PollingEnabled && !o.Scheduled && (duration > 0 || count > 1) {
		return save()
	}
	if state.count == 0 {
		state.start = at
	}
	state.count++
	state.latestPending = at
	var ready bool
	if duration > 0 {
		ready = at-state.start >= int64(duration)*1000
	} else {
		ready = state.count >= count
	}
	if !ready {
		return save()
	}
	state.count, state.start = 0, 0
	eid, err := newID("event")
	if err != nil {
		return err
	}
	event := Event{
		ID: eid, RuleID: rule.ID, RuleName: rule.Name, TargetID: o.TargetID, TargetName: targetName, ObjectName: value.ObjectName,
		Severity: rule.Severity, Selector: rule.Selector, Condition: rule.Condition, Trigger: rule.Trigger, InitialValue: value.Value,
	}
	if event.ObjectName == "" {
		event.ObjectName = targetName
	}
	eventJSON, err := marshal(event)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO alert_events (id,rule_id,target_id,connection_rev,status,snapshot,latest_value,observed_at,triggered_at) VALUES(?,?,?,?,'active',?,?,?,?)`, eid, rule.ID, o.TargetID, targetRev, eventJSON, raw, at, at); err != nil {
		return err
	}
	if err = e.enqueue(ctx, tx, eid, "trigger", rule, targetName, value, at); err != nil {
		return err
	}
	return save()
}

func readRows[T any](rows *sql.Rows) ([]T, error) {
	defer rows.Close()
	items := make([]T, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item T
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func marshal(v any) (string, error) {
	raw, err := json.Marshal(v)
	return string(raw), err
}
