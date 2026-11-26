package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Delivery struct {
	ID        string `json:"id,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Address   string `json:"address"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

type notificationTarget struct {
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name"`
	Channel       string   `json:"channel"`
	CredentialRef string   `json:"credential_ref"`
	ChatID        string   `json:"chat_id,omitempty"`
	ProxyURL      string   `json:"proxy_url,omitempty"`
	Host          string   `json:"host,omitempty"`
	Port          int      `json:"port,omitempty"`
	TLSMode       string   `json:"tls_mode,omitempty"`
	Username      string   `json:"username,omitempty"`
	From          string   `json:"from,omitempty"`
	Recipients    []string `json:"recipients,omitempty"`
}

func (t notificationTarget) addresses() []string {
	if t.Channel == "telegram" {
		return []string{t.ChatID}
	}
	return t.Recipients
}

func settings(ctx context.Context, tx *sql.Tx) (Channels, error) {
	var value Channels
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT config FROM notification_settings WHERE id=1`).Scan(&raw)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &value)
	}
	return value, err
}

func (e *Engine) getNotificationSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var value Channels
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		var err error
		value, err = settings(ctx, tx)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 200, value)
}

func (e *Engine) putNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Panel    *bool `json:"panel"`
		Telegram *bool `json:"telegram"`
		Email    *bool `json:"email"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Panel == nil || input.Telegram == nil || input.Email == nil {
		bad(w, "All three channel switches are required.")
		return
	}
	value := Channels{*input.Panel, *input.Telegram, *input.Email}
	raw, err := marshal(value)
	if err != nil {
		stateError(w, err)
		return
	}
	ctx := r.Context()
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE notification_settings SET config=? WHERE id=1`, raw)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 200, value)
}

func (e *Engine) listNotificationTargets(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(r)
	if !ok {
		bad(w, "limit must be 1–200")
		return
	}
	q, ctx := r.URL.Query(), r.Context()
	channel := q.Get("channel")
	if channel != "" && channel != "telegram" && channel != "email" {
		bad(w, "invalid channel")
		return
	}
	var items []notificationTarget
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT config FROM notification_targets WHERE id>? AND (?='' OR channel=?) ORDER BY id LIMIT ?`, q.Get("cursor"), channel, channel, limit+1)
		if err != nil {
			return err
		}
		items, err = readRows[notificationTarget](rows)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 200, pageJSON(items, limit, func(item notificationTarget) string { return item.ID }))
}

func (e *Engine) createNotificationTarget(w http.ResponseWriter, r *http.Request) {
	var target notificationTarget
	if !decode(w, r, &target) {
		return
	}
	if err := validateDestination(&target); err != nil {
		bad(w, err.Error())
		return
	}
	var err error
	target.ID, err = newID("notify")
	if err != nil {
		stateError(w, err)
		return
	}
	raw, err := marshal(target)
	if err != nil {
		stateError(w, err)
		return
	}
	ctx := r.Context()
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO notification_targets(id,channel,config) VALUES(?,?,?)`, target.ID, target.Channel, raw)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 201, target)
}

type targetPatch struct {
	Name          *string   `json:"name"`
	Channel       *string   `json:"channel"`
	CredentialRef *string   `json:"credential_ref"`
	ChatID        *string   `json:"chat_id"`
	ProxyURL      *string   `json:"proxy_url"`
	Host          *string   `json:"host"`
	Port          *int      `json:"port"`
	TLSMode       *string   `json:"tls_mode"`
	Username      *string   `json:"username"`
	From          *string   `json:"from"`
	Recipients    *[]string `json:"recipients"`
}

func targetByID(ctx context.Context, tx *sql.Tx, id string) (notificationTarget, error) {
	var target notificationTarget
	var raw string
	err := tx.QueryRowContext(ctx, `SELECT config FROM notification_targets WHERE id=?`, id).Scan(&raw)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &target)
	}
	return target, err
}

func (e *Engine) patchNotificationTarget(w http.ResponseWriter, r *http.Request) {
	var patch targetPatch
	if !decode(w, r, &patch) {
		return
	}
	ctx, id := r.Context(), r.PathValue("id")
	var target notificationTarget
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		target, err = targetByID(ctx, tx, id)
		if err != nil {
			return err
		}
		if patch.Channel != nil && *patch.Channel != target.Channel {
			return badRule("The channel of an existing target cannot be changed.")
		}
		patchField(&target.Name, patch.Name)
		patchField(&target.CredentialRef, patch.CredentialRef)
		patchField(&target.ChatID, patch.ChatID)
		patchField(&target.ProxyURL, patch.ProxyURL)
		patchField(&target.Host, patch.Host)
		patchField(&target.Port, patch.Port)
		patchField(&target.TLSMode, patch.TLSMode)
		patchField(&target.Username, patch.Username)
		patchField(&target.From, patch.From)
		patchField(&target.Recipients, patch.Recipients)
		if err := validateDestination(&target); err != nil {
			return badRule(err.Error())
		}
		raw, err := marshal(target)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE notification_targets SET config=? WHERE id=?`, raw, id)
		return err
	})
	if err != nil {
		var invalid badRule
		if errors.As(err, &invalid) {
			bad(w, err.Error())
			return
		}
		stateError(w, err)
		return
	}
	respond(w, 200, target)
}

func (e *Engine) testNotificationTarget(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	var target notificationTarget
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		var err error
		target, err = targetByID(ctx, tx, id)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addresses := target.addresses()
	deliveries := make([]Delivery, 0, len(addresses))
	for _, address := range addresses {
		result := e.sendBounded(ctx, target, address, "Imon test notification")
		deliveries = append(deliveries, Delivery{Address: address, Status: result.status, Detail: result.detail})
	}
	summary := deliveries[0].Status
	for _, item := range deliveries[1:] {
		if item.Status != summary {
			summary = "partial"
			break
		}
	}
	respond(w, 200, map[string]any{"channel": target.Channel, "result": summary, "test": true, "deliveries": deliveries})
}

func (e *Engine) enqueue(ctx context.Context, tx *sql.Tx, eventID, phase string, rule Rule, targetName string, value Value, at int64) error {
	enabled, err := settings(ctx, tx)
	if err != nil {
		return err
	}
	type channelSpec struct {
		name              string
		enabled, selected bool
		ids               []string
	}
	channels := []channelSpec{
		{"panel", enabled.Panel, rule.Channels.Panel, nil},
		{"telegram", enabled.Telegram, rule.Channels.Telegram, rule.NotificationTargetIDs.Telegram},
		{"email", enabled.Email, rule.Channels.Email, rule.NotificationTargetIDs.Email},
	}
	object := value.ObjectName
	if object == "" {
		object = targetName
	}
	message := fmt.Sprintf("Imon | %s | %s\n%s / %s\n%s: %v", phase, rule.Severity, targetName, object, rule.Name, value.Value)
	add := func(channel, address, status, config string) error {
		id, err := newID("delivery")
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO deliveries (id,event_id,phase,channel,address,status,due_at,updated_at,config,message) VALUES(?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(event_id,phase,channel,address) DO NOTHING`, id, eventID, phase, channel, address, status, at, at, config, message)
		return err
	}
	for _, ch := range channels {
		switch {
		case !ch.enabled:
			err = add(ch.name, "", "disabled", "{}")
		case !ch.selected:
			err = add(ch.name, "", "not_selected", "{}")
		case ch.name == "panel":
			_, err = tx.ExecContext(ctx, `UPDATE alert_events SET panel_revision=panel_revision+1 WHERE id=?`, eventID)
			if err == nil {
				err = add(ch.name, "", "delivered", "{}")
			}
		case len(ch.ids) == 0:
			err = add(ch.name, "", "not_configured", "{}")
		default:
			for _, id := range ch.ids {
				target, err := targetByID(ctx, tx, id)
				if err != nil {
					return err
				}
				addresses := target.addresses()
				// Recipient addresses are separate rows, so a temporary failure
				// never sends to an address that already accepted the message.
				target.Recipients = nil
				config, err := marshal(target)
				if err != nil {
					return err
				}
				for _, address := range addresses {
					if err := add(ch.name, address, "queued", config); err != nil {
						return err
					}
				}
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type queued struct {
	id, address, message string
	config               notificationTarget
	attempt              int
}

func (e *Engine) claim(ctx context.Context) (queued, error) {
	var job queued
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		now := e.now().UnixMilli()
		var raw string
		err := tx.QueryRowContext(ctx, `SELECT d.id,d.address,d.config,d.message,d.attempts FROM deliveries d
			WHERE d.status='queued' AND d.due_at<=?
			AND (d.phase='trigger' OR NOT EXISTS(
				SELECT 1 FROM deliveries p WHERE p.event_id=d.event_id AND p.phase='trigger' AND p.channel=d.channel
				AND p.address=d.address AND p.status IN ('queued','sending')))
			ORDER BY d.due_at,d.id LIMIT 1`, now).Scan(&job.id, &job.address, &raw, &job.message, &job.attempt)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(raw), &job.config); err != nil {
			return err
		}
		job.attempt++
		_, err = tx.ExecContext(ctx, `UPDATE deliveries SET status='sending',attempts=?,updated_at=? WHERE id=?`, job.attempt, now, job.id)
		return err
	})
	return job, err
}

func finishDelivery(ctx context.Context, tx *sql.Tx, job queued, result sendResult, now time.Time) error {
	status, due := result.status, now
	if result.retry && job.attempt <= 2 {
		delays := [2]time.Duration{30 * time.Second, 120 * time.Second}
		delay := max(delays[job.attempt-1], result.retryAfter)
		status, due = "queued", now.Add(delay)
	}
	_, err := tx.ExecContext(ctx, `UPDATE deliveries SET status=?,detail=?,due_at=?,updated_at=? WHERE id=? AND status='sending'`,
		status, result.detail, due.UnixMilli(), now.UnixMilli(), job.id)
	return err
}

func (e *Engine) sendBounded(ctx context.Context, target notificationTarget, address, message string) sendResult {
	select {
	case <-ctx.Done():
		return failed("send_timeout")
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
		return e.send(ctx, target, address, message)
	}
}

func (e *Engine) work(ctx context.Context) {
	for ctx.Err() == nil {
		job, err := e.claim(ctx)
		if err != nil {
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				continue
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		result := e.sendBounded(attempt, job.config, job.address, job.message)
		cancel()
		save, done := context.WithTimeout(context.Background(), 2*time.Second)
		_ = e.db.Write(save, func(tx *sql.Tx) error { return finishDelivery(save, tx, job, result, e.now()) })
		done()
	}
}
