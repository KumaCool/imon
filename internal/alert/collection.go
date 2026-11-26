package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ObserveCollection records collection health separately from user rules.
func (e *Engine) ObserveCollection(ctx context.Context, tx *sql.Tx, targetID string, rev int64, group, code string, at time.Time) error {
	if code == "canceled" || code == "stale_target" || code == "firewall_not_configured" {
		return nil
	}
	var targetName string
	err := tx.QueryRowContext(ctx, `SELECT name FROM targets WHERE target_id=? AND connection_rev=? AND enabled=1`, targetID, rev).Scan(&targetName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	key := fmt.Sprintf("collection:%s:%d:%s", targetID, rev, group)
	var id string
	var last int64
	err = tx.QueryRowContext(ctx, `SELECT id,observed_at FROM alert_events WHERE rule_id=? AND status='active'`, key).Scan(&id, &last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	stamp := at.UnixMilli()
	if stamp < last {
		return nil
	}
	active := id != ""
	if code == "" && !active {
		return nil
	}
	if code != "" {
		code = collectionCategory(code)
	}
	raw, err := marshal(code)
	if err != nil {
		return err
	}
	// A repeated failure advances the existing event without re-enqueueing delivery.
	if active && code != "" {
		_, err := tx.ExecContext(ctx, `UPDATE alert_events SET latest_value=?,observed_at=? WHERE id=?`, raw, stamp, id)
		return err
	}

	phase := "trigger"
	rule := Rule{Name: "采集异常", Severity: "warning", Channels: Channels{Panel: true, Telegram: true, Email: true}}
	if code == "" {
		phase = "recovery"
		if _, err := tx.ExecContext(ctx, `UPDATE alert_events SET status='recovered',observed_at=?,recovered_at=?,ended_at=? WHERE id=?`, stamp, stamp, stamp, id); err != nil {
			return err
		}
	} else {
		id, err = newID("event")
		if err != nil {
			return err
		}
		event := Event{ID: id, RuleID: key, RuleName: rule.Name, Severity: rule.Severity, TargetID: targetID, TargetName: targetName,
			ObjectName: group, Source: "collection", Group: group, InitialValue: code}
		snapshot, err := marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO alert_events(id,rule_id,target_id,connection_rev,status,snapshot,latest_value,observed_at,triggered_at)
			VALUES(?,?,?,?,'active',?,?,?,?)`, id, key, targetID, rev, snapshot, raw, stamp, stamp); err != nil {
			return err
		}
	}
	enabled, err := settings(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,channel FROM notification_targets ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var target, channel string
		if err := rows.Scan(&target, &channel); err != nil {
			rows.Close()
			return err
		}
		switch {
		case channel == "telegram" && enabled.Telegram:
			rule.NotificationTargetIDs.Telegram = append(rule.NotificationTargetIDs.Telegram, target)
		case channel == "email" && enabled.Email:
			rule.NotificationTargetIDs.Email = append(rule.NotificationTargetIDs.Email, target)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if code == "" {
		code = "恢复"
	}
	return e.enqueue(ctx, tx, id, phase, rule, targetName, Value{ObjectName: group, Value: code}, stamp)
}

func collectionCategory(code string) string {
	switch code {
	case "timeout", "connection_failed", "dns_failed", "ssh_session_failed", "tls_verification_failed",
		"authentication_failed", "identity_changed", "host_key_untrusted", "credential_unreadable", "credential_invalid",
		"command_unavailable", "command_failed", "permission_denied", "firewall_unreadable",
		"invalid_response", "output_limit", "api_request_failed", "rate_limited", "request_rejected",
		"publish_failed", "storage_unavailable":
		return code
	default:
		return "collection_failed"
	}
}
