package alert

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	errTargetMissing      = errors.New("target not found")
	errTargetKind         = errors.New("metric does not apply to this target")
	errRuleConflict       = errors.New("rule revision changed")
	errNotificationTarget = errors.New("notification target missing or channel does not match")
)

func (e *Engine) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/alert-rules", e.listRules)
	mux.HandleFunc("POST /api/v1/alert-rules", e.createRule)
	mux.HandleFunc("PATCH /api/v1/alert-rules/{id}", e.patchRule)
	mux.HandleFunc("GET /api/v1/alert-events", e.listEvents)
	mux.HandleFunc("GET /api/v1/alert-events/{id}", e.getEvent)
	mux.HandleFunc("POST /api/v1/alert-events/{id}/read", e.readEvent)
	mux.HandleFunc("GET /api/v1/notification-settings", e.getNotificationSettings)
	mux.HandleFunc("PUT /api/v1/notification-settings", e.putNotificationSettings)
	mux.HandleFunc("GET /api/v1/notification-targets", e.listNotificationTargets)
	mux.HandleFunc("POST /api/v1/notification-targets", e.createNotificationTarget)
	mux.HandleFunc("PATCH /api/v1/notification-targets/{id}", e.patchNotificationTarget)
	mux.HandleFunc("POST /api/v1/notification-targets/{id}/test", e.testNotificationTarget)
	mux.HandleFunc("POST /api/v1/notification-settings/panel/test", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, map[string]any{"channel": "panel", "result": "delivered", "test": true})
	})
}

func newID(prefix string) (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(data[:]), nil
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorResponse(w http.ResponseWriter, status int, code, message string) {
	respond(w, status, map[string]any{"code": code, "message": message, "retryable": status == 503})
}

func bad(w http.ResponseWriter, message string) { errorResponse(w, 400, "invalid_request", message) }

func stateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows), errors.Is(err, errTargetMissing):
		errorResponse(w, 404, "not_found", "The requested object no longer exists.")
	case errors.Is(err, errRuleConflict):
		errorResponse(w, 409, "rule_conflict", err.Error())
	case errors.Is(err, errTargetKind), errors.Is(err, errNotificationTarget):
		bad(w, err.Error())
	default:
		errorResponse(w, 503, "storage_unavailable", "Local notification storage is unavailable.")
	}
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		bad(w, "Expected a valid JSON object.")
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		bad(w, "Expected one JSON object.")
		return false
	}
	return true
}

func pageLimit(r *http.Request) (int, bool) {
	input := r.URL.Query().Get("limit")
	if input == "" {
		return 50, true
	}
	limit, err := strconv.Atoi(input)
	return limit, err == nil && limit >= 1 && limit <= 200
}

func pageJSON[T any](items []T, limit int, cursor func(T) string) map[string]any {
	var next any
	if len(items) > limit {
		next = cursor(items[limit-1])
		items = items[:limit]
	}
	return map[string]any{"items": items, "next_cursor": next}
}

func (e *Engine) listRules(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(r)
	if !ok {
		bad(w, "limit must be 1–200")
		return
	}
	ctx := r.Context()
	var rules []Rule
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT config FROM alert_rules WHERE id>? ORDER BY id LIMIT ?`, r.URL.Query().Get("cursor"), limit+1)
		if err != nil {
			return err
		}
		rules, err = readRows[Rule](rows)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 200, pageJSON(rules, limit, func(rule Rule) string { return rule.ID }))
}

func (e *Engine) createRule(w http.ResponseWriter, r *http.Request) {
	var rule Rule
	if !decode(w, r, &rule) {
		return
	}
	if err := validateRule(&rule); err != nil {
		bad(w, err.Error())
		return
	}
	id, err := newID("rule")
	if err != nil {
		stateError(w, err)
		return
	}
	rule.ID, rule.Revision = id, 1
	ctx := r.Context()
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		rev, err := ruleTarget(r, tx, rule)
		if err != nil {
			return err
		}
		raw, err := marshal(rule)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO alert_rules(id,target_id,group_name,connection_rev,revision,enabled,config) VALUES(?,?,?,?,?,?,?)`,
			rule.ID, rule.Selector.TargetID, metrics[rule.Selector.Metric].group, rev, rule.Revision, rule.Enabled, raw)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 201, rule)
}

type rulePatch struct {
	Revision              *int64     `json:"revision"`
	Name                  *string    `json:"name"`
	Enabled               *bool      `json:"enabled"`
	Severity              *string    `json:"severity"`
	Selector              *Selector  `json:"selector"`
	Condition             *Condition `json:"condition"`
	Trigger               *Trigger   `json:"trigger"`
	Channels              *Channels  `json:"channels"`
	NotificationTargetIDs *TargetIDs `json:"notification_target_ids"`
}

func patchField[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

type badRule string

func (s badRule) Error() string { return string(s) }

func (e *Engine) patchRule(w http.ResponseWriter, r *http.Request) {
	var patch rulePatch
	if !decode(w, r, &patch) {
		return
	}
	id, ctx := r.PathValue("id"), r.Context()
	var rule Rule
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		var raw string
		var oldRev int64
		if err := tx.QueryRowContext(ctx, `SELECT config,connection_rev FROM alert_rules WHERE id=?`, id).Scan(&raw, &oldRev); err != nil {
			return err
		}
		var old Rule
		if err := json.Unmarshal([]byte(raw), &old); err != nil {
			return err
		}
		if patch.Revision != nil && *patch.Revision != old.Revision {
			return errRuleConflict
		}
		rule = old
		patchField(&rule.Name, patch.Name)
		patchField(&rule.Enabled, patch.Enabled)
		patchField(&rule.Severity, patch.Severity)
		patchField(&rule.Selector, patch.Selector)
		patchField(&rule.Condition, patch.Condition)
		patchField(&rule.Trigger, patch.Trigger)
		patchField(&rule.Channels, patch.Channels)
		patchField(&rule.NotificationTargetIDs, patch.NotificationTargetIDs)
		if err := validateRule(&rule); err != nil {
			return badRule(err.Error())
		}
		rev, err := ruleTarget(r, tx, rule)
		if !rule.Enabled && errors.Is(err, errTargetMissing) && old.Selector.TargetID == rule.Selector.TargetID {
			rev, err = oldRev, nil
		}
		if err != nil {
			return err
		}
		configChanged := oldRev != rev || canonicalSelector(old.Selector) != canonicalSelector(rule.Selector) || !sameJSON(old.Condition, rule.Condition) || !sameJSON(old.Trigger, rule.Trigger)
		if configChanged || old.Enabled != rule.Enabled {
			status := "configuration_changed"
			if !rule.Enabled {
				status = "monitoring_stopped"
			}
			if _, err := tx.ExecContext(ctx, `UPDATE alert_events SET status=?,ended_at=?,detail_state='' WHERE rule_id=? AND status='active'`, status, e.now().UnixMilli(), id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM rule_state WHERE rule_id=?`, id); err != nil {
				return err
			}
		}
		rule.Revision++
		raw, err = marshal(rule)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE alert_rules SET target_id=?,group_name=?,connection_rev=?,revision=?,enabled=?,config=? WHERE id=?`,
			rule.Selector.TargetID, metrics[rule.Selector.Metric].group, rev, rule.Revision, rule.Enabled, raw, id)
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
	respond(w, 200, rule)
}

func sameJSON(a, b any) bool {
	left, err := marshal(a)
	if err != nil {
		return false
	}
	right, err := marshal(b)
	return err == nil && left == right
}

func ruleTarget(r *http.Request, tx *sql.Tx, rule Rule) (int64, error) {
	ctx := r.Context()
	var kind string
	var rev int64
	err := tx.QueryRowContext(ctx, `SELECT kind,connection_rev FROM targets WHERE target_id=? AND enabled=1`, rule.Selector.TargetID).Scan(&kind, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errTargetMissing
	}
	if err != nil {
		return 0, err
	}
	spec := metrics[rule.Selector.Metric]
	if spec.targetKind != "" && spec.targetKind != kind {
		return 0, errTargetKind
	}
	for channel, ids := range map[string][]string{"telegram": rule.NotificationTargetIDs.Telegram, "email": rule.NotificationTargetIDs.Email} {
		for _, id := range ids {
			var exist int
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM notification_targets WHERE id=? AND channel=?)`, id, channel).Scan(&exist); err != nil {
				return 0, err
			}
			if exist == 0 {
				return 0, errNotificationTarget
			}
		}
	}
	return rev, nil
}

const eventColumns = `e.snapshot,e.status,e.latest_value,e.observed_at,e.triggered_at,e.recovered_at,e.ended_at,e.panel_revision,e.panel_read_revision,e.detail_state,
  EXISTS(SELECT 1 FROM targets t WHERE t.target_id=e.target_id AND t.enabled=1 AND t.connection_rev=e.connection_rev)
  AND e.detail_state<>'object_missing'
  AND (
    json_extract(e.snapshot,'$.selector.uid') IS NULL
    OR EXISTS (
      SELECT 1 FROM group_state g
      JOIN snapshot_rows s ON (s.target_id,s.connection_rev,s.group_name,s.batch_id) =
        (g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
      WHERE g.target_id=e.target_id AND g.connection_rev=e.connection_rev
        AND g.group_name=CASE json_extract(e.snapshot,'$.selector.metric')
          WHEN 'node_ready' THEN 'nodes'
          WHEN 'pod_ready' THEN 'pods'
          WHEN 'pod_phase' THEN 'pods'
          ELSE 'deployments'
        END
        AND s.object_key=json_extract(e.snapshot,'$.selector.uid')
    )
  )`

type rowScanner interface{ Scan(...any) error }

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	var snapshot, latest, status, detail string
	var observed, triggered, panel, read int64
	var recovered, ended *int64
	var source bool
	if err := row.Scan(&snapshot, &status, &latest, &observed, &triggered, &recovered, &ended, &panel, &read, &detail, &source); err != nil {
		return event, err
	}
	if err := json.Unmarshal([]byte(snapshot), &event); err != nil {
		return event, err
	}
	if err := json.Unmarshal([]byte(latest), &event.LatestValue); err != nil {
		return event, err
	}
	if event.Source == "collection" {
		event.ErrorCategory, _ = event.LatestValue.(string)
	}
	event.Status, event.DetailState = status, detail
	event.ObservedAt, event.TriggeredAt, event.RecoveredAt, event.EndedAt = observed, triggered, recovered, ended
	event.PanelRevision, event.PanelReadRevision, event.SourceAvailable = panel, read, source
	return event, nil
}

func unreadCount(r *http.Request, tx *sql.Tx) (int, error) {
	var count int
	err := tx.QueryRowContext(r.Context(), `SELECT count(*) FROM alert_events WHERE panel_revision>panel_read_revision`).Scan(&count)
	return count, err
}

func parseEventCursor(input string) (int64, string, bool) {
	bytes, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return 0, "", false
	}
	date, id, ok := strings.Cut(string(bytes), ":")
	at, err := strconv.ParseInt(date, 10, 64)
	return at, id, ok && err == nil && strings.HasPrefix(id, "event-")
}

func (e *Engine) listEvents(w http.ResponseWriter, r *http.Request) {
	q, ctx := r.URL.Query(), r.Context()
	limit, ok := pageLimit(r)
	if !ok {
		bad(w, "limit must be 1–200")
		return
	}
	where, args := []string{"1=1"}, []any{}
	if status := q.Get("status"); status != "" && status != "all" {
		if status != "active" && status != "recovered" {
			bad(w, "invalid event status filter")
			return
		}
		where = append(where, "e.status=?")
		args = append(args, status)
	}
	if unread := q.Get("unread"); unread != "" {
		if unread != "true" && unread != "false" {
			bad(w, "invalid unread filter")
			return
		}
		if unread == "true" {
			where = append(where, "e.panel_revision>e.panel_read_revision")
		}
	}
	if cursor := q.Get("cursor"); cursor != "" {
		at, id, ok := parseEventCursor(cursor)
		if !ok {
			bad(w, "invalid event cursor")
			return
		}
		where = append(where, "(e.triggered_at,e.id)<(?,?)")
		args = append(args, at, id)
	}
	args = append(args, limit+1)
	items := make([]Event, 0)
	var count int
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+eventColumns+` FROM alert_events e WHERE `+strings.Join(where, " AND ")+` ORDER BY e.triggered_at DESC,e.id DESC LIMIT ?`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			event, err := scanEvent(rows)
			if err != nil {
				return err
			}
			items = append(items, event)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		count, err = unreadCount(r, tx)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	result := pageJSON(items, limit, func(event Event) string {
		return base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s", event.TriggeredAt, event.ID))
	})
	result["unread_count"] = count
	respond(w, 200, result)
}

func (e *Engine) getEvent(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	var event Event
	err := e.db.Read(ctx, func(tx *sql.Tx) error {
		var err error
		event, err = scanEvent(tx.QueryRowContext(ctx, `SELECT `+eventColumns+` FROM alert_events e WHERE id=?`, id))
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,phase,channel,address,status,detail,attempts,updated_at FROM deliveries WHERE event_id=? ORDER BY phase DESC,channel,address`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		event.Deliveries = make([]Delivery, 0, 6)
		for rows.Next() {
			var d Delivery
			if err := rows.Scan(&d.ID, &d.Phase, &d.Channel, &d.Address, &d.Status, &d.Detail, &d.Attempts, &d.UpdatedAt); err != nil {
				return err
			}
			event.Deliveries = append(event.Deliveries, d)
		}
		return rows.Err()
	})
	if err != nil {
		stateError(w, err)
		return
	}
	respond(w, 200, event)
}

func (e *Engine) readEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Through *int64 `json:"through_revision"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Through == nil || *req.Through < 0 {
		bad(w, "through_revision must be nonnegative")
		return
	}
	ctx, id := r.Context(), r.PathValue("id")
	var count int
	var rangeError bool
	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		var current int64
		if err := tx.QueryRowContext(ctx, `SELECT panel_revision FROM alert_events WHERE id=?`, id).Scan(&current); err != nil {
			return err
		}
		if *req.Through > current {
			rangeError = true
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE alert_events SET panel_read_revision=max(panel_read_revision,?) WHERE id=?`, *req.Through, id); err != nil {
			return err
		}
		var err error
		count, err = unreadCount(r, tx)
		return err
	})
	if err != nil {
		stateError(w, err)
		return
	}
	if rangeError {
		bad(w, "through_revision exceeds the event revision")
		return
	}
	respond(w, 200, map[string]any{"id": id, "unread_count": count})
}
