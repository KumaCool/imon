package control

import (
	"context"
	"database/sql"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

type collectionRequest struct {
	View     string `json:"view"`
	TargetID string `json:"target_id"`
	Group    string `json:"group"`
	Source   string `json:"source"`
	Cursor   string `json:"cursor"`
	Limit    *int   `json:"limit"`
	DueOnly  bool   `json:"due_only"`
}

type collectionScope struct {
	targets []binding
	kind    string
	view    string
	groups  []string
	all     bool
	next    string
}

func (s collectionScope) matches(id, kind, group string) bool {
	if s.kind != "" && s.kind != kind {
		return false
	}
	if s.view == "services" {
		if kind == "host" && group != "systemd" || kind == "cluster" && group != "deployments" {
			return false
		}
	} else if !slices.Contains(s.groups, group) {
		return false
	}
	return s.all || slices.ContainsFunc(s.targets, func(b binding) bool { return b.ID == id })
}

func (c *Control) collectionScope(ctx context.Context, in collectionRequest, status bool) (scope collectionScope, err error) {
	scope.view = in.View
	limit := 50
	if in.Limit != nil {
		limit = *in.Limit
		if limit < 1 || limit > 200 {
			return scope, errInvalid
		}
	}
	switch in.View {
	case "hosts", "clusters":
		if in.TargetID != "" || in.Group != "" || in.Source != "" {
			return scope, errInvalid
		}
		scope.kind, scope.groups = "host", []string{"host_metrics", "os_info"}
		if in.View == "clusters" {
			scope.kind, scope.groups = "cluster", []string{"nodes", "pods"}
		}
	case "services":
		if in.Group != "" || in.Limit != nil || status && in.Cursor != "" || in.TargetID != "" && in.Cursor != "" || in.Source != "" && in.Source != "host" && in.Source != "cluster" {
			return scope, errInvalid
		}
		limit = 32
		scope.kind = in.Source
		if status && in.TargetID == "" {
			scope.all = true
			return scope, nil
		}
	case "host_metrics", "network", "cluster":
		if in.TargetID == "" || in.Source != "" || in.Cursor != "" || in.Limit != nil {
			return scope, errInvalid
		}
		scope.kind = "host"
		switch in.View {
		case "host_metrics":
			if in.Group != "" {
				return scope, errInvalid
			}
			scope.groups = []string{"host_metrics"}
		case "network":
			if !slices.Contains([]string{"interfaces", "routes", "listeners", "firewall"}, in.Group) {
				return scope, errInvalid
			}
			scope.groups = []string{in.Group}
		case "cluster":
			if !slices.Contains([]string{"namespaces", "deployments", "pods", "services", "nodes"}, in.Group) {
				return scope, errInvalid
			}
			scope.kind, scope.groups = "cluster", []string{in.Group}
		}
	default:
		return scope, errInvalid
	}
	err = c.db.Read(ctx, func(tx *sql.Tx) error {
		if in.TargetID != "" {
			var b binding
			if err := readBinding(ctx, tx, in.TargetID, &b); err != nil {
				return err
			}
			if scope.kind != "" && scope.kind != b.Kind {
				return errInvalid
			}
			scope.targets = []binding{b}
			return nil
		}
		items, err := listTargetRows(ctx, tx, scope.kind, in.Cursor, limit+1)
		if err != nil {
			return err
		}
		if len(items) > limit {
			items = items[:limit]
			scope.next = items[limit-1].ID
		}
		for _, item := range items {
			var b binding
			if status {
				b.Target = item
			} else if err := readBinding(ctx, tx, item.ID, &b); err != nil {
				return err
			}
			scope.targets = append(scope.targets, b)
		}
		return nil
	})
	return scope, err
}

func (c *Control) requestCollection(w http.ResponseWriter, r *http.Request) {
	var in collectionRequest
	if !decode(w, r, &in) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx := r.Context()
	scope, err := c.collectionScope(ctx, in, false)
	if err != nil {
		report(w, err)
		return
	}
	var due map[string]map[string]bool
	if in.DueOnly {
		due = make(map[string]map[string]bool, len(scope.targets))
		if err := c.foregroundGroups(ctx, scope, time.Now(), func(id, group string, state foregroundGroupStatus) {
			if !state.due {
				return
			}
			if due[id] == nil {
				due[id] = make(map[string]bool)
			}
			due[id][group] = true
		}); err != nil {
			report(w, err)
			return
		}
	}
	type jobRef struct {
		TargetID string `json:"target_id"`
		JobID    string `json:"job_id"`
	}
	out := struct {
		Jobs []jobRef `json:"jobs"`
		Next string   `json:"next_cursor,omitempty"`
	}{make([]jobRef, 0, len(scope.targets)), scope.next}
	defer c.signal()
	for _, target := range scope.targets {
		requested := scopeGroups(scope, target.Kind)
		groups := make(map[string]bool, len(requested))
		for _, group := range requested {
			groups[group] = false
		}
		var refs []string
		if in.DueOnly {
			for _, existing := range []*collection{c.active[target.ID], c.queued[target.ID]} {
				if existing != nil && existing.target.ConnectionRev == target.ConnectionRev && slices.ContainsFunc(requested, func(group string) bool {
					_, covered := existing.groups[group]
					return covered
				}) {
					refs = append(refs, existing.job.ID)
				}
			}
			for group := range groups {
				if !due[target.ID][group] {
					delete(groups, group)
				}
			}
		}
		ids, err := c.enqueueGroups(ctx, target, groups, true, true)
		if err != nil {
			report(w, err)
			return
		}
		for _, id := range ids {
			if !slices.Contains(refs, id) {
				refs = append(refs, id)
			}
		}
		for _, id := range refs {
			out.Jobs = append(out.Jobs, jobRef{target.ID, id})
		}
	}
	if len(out.Jobs) == 0 {
		send(w, http.StatusOK, out)
	} else {
		send(w, http.StatusAccepted, out)
	}
}

type collectionProgress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
}

func scopeGroups(scope collectionScope, kind string) []string {
	if scope.view != "services" {
		return scope.groups
	}
	if kind == "host" {
		return []string{"systemd"}
	}
	return []string{"deployments"}
}

type foregroundGroupStatus struct {
	due, pending, inRound bool
	next                  *int64
}

// foregroundGroups reads only the requested groups at each target's current revision.
// Prefer completion time so a slow or failed attempt does not immediately retry.
func (c *Control) foregroundGroups(ctx context.Context, scope collectionScope, now time.Time, visit func(id, group string, state foregroundGroupStatus)) error {
	if !scope.all && len(scope.targets) == 0 {
		return nil
	}
	var pairs []string
	var args []any
	for _, kind := range []string{"host", "cluster"} {
		if scope.kind != "" && kind != scope.kind {
			continue
		}
		for _, group := range scopeGroups(scope, kind) {
			pairs = append(pairs, "(?,?)")
			args = append(args, kind, group)
		}
	}
	query := `WITH requested(kind, group_name) AS (VALUES ` + strings.Join(pairs, ",") + `)
		SELECT t.target_id,t.kind,t.connection_rev,r.group_name,coalesce(b.completed_at,b.started_at)
		FROM targets t JOIN requested r ON r.kind=t.kind
		LEFT JOIN group_state g ON (g.target_id,g.connection_rev,g.group_name)=(t.target_id,t.connection_rev,r.group_name)
		LEFT JOIN snapshot_batches b ON (b.target_id,b.connection_rev,b.group_name,b.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id)
		WHERE t.enabled=1`
	if !scope.all {
		placeholders := make([]string, 0, len(scope.targets))
		for _, target := range scope.targets {
			placeholders = append(placeholders, "?")
			args = append(args, target.ID)
		}
		query += ` AND t.target_id IN (` + strings.Join(placeholders, ",") + `)`
	}
	return c.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, kind, group string
			var rev int64
			var attempted sql.NullInt64
			if err := rows.Scan(&id, &kind, &rev, &group, &attempted); err != nil {
				return err
			}
			state := c.foregroundWork(id, rev, group)
			if !state.pending {
				if !attempted.Valid {
					state.due = true
				} else if c.settings.Enabled {
					next := attempted.Int64 + c.settings.period(kind, group).Milliseconds()
					if next <= now.UnixMilli() {
						state.due = true
					} else {
						state.next = &next
					}
				}
			}
			visit(id, group, state)
		}
		return rows.Err()
	})
}

func (c *Control) foregroundWork(id string, rev int64, group string) (state foregroundGroupStatus) {
	if target := c.round[id]; c.settings.Enabled && target != nil && target.rev == rev {
		if task := target.groups[group]; task != nil {
			state.inRound, state.pending = true, !task.done
		}
	}
	for _, job := range []*collection{c.active[id], c.queued[id]} {
		if job != nil && job.target.ConnectionRev == rev {
			if _, covered := job.groups[group]; covered {
				state.pending = true
			}
		}
	}
	return state
}

func (c *Control) collectionStatus(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for key, values := range q {
		if len(values) != 1 || !slices.Contains([]string{"view", "target_id", "group", "source", "cursor", "limit"}, key) {
			report(w, errInvalid)
			return
		}
	}
	in := collectionRequest{View: q.Get("view"), TargetID: q.Get("target_id"), Group: q.Get("group"), Source: q.Get("source"), Cursor: q.Get("cursor")}
	if q.Has("limit") {
		limit, err := strconv.Atoi(q.Get("limit"))
		if err != nil {
			report(w, errInvalid)
			return
		}
		in.Limit = &limit
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	scope, err := c.collectionScope(r.Context(), in, true)
	if err != nil {
		report(w, err)
		return
	}
	now := time.Now()
	out := struct {
		ServerNow      int64               `json:"server_now"`
		Next           *int64              `json:"next_run_at"`
		Active         *collectionProgress `json:"active"`
		ForegroundDue  bool                `json:"foreground_due"`
		NextForeground *int64              `json:"next_foreground_at"`
	}{ServerNow: now.UnixMilli()}
	pending := map[string]bool{}
	if err := c.foregroundGroups(r.Context(), scope, now, func(id, _ string, state foregroundGroupStatus) {
		out.ForegroundDue = out.ForegroundDue || state.due
		if state.next != nil && (out.NextForeground == nil || *state.next < *out.NextForeground) {
			out.NextForeground = state.next
		}
		if state.inRound || state.pending {
			pending[id] = pending[id] || state.pending
		}
	}); err != nil {
		report(w, err)
		return
	}
	progress := collectionProgress{Total: len(pending)}
	for _, busy := range pending {
		if !busy {
			progress.Completed++
		}
	}
	if progress.Total > progress.Completed {
		out.Active = &progress
	}
	if c.settings.Enabled {
		if out.Active == nil {
			rules, err := c.scheduledRules(r.Context())
			if err != nil {
				report(w, err)
				return
			}
			var first time.Time
			for id, target := range rules {
				for group := range target.groups {
					if !scope.matches(id, target.kind, group) {
						continue
					}
					due := c.effectiveDue(id, group)
					if !due.After(now) {
						if c.round != nil {
							send(w, 200, out)
							return
						}
						due = now
					}
					if first.IsZero() || due.Before(first) {
						first = due
					}
				}
			}
			if !first.IsZero() {
				ms := first.UnixMilli()
				out.Next = &ms
			}
		}
	}
	send(w, 200, out)
}
