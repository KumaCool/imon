package control

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

type targetView struct {
	store.Target
	Address                     string            `json:"address,omitempty"`
	LastSuccessAt               *int64            `json:"last_success_at"`
	ProbeObservedAt             *int64            `json:"probe_observed_at"`
	ConnectionStatus            string            `json:"connection_status"`
	ErrorCode                   string            `json:"error_code,omitempty"`
	Summary                     map[string]any    `json:"summary"`
	NodeLink                    map[string]string `json:"node_link,omitempty"`
	FirewallStatus              string            `json:"firewall_status,omitempty"`
	FirewallAuthorizationStatus string            `json:"firewall_authorization_status,omitempty"`
	Stale                       bool              `json:"stale"`
}

type targetDetail struct {
	targetView
	Config targetDetailConfig `json:"config"`
}

type targetDetailConfig struct {
	SSH        *collector.Endpoint `json:"ssh,omitempty"`
	Jump       *collector.Endpoint `json:"jump,omitempty"`
	Kubeconfig string              `json:"kubeconfig,omitempty"`
	Context    string              `json:"context,omitempty"`
}

func (c *Control) listTargets(w http.ResponseWriter, r *http.Request) {
	limit, ok := intLimit(r)
	if !ok {
		report(w, errInvalid)
		return
	}
	ctx := r.Context()
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != "host" && kind != "cluster" {
		report(w, errInvalid)
		return
	}
	settings := c.samplingSettings()
	views := make([]targetView, 0, limit)
	var next string
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		items, err := listTargetRows(ctx, tx, kind, r.URL.Query().Get("cursor"), limit+1)
		if err != nil {
			return err
		}
		if len(items) > limit {
			items = items[:limit]
			next = items[limit-1].ID
		}
		for _, item := range items {
			v, err := enrich(ctx, tx, item, settings)
			if err != nil {
				return err
			}
			views = append(views, v)
		}
		return nil
	})
	if err != nil {
		report(w, err)
		return
	}
	send(w, 200, map[string]any{"items": views, "next_cursor": next})
}

func listTargetRows(ctx context.Context, tx *sql.Tx, kind, after string, limit int) ([]store.Target, error) {
	rows, err := tx.QueryContext(ctx, `SELECT target_id,kind,name,connection_rev,enabled FROM targets
		WHERE enabled=1 AND target_id>? AND (?='' OR kind=?) ORDER BY target_id LIMIT ?`, after, kind, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]store.Target, 0, limit)
	for rows.Next() {
		var t store.Target
		if err := rows.Scan(&t.ID, &t.Kind, &t.Name, &t.ConnectionRev, &t.Enabled); err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return items, rows.Err()
}

func (c *Control) getTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	settings := c.samplingSettings()
	var v targetDetail
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		var b binding
		if err := readBinding(ctx, tx, r.PathValue("id"), &b); err != nil {
			return err
		}
		var err error
		v.targetView, err = enrich(ctx, tx, b.Target, settings)
		if b.Kind == "host" {
			b.Config.SSH.HostKey = ""
			if b.Config.Jump != nil {
				b.Config.Jump.HostKey = ""
			}
			v.Config = targetDetailConfig{SSH: &b.Config.SSH, Jump: b.Config.Jump}
		} else {
			v.Config = targetDetailConfig{Kubeconfig: b.Config.Kubeconfig, Context: b.Config.Context}
		}
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	send(w, 200, v)
}

func (c *Control) samplingSettings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings
}

func enrich(ctx context.Context, tx *sql.Tx, t store.Target, settings Settings) (targetView, error) {
	v := targetView{Target: t, ConnectionStatus: "pending", Summary: map[string]any{}}
	if t.Kind == "host" {
		err := tx.QueryRowContext(ctx, `SELECT CASE WHEN json_valid(connection_ref)
			THEN coalesce(json_extract(connection_ref,'$.ssh.address'),'') ELSE '' END
			FROM targets WHERE target_id=? AND connection_rev=? AND enabled=1`, t.ID, t.ConnectionRev).Scan(&v.Address)
		if err != nil {
			return v, err
		}
	}
	var reachable bool
	err := tx.QueryRowContext(ctx, `SELECT observed_at,reachable,error_code FROM target_probe WHERE target_id=? AND connection_rev=?`, t.ID, t.ConnectionRev).
		Scan(&v.ProbeObservedAt, &reachable, &v.ErrorCode)
	switch {
	case err == nil && reachable:
		v.ConnectionStatus = "success"
	case err == nil:
		v.ConnectionStatus = "unreachable"
	case !errors.Is(err, sql.ErrNoRows):
		return v, err
	}
	err = tx.QueryRowContext(ctx, `SELECT max(b.observed_at) FROM group_state g JOIN snapshot_batches b ON (b.target_id,b.connection_rev,b.group_name,b.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id) WHERE g.target_id=? AND g.connection_rev=?`, t.ID, t.ConnectionRev).Scan(&v.LastSuccessAt)
	if err != nil {
		return v, err
	}
	summaryGroups := []string{"host_metrics"}
	if t.Kind == "host" {
		var cluster, uid, clusterName, nodeName, linkStatus string
		err = tx.QueryRowContext(ctx, `SELECT l.cluster_id,l.node_uid,t.name,coalesce(json_extract(r.payload,'$.name'),''),
			CASE WHEN r.object_key IS NOT NULL THEN 'linked' WHEN g.published_batch_id IS NOT NULL THEN 'missing' ELSE 'pending' END
			FROM node_links l JOIN targets t ON t.target_id=l.cluster_id AND t.enabled=1
			LEFT JOIN group_state g ON g.target_id=t.target_id AND g.connection_rev=t.connection_rev AND g.group_name='nodes'
			LEFT JOIN snapshot_rows r ON (r.target_id,r.connection_rev,r.group_name,r.batch_id,r.object_key)=
				(g.target_id,g.connection_rev,g.group_name,g.published_batch_id,l.node_uid)
			WHERE l.host_id=?`, t.ID).Scan(&cluster, &uid, &clusterName, &nodeName, &linkStatus)
		if err == nil {
			v.NodeLink = map[string]string{"cluster_id": cluster, "cluster_name": clusterName, "node_uid": uid, "node_name": nodeName, "status": linkStatus}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return v, err
		}
		var cpu, mem, disk *float64
		err = tx.QueryRowContext(ctx, `SELECT max(json_extract(r.payload,'$.cpu_percent')),max(json_extract(r.payload,'$.memory_percent')),max(json_extract(r.payload,'$.disk_percent')) FROM group_state g JOIN snapshot_rows r ON (r.target_id,r.connection_rev,r.group_name,r.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id) WHERE g.target_id=? AND g.connection_rev=? AND g.group_name='host_metrics'`, t.ID, t.ConnectionRev).Scan(&cpu, &mem, &disk)
		if err != nil {
			return v, err
		}
		v.Summary["cpu_percent"], v.Summary["memory_percent"], v.Summary["disk_percent"] = cpu, mem, disk
		if err := addHostUsage(ctx, tx, t, settings, v.Summary); err != nil {
			return v, err
		}
		err = tx.QueryRowContext(ctx, `SELECT CASE WHEN b.status='ok' THEN 'readable' ELSE 'unreadable' END FROM group_state g JOIN snapshot_batches b ON (b.target_id,b.connection_rev,b.group_name,b.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id) WHERE g.target_id=? AND g.connection_rev=? AND g.group_name='firewall'`, t.ID, t.ConnectionRev).Scan(&v.FirewallStatus)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return v, err
		}
		// The firewall collection result and the maintenance helper state are
		// intentionally separate.  The former says whether the last read
		// worked; the latter drives the install/uninstall action in the list.
		err = tx.QueryRowContext(ctx, `SELECT status FROM firewall_authorization_observations WHERE target_id=? AND connection_rev=?`, t.ID, t.ConnectionRev).Scan(&v.FirewallAuthorizationStatus)
		if errors.Is(err, sql.ErrNoRows) {
			// Keep the status empty until the dedicated authorization probe has
			// classified the host. A readable firewall snapshot alone cannot
			// distinguish native privilege from the installed helper.
			err = nil
		} else if err != nil {
			return v, err
		}
	} else {
		summaryGroups = []string{"nodes", "pods"}
		q := `SELECT CASE WHEN g.published_batch_id IS NOT NULL THEN count(r.object_key) END, CASE WHEN g.published_batch_id IS NOT NULL THEN coalesce(sum(CASE WHEN %s THEN 1 ELSE 0 END),0) END FROM group_state g LEFT JOIN snapshot_rows r ON (r.target_id,r.connection_rev,r.group_name,r.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id) WHERE g.target_id=? AND g.connection_rev=? AND g.group_name=?`
		var count, ready, abnormal *int64
		metricQuery := func(condition string) string { return fmt.Sprintf(q, condition) }
		if err := tx.QueryRowContext(ctx, metricQuery(`json_extract(r.payload,'$.ready')='True'`), t.ID, t.ConnectionRev, "nodes").Scan(&count, &ready); err != nil {
			return v, err
		}
		if err := tx.QueryRowContext(ctx, metricQuery(`json_extract(r.payload,'$.abnormal')=1`), t.ID, t.ConnectionRev, "pods").Scan(new(*int64), &abnormal); err != nil {
			return v, err
		}
		v.Summary["nodes_total"], v.Summary["nodes_ready"], v.Summary["abnormal_pods"] = count, ready, abnormal
	}
	if err := addServiceObservation(ctx, tx, t, settings, v.Summary); err != nil {
		return v, err
	}
	for _, group := range summaryGroups {
		var at int64
		var status string
		err := tx.QueryRowContext(ctx, `SELECT p.observed_at,a.status FROM group_state g
			JOIN snapshot_batches p ON (p.target_id,p.connection_rev,p.group_name,p.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
			JOIN snapshot_batches a ON (a.target_id,a.connection_rev,a.group_name,a.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id)
			WHERE g.target_id=? AND g.connection_rev=? AND g.group_name=?`, t.ID, t.ConnectionRev, group).Scan(&at, &status)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return v, err
		}
		v.Stale = v.Stale || observationStale(&at, status, settings, t.Kind, group)
	}
	return v, nil
}

func (c *Control) nodeLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClusterID string `json:"cluster_id"`
		NodeUID   string `json:"node_uid"`
	}
	if r.Method == http.MethodPut && !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	err := c.db.Write(ctx, func(tx *sql.Tx) error {
		var b binding
		if err := readBinding(ctx, tx, id, &b); err != nil {
			return err
		}
		if b.Kind != "host" {
			return store.ErrNotFound
		}
		if r.Method == http.MethodDelete {
			_, err := tx.ExecContext(ctx, `DELETE FROM node_links WHERE host_id=?`, id)
			return err
		}
		var k binding
		if err := readBinding(ctx, tx, req.ClusterID, &k); err != nil {
			return err
		}
		if k.Kind != "cluster" {
			return errInvalid
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM group_state g JOIN snapshot_rows s ON (s.target_id,s.connection_rev,s.group_name,s.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id) WHERE g.target_id=? AND g.connection_rev=? AND g.group_name='nodes' AND s.object_key=?)`, k.ID, k.ConnectionRev, req.NodeUID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return store.ErrNotFound
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM node_links WHERE cluster_id=? AND node_uid=? AND host_id<>?)`, k.ID, req.NodeUID, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return errConflict
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO node_links(host_id,cluster_id,node_uid) VALUES(?,?,?) ON CONFLICT(host_id) DO UPDATE SET cluster_id=excluded.cluster_id,node_uid=excluded.node_uid`, id, k.ID, req.NodeUID)
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func intLimit(r *http.Request) (int, bool) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 50, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 1 && n <= 200
}
func encodeCursor(v any) string {
	if v == nil {
		return ""
	}
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}
func decodeCursor(raw string, out any) error {
	if len(raw) > 4096 {
		return errInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(decoded, out) != nil {
		return errInvalid
	}
	return nil
}

type snapshotView struct {
	store.SnapshotPage
	NextCursor  any      `json:"next_cursor"`
	Stale       bool     `json:"stale"`
	PollEnabled bool     `json:"poll_enabled"`
	History     []sample `json:"history,omitempty"`
}

func (c *Control) snapshot(r *http.Request, b binding, group string) (snapshotView, error) {
	limit, ok := intLimit(r)
	if !ok {
		return snapshotView{}, errInvalid
	}
	s := c.samplingSettings()
	var cursor *store.SnapshotCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor = &store.SnapshotCursor{}
		if err := decodeCursor(raw, cursor); err != nil {
			return snapshotView{}, err
		}
	}
	var namespace string
	if b.Kind == "cluster" && slices.Contains([]string{"deployments", "pods", "services"}, group) {
		namespace = r.URL.Query().Get("namespace")
	}
	ctx := r.Context()
	var page store.SnapshotPage
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		var err error
		page, err = store.ReadSnapshotTx(ctx, tx, b.ID, group, namespace, cursor, limit)
		if err != nil {
			return err
		}
		if page.ConnectionRev != b.ConnectionRev {
			return store.ErrStaleTarget
		}
		if len(page.Rows) == 0 || b.Kind != "cluster" {
			return nil
		}
		switch group {
		case "namespaces":
			return enrichNamespaces(ctx, tx, b.ID, &page)
		case "nodes":
			return enrichNodes(ctx, tx, b.ID, &page)
		default:
			return nil
		}
	})
	if err != nil {
		return snapshotView{}, err
	}
	var next any
	if page.Next != nil {
		next = encodeCursor(page.Next)
	}
	v := snapshotView{SnapshotPage: page, NextCursor: next, PollEnabled: s.Enabled}
	var status string
	if page.Attempt != nil {
		status = page.Attempt.Status
	}
	v.Stale = observationStale(page.ObservedAt, status, s, b.Kind, group)
	return v, nil
}

func observationStale(at *int64, status string, settings Settings, kind, group string) bool {
	return at == nil || settings.Enabled && time.Since(time.UnixMilli(*at)) > 2*settings.period(kind, group) ||
		status == "failed" || status == "interrupted"
}

func enrichNamespaces(ctx context.Context, tx *sql.Tx, targetID string, page *store.SnapshotPage) error {
	names := make([]string, len(page.Rows))
	payloads := make([]map[string]any, len(page.Rows))
	for i, row := range page.Rows {
		if err := json.Unmarshal(row.Payload, &payloads[i]); err != nil {
			return err
		}
		names[i], _ = payloads[i]["name"].(string)
	}
	for _, resource := range []struct{ group, field string }{
		{"deployments", "deployment_count"}, {"pods", "pod_count"}, {"services", "service_count"},
	} {
		counts, err := namespaceCounts(ctx, tx, targetID, page, resource.group, names)
		if err != nil {
			return err
		}
		for i, payload := range payloads {
			payload[resource.field] = nil
			if counts != nil {
				payload[resource.field] = counts[names[i]]
			}
		}
	}
	for i, payload := range payloads {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		page.Rows[i].Payload = raw
	}
	return nil
}

func namespaceCounts(ctx context.Context, tx *sql.Tx, targetID string, page *store.SnapshotPage, group string, names []string) (map[string]int64, error) {
	var complete bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM group_state
		WHERE target_id=? AND connection_rev=? AND group_name=? AND published_batch_id=?)`,
		targetID, page.ConnectionRev, group, page.BatchID).Scan(&complete); err != nil || !complete {
		return nil, err
	}
	namesJSON, err := json.Marshal(names)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT json_extract(payload,'$.namespace'), count(*) FROM snapshot_rows
		WHERE target_id=? AND connection_rev=? AND group_name=? AND batch_id=?
		AND json_extract(payload,'$.namespace') IN (SELECT value FROM json_each(?))
		GROUP BY json_extract(payload,'$.namespace')`, targetID, page.ConnectionRev, group, page.BatchID, string(namesJSON))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int64, len(names))
	for rows.Next() {
		var name string
		var count int64
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		counts[name] = count
	}
	return counts, rows.Err()
}

func enrichNodes(ctx context.Context, tx *sql.Tx, targetID string, page *store.SnapshotPage) error {
	keys := make([]string, len(page.Rows))
	for i, row := range page.Rows {
		keys[i] = row.ObjectKey
	}
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT l.node_uid,t.target_id,t.name FROM node_links l
		JOIN targets t ON t.target_id=l.host_id AND t.enabled=1
		WHERE l.cluster_id=? AND l.node_uid IN (SELECT value FROM json_each(?))`, targetID, string(keysJSON))
	if err != nil {
		return err
	}
	defer rows.Close()
	type hostLink struct{ id, name string }
	links := make(map[string]hostLink)
	for rows.Next() {
		var uid string
		var host hostLink
		if err := rows.Scan(&uid, &host.id, &host.name); err != nil {
			return err
		}
		links[uid] = host
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i, row := range page.Rows {
		host, ok := links[row.ObjectKey]
		if !ok {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal(row.Payload, &payload); err != nil {
			return err
		}
		payload["host_id"], payload["host_name"] = host.id, host.name
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		page.Rows[i].Payload = raw
	}
	return nil
}

func (c *Control) network(w http.ResponseWriter, r *http.Request) {
	c.readGroup(w, r, "host", []string{"interfaces", "routes", "listeners", "firewall"})
}
func (c *Control) resources(w http.ResponseWriter, r *http.Request) {
	c.readGroup(w, r, "cluster", collector.Groups("cluster"))
}
func (c *Control) readGroup(w http.ResponseWriter, r *http.Request, kind string, groups []string) {
	b, err := c.target(r.Context(), r.PathValue("id"))
	if err != nil {
		report(w, err)
		return
	}
	group := r.PathValue("group")
	if b.Kind != kind || !slices.Contains(groups, group) {
		report(w, store.ErrNotFound)
		return
	}
	v, err := c.snapshot(r, b, group)
	if err != nil {
		report(w, err)
		return
	}
	send(w, 200, v)
}

type number struct {
	Metric, Dimension string
	Value             float64
}

func metricValues(in collector.Row) []number {
	var item map[string]any
	if json.Unmarshal(in.Data, &item) != nil {
		return nil
	}
	dim, _ := item["name"].(string)
	var out []number
	for _, metric := range []string{"cpu_percent", "memory_percent", "disk_percent", "available_bytes", "total_bytes", "rx_bytes_per_second", "tx_bytes_per_second"} {
		if metric == "total_bytes" && in.Key == "memory" {
			continue
		}
		if value, ok := item[metric].(float64); ok {
			out = append(out, number{metric, dim, value})
		}
	}
	return out
}
func writeSamples(ctx context.Context, tx *sql.Tx, key store.SnapshotKey, at time.Time, rows []collector.Row) error {
	for _, r := range rows {
		for _, v := range metricValues(r) {
			if _, err := tx.ExecContext(ctx, `INSERT INTO performance_samples VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`, key.TargetID, key.ConnectionRev, v.Metric, v.Dimension, key.BatchID, at.UnixMilli(), v.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

type sample struct {
	Metric    string  `json:"metric"`
	Dimension string  `json:"dimension"`
	At        int64   `json:"at"`
	Value     float64 `json:"value"`
	Max       float64 `json:"max"`
}

func (c *Control) metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := c.target(ctx, r.PathValue("id"))
	if err != nil {
		report(w, err)
		return
	}
	if b.Kind != "host" {
		report(w, store.ErrNotFound)
		return
	}
	v, err := c.snapshot(r, b, "host_metrics")
	if err != nil {
		report(w, err)
		return
	}
	to, from := time.Now().UnixMilli(), time.Now().Add(-time.Hour).UnixMilli()
	for k, d := range map[string]*int64{"from": &from, "to": &to} {
		if raw := r.URL.Query().Get(k); raw != "" {
			*d, err = strconv.ParseInt(raw, 10, 64)
			if err != nil {
				report(w, errInvalid)
				return
			}
		}
	}
	if from < 0 || to <= from || to-from > (30*24*time.Hour).Milliseconds() {
		report(w, errInvalid)
		return
	}
	width := max((to-from+599)/600, 1)
	err = c.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT metric,dimension,?3+((observed_at-?3)/?5)*?5,avg(value),max(value) FROM performance_samples WHERE target_id=?1 AND connection_rev=?2 AND observed_at>=?3 AND observed_at<?4 GROUP BY metric,dimension,(observed_at-?3)/?5 ORDER BY metric,dimension,3 LIMIT 30001`, b.ID, b.ConnectionRev, from, to, width)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p sample
			if err := rows.Scan(&p.Metric, &p.Dimension, &p.At, &p.Value, &p.Max); err != nil {
				return err
			}
			v.History = append(v.History, p)
		}
		return rows.Err()
	})
	if err != nil {
		report(w, err)
		return
	}
	if len(v.History) > 30000 {
		fail(w, 400, "range_too_large", "请缩短趋势范围")
		return
	}
	send(w, 200, v)
}
