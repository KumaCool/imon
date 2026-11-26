package control

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

const servicesSQL = `SELECT t.target_id,t.kind,t.name,t.connection_rev,r.object_key,r.payload,p.observed_at,(a.status IS NULL OR a.status<>'ok'),a.error_code,
 coalesce(ga.object_ids,'[]'),dr.replicas
 FROM targets t JOIN group_state g ON (g.target_id,g.connection_rev)=(t.target_id,t.connection_rev)
 JOIN snapshot_rows r ON (r.target_id,r.connection_rev,r.group_name,r.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
 JOIN snapshot_batches p ON (p.target_id,p.connection_rev,p.group_name,p.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.published_batch_id)
 LEFT JOIN snapshot_batches a ON (a.target_id,a.connection_rev,a.group_name,a.batch_id)=(g.target_id,g.connection_rev,g.group_name,g.attempt_batch_id)
 LEFT JOIN service_authorizations ga ON ga.target_id=t.target_id AND ga.connection_rev=t.connection_rev
 LEFT JOIN deployment_resume dr ON dr.target_id=t.target_id AND dr.connection_rev=t.connection_rev AND dr.uid=r.object_key
 WHERE t.enabled=1 AND g.group_name=CASE t.kind WHEN 'host' THEN 'systemd' ELSE 'deployments' END `

type service struct {
	ID             string   `json:"id"`
	TargetID       string   `json:"target_id"`
	TargetName     string   `json:"target_name"`
	Source         string   `json:"source"`
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace,omitempty"`
	UID            string   `json:"uid,omitempty"`
	Unit           string   `json:"unit,omitempty"`
	State          *string  `json:"state"`
	Ready          *int32   `json:"ready,omitempty"`
	Desired        *int32   `json:"desired,omitempty"`
	ConnectionRev  int64    `json:"connection_rev"`
	ObservedAt     int64    `json:"observed_at"`
	Stale          bool     `json:"stale"`
	Authorized     bool     `json:"authorized"`
	ResumeReplicas *int32   `json:"resume_replicas,omitempty"`
	CPUPercent     *float64 `json:"cpu_percent,omitempty"`
	MemoryBytes    *uint64  `json:"memory_bytes,omitempty"`
	Error          *string  `json:"error_code,omitempty"`
	ObjectKey      string   `json:"object_key"`
}

type rowScanner interface{ Scan(...any) error }

func readService(row rowScanner, s Settings) (service, error) {
	var v service
	var data, ids string
	if err := row.Scan(&v.TargetID, &v.Source, &v.TargetName, &v.ConnectionRev, &v.ObjectKey, &data, &v.ObservedAt, &v.Stale, &v.Error, &ids, &v.ResumeReplicas); err != nil {
		return v, err
	}
	var p struct {
		Name, Namespace string
		State           *string
		Desired, Ready  *int32
		CPUPercent      *float64 `json:"cpu_percent"`
		MemoryBytes     *uint64  `json:"memory_bytes"`
	}
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return v, err
	}
	v.Name, v.Namespace, v.State, v.Desired, v.Ready = p.Name, p.Namespace, p.State, p.Desired, p.Ready
	v.CPUPercent, v.MemoryBytes = p.CPUPercent, p.MemoryBytes
	if v.Source == "host" {
		v.Unit = v.ObjectKey
	} else {
		v.UID = v.ObjectKey
	}
	v.ID = v.TargetID + "." + base64.RawURLEncoding.EncodeToString([]byte(v.ObjectKey))
	var allowed []string
	if err := json.Unmarshal([]byte(ids), &allowed); err != nil {
		return v, err
	}
	v.Authorized = slices.Contains(allowed, v.ID)
	v.Stale = v.Stale || s.Enabled && time.Since(time.UnixMilli(v.ObservedAt)) > 2*s.period(v.Source, "systemd")
	return v, nil
}

type serviceCursor struct {
	Sort      string `json:"sort,omitempty"`
	Direction string `json:"direction,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

func serviceSort(q url.Values) (field, direction string, valid bool) {
	field = q.Get("sort")
	if field == "" {
		field = "name"
	}
	direction = strings.ToLower(q.Get("direction"))
	if direction == "" {
		direction = "asc"
	}
	switch field {
	case "name", "target", "state", "cpu", "memory":
		return field, direction, direction == "asc" || direction == "desc"
	}
	return field, direction, false
}

func (c *Control) services(w http.ResponseWriter, r *http.Request) {
	limit, ok := intLimit(r)
	if !ok {
		report(w, errInvalid)
		return
	}
	q := r.URL.Query()
	var cursor serviceCursor
	if raw := q.Get("cursor"); raw != "" {
		if err := decodeCursor(raw, &cursor); err != nil {
			report(w, err)
			return
		}
	}
	sortField, direction, validSort := serviceSort(q)
	if !validSort || cursor.Offset < 0 || q.Get("cursor") != "" && (cursor.Sort != sortField || cursor.Direction != direction) {
		report(w, errInvalid)
		return
	}
	c.mu.Lock()
	settings := c.settings
	c.mu.Unlock()
	items := make([]service, 0, limit+1)
	orderBy := map[string]string{
		"name":   "lower(json_extract(r.payload,'$.name'))",
		"target": "lower(t.name)",
		"state":  "lower(json_extract(r.payload,'$.state'))",
		"cpu":    "json_extract(r.payload,'$.cpu_percent')",
		"memory": "json_extract(r.payload,'$.memory_bytes')",
	}[sortField]
	directionSQL := strings.ToUpper(direction)
	ctx := r.Context()
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		query := servicesSQL + ` AND (?1='' OR t.kind=?1) AND (?2='' OR t.kind='host' AND t.target_id=?2)
	 AND (?3='' OR t.kind='cluster' AND t.target_id=?3) AND (?4='' OR json_extract(r.payload,'$.namespace')=?4)
	 AND (?5='' OR json_extract(r.payload,'$.state')=?5) AND (?6='' OR instr(lower(json_extract(r.payload,'$.name')),lower(?6))>0)
	 ORDER BY CASE WHEN ` + orderBy + ` IS NULL THEN 1 ELSE 0 END, ` + orderBy + ` ` + directionSQL + `, t.target_id ` + directionSQL + `, r.object_key ` + directionSQL + ` LIMIT ?7 OFFSET ?8`
		rows, err := tx.QueryContext(ctx, query, q.Get("source"), q.Get("host_id"), q.Get("cluster_id"), q.Get("namespace"), q.Get("state"), q.Get("q"), limit+1, cursor.Offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := readService(rows, settings)
			if err != nil {
				return err
			}
			items = append(items, v)
		}
		return rows.Err()
	})
	if err != nil {
		report(w, err)
		return
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(serviceCursor{Sort: sortField, Direction: direction, Offset: cursor.Offset + limit})
	}
	send(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func findService(ctx context.Context, tx *sql.Tx, id string, s Settings) (service, error) {
	target, encoded, ok := strings.Cut(id, ".")
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if !ok || target == "" || len(key) == 0 || err != nil {
		return service{}, store.ErrNotFound
	}
	v, err := readService(tx.QueryRowContext(ctx, servicesSQL+` AND t.target_id=? AND r.object_key=?`, target, string(key)), s)
	if err == nil && v.ID != id {
		return service{}, store.ErrNotFound
	}
	return v, err
}

func (c *Control) getService(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c.mu.Lock()
	s := c.settings
	c.mu.Unlock()
	var v service
	err := c.db.Read(ctx, func(tx *sql.Tx) error { var err error; v, err = findService(ctx, tx, r.PathValue("id"), s); return err })
	if err != nil {
		report(w, err)
		return
	}
	send(w, 200, v)
}

type grant struct {
	Revision          int64            `json:"connection_rev"`
	Credential        collector.Config `json:"credential_ref"`
	Objects           []string         `json:"object_ids"`
	ExternalConfirmed bool             `json:"external_manager_checked"`
}

func separateCredentials(b binding, cfg *collector.Config) bool {
	if b.Kind == "host" {
		user, keyFile := cfg.SSH.User, cfg.SSH.KeyFile
		if user == "" || user == b.Config.SSH.User || !filepath.IsAbs(keyFile) || filepath.Clean(keyFile) == filepath.Clean(b.Config.SSH.KeyFile) {
			return false
		}
		*cfg = b.Config
		cfg.SSH.User, cfg.SSH.KeyFile = user, keyFile
		return true
	}
	if !filepath.IsAbs(cfg.Kubeconfig) || filepath.Clean(cfg.Kubeconfig) == filepath.Clean(b.Config.Kubeconfig) {
		return false
	}
	cfg.SSH, cfg.Jump = collector.Endpoint{}, nil
	return true
}

func (c *Control) authorization(w http.ResponseWriter, r *http.Request) {
	id, ctx := r.PathValue("id"), r.Context()
	var g grant
	if r.Method == http.MethodGet {
		var raw string
		err := c.db.Read(ctx, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT a.connection_rev,a.object_ids,t.kind='cluster' FROM service_authorizations a JOIN targets t USING(target_id) WHERE a.target_id=? AND t.enabled=1 AND a.connection_rev=t.connection_rev`, id).Scan(&g.Revision, &raw, &g.ExternalConfirmed)
		})
		if err != nil {
			report(w, err)
			return
		}
		if err := json.Unmarshal([]byte(raw), &g.Objects); err != nil {
			report(w, err)
			return
		}
		send(w, 200, map[string]any{"connection_rev": g.Revision, "object_ids": g.Objects, "external_manager_checked": g.ExternalConfirmed})
		return
	}
	if r.Method == http.MethodPut && !decode(w, r, &g) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.db.Write(ctx, func(tx *sql.Tx) error {
		var b binding
		if err := readBinding(ctx, tx, id, &b); err != nil {
			return err
		}
		if err := checkNoMutation(ctx, tx, id, true); err != nil {
			return err
		}
		if r.Method == http.MethodDelete {
			_, err := tx.ExecContext(ctx, `DELETE FROM service_authorizations WHERE target_id=?`, id)
			return err
		}
		if g.Revision != b.ConnectionRev {
			return errConflict
		}
		if len(g.Objects) == 0 || b.Kind == "cluster" && !g.ExternalConfirmed || !separateCredentials(b, &g.Credential) {
			return errInvalid
		}
		for _, id := range g.Objects {
			v, err := findService(ctx, tx, id, c.settings)
			if err != nil {
				return err
			}
			if v.TargetID != b.ID || v.Source == "host" && !collector.ValidSystemdServiceUnit(v.Unit) {
				return errInvalid
			}
		}
		ref, _ := json.Marshal(g.Credential)
		ids, _ := json.Marshal(g.Objects)
		_, err := tx.ExecContext(ctx, `INSERT INTO service_authorizations(target_id,connection_rev,credential_ref,object_ids) VALUES(?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET connection_rev=excluded.connection_rev,credential_ref=excluded.credential_ref,object_ids=excluded.object_ids`, b.ID, b.ConnectionRev, string(ref), string(ids))
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type actionInput struct {
	Action          string `json:"action"`
	Rev             int64  `json:"connection_rev"`
	State           string `json:"expected_state"`
	ExpectedDesired *int32 `json:"expected_desired"`
	Replicas        *int32 `json:"replicas"`
	ConfirmUnknown  bool   `json:"confirm_unknown"`
}

func (c *Control) serviceAction(w http.ResponseWriter, r *http.Request) {
	var in actionInput
	if !decode(w, r, &in) {
		return
	}
	if in.Action != "start" && in.Action != "stop" {
		report(w, errInvalid)
		return
	}
	ctx := r.Context()
	c.mu.Lock()
	defer c.mu.Unlock()
	var v service
	var b binding
	var ref string
	var cfg collector.Config
	job := Job{ID: newID(), Kind: "service_action", Status: "queued", QueuedAt: time.Now().UnixMilli()}
	var duplicate string
	err := c.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		v, err = findService(ctx, tx, r.PathValue("id"), c.settings)
		if err != nil {
			return err
		}
		if !v.Authorized {
			return errForbidden
		}
		if v.ConnectionRev != in.Rev || v.Stale || v.State == nil || *v.State != in.State {
			return errConflict
		}
		if in.Action == "stop" && in.State != "running" || in.Action == "start" && in.State != "stopped" && in.State != "failed" {
			return errInvalid
		}
		if v.Source == "cluster" {
			if in.ExpectedDesired == nil || v.Desired == nil || *in.ExpectedDesired != *v.Desired {
				return errConflict
			}
			if in.Action == "start" {
				if *v.Desired != 0 {
					return errInvalid
				}
				if v.ResumeReplicas != nil {
					if in.Replicas != nil {
						return errInvalid
					}
					in.Replicas = v.ResumeReplicas
				}
				if in.Replicas == nil || *in.Replicas < 1 {
					return errInvalid
				}
			} else if in.Replicas != nil || *v.Desired < 1 {
				return errInvalid
			}
		} else if in.ExpectedDesired != nil || in.Replicas != nil {
			return errInvalid
		}
		err = tx.QueryRowContext(ctx, `SELECT j.job_id FROM collection_jobs j JOIN service_action_details d USING(job_id) WHERE j.target_id=? AND j.connection_rev=? AND j.status IN ('queued','running') AND d.object_id=? AND d.action=? AND d.expected_state=? AND d.expected_desired IS ? AND d.replicas IS ?`, v.TargetID, v.ConnectionRev, v.ID, in.Action, in.State, in.ExpectedDesired, in.Replicas).Scan(&duplicate)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := checkNoMutation(ctx, tx, v.TargetID, in.ConfirmUnknown); err != nil {
			return err
		}
		if err := readBinding(ctx, tx, v.TargetID, &b); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT credential_ref FROM service_authorizations WHERE target_id=? AND connection_rev=?`, b.ID, b.ConnectionRev).Scan(&ref); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(ref), &cfg); err != nil {
			return err
		}
		if !separateCredentials(b, &cfg) {
			return errForbidden
		}
		if in.ConfirmUnknown {
			if _, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status='failed',error_code='operator_acknowledged' WHERE target_id=? AND status='unknown'`, v.TargetID); err != nil {
				return err
			}
		}
		job.TargetID = b.ID
		if err := insertJob(ctx, tx, job, b.ConnectionRev); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO service_action_details(job_id,object_id,action,expected_state,expected_desired,replicas) VALUES(?,?,?,?,?,?)`, job.ID, v.ID, in.Action, in.State, in.ExpectedDesired, in.Replicas)
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	if duplicate != "" {
		job.ID = duplicate
	} else {
		c.wg.Go(func() { c.runAction(job, b, cfg, ref, v, in) })
	}
	send(w, 202, map[string]string{"job_id": job.ID})
}

func (c *Control) runAction(job Job, b binding, cfg collector.Config, ref string, v service, in actionInput) {
	ctx, cancel := context.WithTimeout(c.ctx, 55*time.Second)
	defer cancel()
	startErr := c.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status='running' WHERE job_id=? AND status='queued'`, job.ID)
		return err
	})
	if startErr != nil {
		return
	}
	req := collector.ActionRequest{Action: in.Action, Key: v.ObjectKey, Name: v.Name, Namespace: v.Namespace, ExpectedState: in.State, ExpectedDesired: in.ExpectedDesired, Replicas: in.Replicas}
	result, actionErr := collector.RunServiceAction(ctx, b.Kind, cfg, b.Identity, req, func(old int32) error {
		return c.db.Write(ctx, func(tx *sql.Tx) error {
			var current binding
			if err := readBinding(ctx, tx, b.ID, &current); err != nil {
				return err
			}
			if current.ConnectionRev != b.ConnectionRev {
				return store.ErrStaleTarget
			}
			var currentRef, raw string
			if err := tx.QueryRowContext(ctx, `SELECT credential_ref,object_ids FROM service_authorizations WHERE target_id=? AND connection_rev=?`, b.ID, b.ConnectionRev).Scan(&currentRef, &raw); err != nil {
				return err
			}
			var ids []string
			if json.Unmarshal([]byte(raw), &ids) != nil || currentRef != ref || !slices.Contains(ids, v.ID) {
				return errForbidden
			}
			_, err := tx.ExecContext(ctx, `UPDATE service_action_details SET attempted=1 WHERE job_id=?`, job.ID)
			return err
		})
	})
	status := "failed"
	if result.Confirmed {
		status = "success"
	} else if result.Sent {
		status = "unknown"
	} else if c.ctx.Err() != nil {
		status = "canceled"
	}
	ctxCommit, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	err := c.db.Write(ctxCommit, func(tx *sql.Tx) error {
		if result.Confirmed {
			if _, err := tx.ExecContext(ctxCommit, `UPDATE service_action_details SET acknowledged=1 WHERE job_id=?`, job.ID); err != nil {
				return err
			}
			if b.Kind == "cluster" && in.Action == "stop" && result.PreviousDesired != nil {
				if _, err := tx.ExecContext(ctxCommit, `INSERT INTO deployment_resume VALUES(?,?,?,?) ON CONFLICT(target_id,connection_rev,uid) DO UPDATE SET replicas=excluded.replicas`, b.ID, b.ConnectionRev, v.UID, *result.PreviousDesired); err != nil {
					return err
				}
			} else if b.Kind == "cluster" && in.Action == "start" {
				if _, err := tx.ExecContext(ctxCommit, `DELETE FROM deployment_resume WHERE target_id=? AND connection_rev=? AND uid=?`, b.ID, b.ConnectionRev, v.UID); err != nil {
					return err
				}
			}
		}
		facts := map[string]string{}
		if result.State != "" {
			facts["observed_state"] = result.State
		}
		if result.Confirmed && result.Desired != nil {
			facts["convergence"] = "pending"
		}
		return finishJob(ctxCommit, tx, job.ID, status, facts, collectionError(actionErr))
	})
	if err == nil && result.Sent {
		c.refreshAction(ctxCommit, b)
	}
	if err == nil && result.Confirmed && result.Desired != nil {
		check, cancel := context.WithTimeout(c.ctx, time.Minute)
		state, err := collector.WaitDeployment(check, cfg, b.Identity, req, *result.Desired)
		cancel()
		final := map[string]string{"convergence": "not_confirmed"}
		if state != "" {
			final["observed_state"] = state
			final["convergence"] = "confirmed"
			if state == "failed" {
				final["convergence"] = "workload_failed"
			}
		}
		if err != nil {
			final["convergence_error"] = collectionError(err)
		}
		raw, _ := json.Marshal(final)
		commit, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := c.db.Write(commit, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(commit, `UPDATE collection_jobs SET results=? WHERE job_id=? AND status='success'`, string(raw), job.ID)
			return err
		}); err == nil && state != "" {
			c.refreshAction(commit, b)
		}
	}
}

func (c *Control) refreshAction(ctx context.Context, b binding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.target(ctx, b.ID)
	if err == nil && c.ctx.Err() == nil && current.ConnectionRev == b.ConnectionRev {
		group := "systemd"
		if b.Kind == "cluster" {
			group = "deployments"
		}
		if _, err = c.enqueue(ctx, current, map[string]bool{group: false}, true); err == nil {
			c.signal()
		}
	}
}
