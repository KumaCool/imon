package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

type connectionInput struct {
	collector.Config
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	TargetID       string `json:"target_id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	KeyFile        string `json:"key_file"`
	HostKey        string `json:"host_key"`
	TestToken      string `json:"test_token"`
	SSHConfirm     string `json:"ssh_confirmation_token"`
	ConnectionRev  int64  `json:"connection_rev"`
	ConfirmUnknown bool   `json:"confirm_unknown"`
}

type binding struct {
	store.Target
	Identity string
	Config   collector.Config
}

type proof struct {
	kind, input, config, identity, targetID string
	revision                                int64
	expires                                 time.Time
}

type sshConfirmation struct {
	input, targetID string
	revision        int64
	config          collector.Config
	expires         time.Time
}

func (in connectionInput) normalized() (kind, ref string, cfg collector.Config, err error) {
	kind, cfg = in.Kind, in.Config
	switch kind {
	case "host":
		if in.Host != "" {
			cfg.SSH = collector.Endpoint{Address: in.Host, Port: in.Port, User: in.User, KeyFile: in.KeyFile}
		}
		cfg.SSH.HostKey = ""
		if cfg.SSH.Port == 0 {
			cfg.SSH.Port = 22
		}
		if cfg.Jump != nil {
			jump := *cfg.Jump
			jump.HostKey = ""
			if jump.Port == 0 {
				jump.Port = 22
			}
			cfg.Jump = &jump
		}
		cfg.Kubeconfig, cfg.Context, cfg.KubeExecSHA256 = "", "", ""
	case "cluster":
		cfg.SSH, cfg.Jump = collector.Endpoint{}, nil
	default:
		return "", "", cfg, errors.New("select host or cluster")
	}
	raw, err := json.Marshal(cfg)
	return kind, string(raw), cfg, err
}

func preserveHostKey(newEndpoint *collector.Endpoint, oldEndpoint *collector.Endpoint) {
	if newEndpoint != nil && oldEndpoint != nil && strings.EqualFold(newEndpoint.Address, oldEndpoint.Address) &&
		(newEndpoint.Port == oldEndpoint.Port || newEndpoint.Port == 22 && oldEndpoint.Port == 0) {
		newEndpoint.HostKey = oldEndpoint.HostKey
	}
}

func (c *Control) expireProofs(now time.Time) {
	for key, value := range c.proofs {
		if !now.Before(value.expires) {
			delete(c.proofs, key)
		}
	}
	for key, value := range c.sshConfirmations {
		if !now.Before(value.expires) {
			delete(c.sshConfirmations, key)
		}
	}
}

func (c *Control) testTarget(w http.ResponseWriter, r *http.Request) {
	var in connectionInput
	if !decode(w, r, &in) {
		return
	}
	kind, ref, cfg, err := in.normalized()
	if err != nil {
		fail(w, 400, "invalid_target", err.Error())
		return
	}
	select {
	case c.probes <- struct{}{}:
		defer func() { <-c.probes }()
	default:
		fail(w, 409, "probe_busy", "连接测试正在执行")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	var old binding
	if in.TargetID != "" {
		old, err = c.target(ctx, in.TargetID)
		if err != nil {
			report(w, err)
			return
		}
		if old.Kind != kind {
			report(w, errIdentity)
			return
		}
		if kind == "host" {
			preserveHostKey(&cfg.SSH, &old.Config.SSH)
			preserveHostKey(cfg.Jump, old.Config.Jump)
		}
	}
	if in.SSHConfirm != "" {
		c.mu.Lock()
		c.expireProofs(time.Now())
		confirmation, ok := c.sshConfirmations[in.SSHConfirm]
		ok = ok && kind == "host" && confirmation.input == ref && confirmation.targetID == in.TargetID && confirmation.revision == old.ConnectionRev
		if ok {
			delete(c.sshConfirmations, in.SSHConfirm)
		}
		c.mu.Unlock()
		if !ok {
			fail(w, 409, "ssh_confirmation_expired", "指纹确认已失效，请重新测试连接")
			return
		}
		cfg = confirmation.config
	}
	identity, warnings, resolved, err := collector.ProbeBinding(ctx, kind, cfg, old.Identity)
	if err != nil {
		var observe *collector.HostKeyConfirmation
		if errors.As(err, &observe) {
			if observe.Role == "jump" {
				jump := *cfg.Jump
				jump.HostKey = observe.Key
				cfg.Jump = &jump
			} else {
				cfg.SSH.HostKey = observe.Key
			}
			token, now := newID(), time.Now()
			c.mu.Lock()
			c.expireProofs(now)
			c.sshConfirmations[token] = sshConfirmation{ref, in.TargetID, old.ConnectionRev, cfg, now.Add(3 * time.Minute)}
			c.mu.Unlock()
			send(w, 409, map[string]any{
				"code": observe.Error(), "message": "首次连接，请核对 SSH 主机指纹", "retryable": false,
				"details": map[string]string{"role": observe.Role, "address": observe.Address, "fingerprint": observe.Fingerprint, "confirmation_token": token},
			})
			return
		}
		code := collectionError(err)
		if code == "identity_changed" {
			report(w, errIdentity)
			return
		}
		fail(w, 400, code, "连接测试失败（"+code+"）")
		return
	}
	raw, err := json.Marshal(resolved)
	if err != nil {
		fail(w, 500, "invalid_target", "连接配置无效")
		return
	}
	token := newID()
	now := time.Now()
	expires := now.Add(3 * time.Minute)
	c.mu.Lock()
	c.expireProofs(now)
	c.proofs[token] = proof{kind, ref, string(raw), identity, in.TargetID, old.ConnectionRev, expires}
	c.mu.Unlock()
	send(w, 200, map[string]any{"test_token": token, "identity": identity, "expires_at": expires.UnixMilli(), "warnings": warnings})
}

func (c *Control) target(ctx context.Context, id string) (binding, error) {
	var b binding
	err := c.db.Read(ctx, func(tx *sql.Tx) error { return readBinding(ctx, tx, id, &b) })
	return b, err
}

func readBinding(ctx context.Context, tx *sql.Tx, id string, b *binding) error {
	b.ID = id
	err := tx.QueryRowContext(ctx, `SELECT kind,name,connection_ref,connection_rev,enabled,identity FROM targets WHERE target_id=? AND enabled=1`, id).
		Scan(&b.Kind, &b.Name, &b.ConnectionRef, &b.ConnectionRev, &b.Enabled, &b.Identity)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if b.ConnectionRef == "" {
		return nil
	}
	return json.Unmarshal([]byte(b.ConnectionRef), &b.Config)
}

func (c *Control) saveTarget(w http.ResponseWriter, r *http.Request) {
	var in connectionInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 {
		fail(w, 400, "invalid_name", "请输入名称（最多 200 字节）")
		return
	}
	id := r.PathValue("id")
	create := id == ""
	if create {
		id = newID()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var p proof
	if create || in.TestToken != "" || in.Host != "" || in.SSH.Address != "" || in.Jump != nil || in.Kubeconfig != "" || in.Context != "" {
		kind, ref, _, err := in.normalized()
		if err != nil {
			fail(w, 400, "invalid_target", err.Error())
			return
		}
		p = c.proofs[in.TestToken]
		if p.kind != kind || p.input != ref || (create && p.targetID != "") || (!create && p.targetID != id) || !time.Now().Before(p.expires) {
			fail(w, 409, "test_required", "请先测试当前连接参数")
			return
		}
	}
	if !create && p.kind == "host" {
		b, err := c.target(r.Context(), id)
		if err != nil {
			report(w, err)
			return
		}
		var replacement collector.Config
		if err := json.Unmarshal([]byte(p.config), &replacement); err != nil {
			report(w, err)
			return
		}
		if b.Kind == "host" && p.revision == b.ConnectionRev && in.ConnectionRev == b.ConnectionRev &&
			p.identity == b.Identity && replacement.SSH.User != b.Config.SSH.User {
			if err := c.checkHostFirewallCleanup(r.Context(), b); err != nil {
				reportFirewallCleanup(w, err)
				return
			}
		}
	}
	var result store.Target
	var changed bool
	err := c.db.Write(r.Context(), func(tx *sql.Tx) error {
		ctx := r.Context()
		if create {
			result = store.Target{ID: id, Kind: p.kind, Name: in.Name, ConnectionRev: 1, Enabled: true}
			_, err := tx.ExecContext(ctx, `INSERT INTO targets(target_id,kind,name,connection_ref,connection_rev,enabled,identity) VALUES(?,?,?,?,1,1,?)`, id, p.kind, in.Name, p.config, p.identity)
			return err
		}
		var old binding
		if err := readBinding(ctx, tx, id, &old); err != nil {
			return err
		}
		if in.ConnectionRev != old.ConnectionRev {
			return errConflict
		}
		result = old.Target
		result.Name = in.Name
		if p.kind != "" {
			if p.revision != old.ConnectionRev {
				return errConflict
			}
			if p.kind != old.Kind || p.identity != old.Identity {
				return errIdentity
			}
			if p.config != old.ConnectionRef {
				if err := checkNoMutation(ctx, tx, id, in.ConfirmUnknown); err != nil {
					return err
				}
				result.ConnectionRef = p.config
				result.ConnectionRev++
				changed = true
				if err := c.invalidate(ctx, tx, id, "configuration_changed"); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE targets SET name=?,connection_ref=?,connection_rev=? WHERE target_id=?`, result.Name, result.ConnectionRef, result.ConnectionRev, id)
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	delete(c.proofs, in.TestToken)
	if create || changed {
		c.due[id] = nil
		c.signal()
		if result.Kind == "host" {
			var cfg collector.Config
			if json.Unmarshal([]byte(p.config), &cfg) == nil {
				c.startFirewallProbe(binding{Target: result, Identity: p.identity, Config: cfg})
			}
		}
	}
	if changed {
		c.cancelCollection(id)
	}
	status := 200
	if create {
		status = 201
	}
	send(w, status, result)
}

func checkNoMutation(ctx context.Context, tx *sql.Tx, id string, confirmUnknown bool) error {
	return checkNoMutationForTarget(ctx, tx, id, confirmUnknown, false)
}

func checkNoMutationForTarget(ctx context.Context, tx *sql.Tx, id string, confirmUnknown, resolveFirewall bool) error {
	var busy, unknown bool
	err := tx.QueryRowContext(ctx, `SELECT coalesce(max(j.status IN ('queued','running')),0),coalesce(max(j.status='unknown' AND (NOT ? OR j.kind<>'firewall')),0)
		FROM collection_jobs j JOIN targets t USING(target_id)
		WHERE j.target_id=? AND j.connection_rev=t.connection_rev AND j.kind<>'collect'`, resolveFirewall, id).Scan(&busy, &unknown)
	if err != nil {
		return err
	}
	if busy {
		return errConflict
	}
	if unknown && !confirmUnknown {
		return errUnconfirmed
	}
	return nil
}

func (c *Control) invalidate(ctx context.Context, tx *sql.Tx, id, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status='canceled',completed_at=?,error_code=? WHERE target_id=? AND kind='collect' AND status IN ('queued','running')`, time.Now().UnixMilli(), reason, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM service_authorizations WHERE target_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM firewall_authorization_observations WHERE target_id=?`, id); err != nil {
		return err
	}
	if c.observer != nil {
		return c.observer.Stop(ctx, tx, id, reason)
	}
	return nil
}

var (
	errFirewallCleanupRequired   = errors.New("firewall cleanup required")
	errFirewallCleanupUnverified = errors.New("firewall cleanup unverified")
)

func reportFirewallCleanup(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errFirewallCleanupRequired):
		fail(w, 409, "firewall_cleanup_required", "请先卸载授权并确认清理结果")
	case errors.Is(err, errFirewallCleanupUnverified):
		fail(w, 409, "firewall_cleanup_unverified", "无法核对目标机上的授权，请在 SSH 连接恢复后重试")
	default:
		report(w, err)
	}
}

func (c *Control) checkHostFirewallCleanup(ctx context.Context, b binding) error {
	var pending, confirmed bool
	if err := c.db.Read(ctx, func(tx *sql.Tx) (err error) {
		pending, err = firewallHasPendingCleanup(ctx, tx, b.ID)
		if err != nil {
			return err
		}
		confirmed, err = firewallCleanupConfirmed(ctx, tx, b.ID, b.ConnectionRev)
		return err
	}); err != nil {
		return err
	}
	if pending {
		return errFirewallCleanupRequired
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	probe, err := collector.DetectFirewall(probeCtx, b.Config, b.Identity)
	if err != nil {
		return errFirewallCleanupUnverified
	}
	if probe.Status == "uninstalled" || probe.Status == "unknown" && probe.MarkersAbsent && confirmed {
		return nil
	}
	return errFirewallCleanupRequired
}

func (c *Control) unbind(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	c.mu.Lock()
	defer c.mu.Unlock()
	var b binding
	var existing string
	job := Job{ID: newID(), TargetID: id, Kind: "firewall", Status: "queued", QueuedAt: time.Now().UnixMilli()}
	err := c.db.Write(ctx, func(tx *sql.Tx) error {
		if err := readBinding(ctx, tx, id, &b); err != nil {
			return err
		}
		host := b.Kind == "host"
		if host {
			err := tx.QueryRowContext(ctx, `SELECT job_id FROM collection_jobs WHERE target_id=? AND connection_rev=?
				AND kind='firewall' AND status IN ('queued','running') AND json_extract(results,'$.unbind_requested')='true'`, id, b.ConnectionRev).Scan(&existing)
			if err == nil || !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if err := checkNoMutationForTarget(ctx, tx, id, r.URL.Query().Get("confirm_unknown") == "true", host); err != nil {
			return err
		}
		if !host {
			return c.unbindTarget(ctx, tx, b)
		}
		if err := insertJob(ctx, tx, job, b.ConnectionRev); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET results=json_object('unbind_requested','true') WHERE job_id=?`, job.ID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO firewall_maintenance(job_id,target_id,connection_rev,action) VALUES(?,?,?,'uninstall')`, job.ID, id, b.ConnectionRev)
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	if b.Kind == "host" {
		if existing == "" {
			existing = job.ID
			c.wg.Go(func() { c.runFirewall(job, b, "uninstall", nil, false, true) })
		}
		send(w, http.StatusAccepted, map[string]string{"job_id": existing})
		return
	}
	c.cancelCollection(id)
	delete(c.due, id)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Control) unbindTarget(ctx context.Context, tx *sql.Tx, b binding) error {
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT connection_rev FROM targets WHERE target_id=? AND enabled=1`, b.ID).Scan(&revision); err != nil {
		return err
	}
	if revision != b.ConnectionRev {
		return errConflict
	}
	if err := c.invalidate(ctx, tx, b.ID, "monitoring_stopped"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM node_links WHERE host_id=? OR cluster_id=?`, b.ID, b.ID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE targets SET enabled=0,connection_rev=connection_rev+1,connection_ref='' WHERE target_id=?`, b.ID)
	return err
}

func (c *Control) kubeExecApproval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kubeconfig string `json:"kubeconfig"`
		Context    string `json:"context"`
	}
	if !decode(w, r, &in) {
		return
	}
	digest, err := collector.KubeExecApproval(in.Kubeconfig, in.Context)
	if err != nil {
		fail(w, 400, collectionError(err), "无法读取此登录插件的配置摘要")
		return
	}
	send(w, 200, map[string]string{"sha256": digest})
}
