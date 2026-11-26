package control

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"imon/internal/collector"
	"imon/internal/firewall"
	"imon/internal/store"
)

type firewallJob struct {
	Action                string `json:"action"`
	StagePath             string `json:"stage_path,omitempty"`
	SHA256                string `json:"sha256,omitempty"`
	Command               string `json:"command,omitempty"`
	DownloadPath          string `json:"download_path,omitempty"`
	ManualUploadAvailable bool   `json:"manual_upload_available,omitempty"`
	arch                  string
}

type firewallAuthorizationState struct {
	Status                  string `json:"status"`
	InstalledVersion        string `json:"installed_version,omitempty"`
	AvailableVersion        string `json:"available_version,omitempty"`
	InstalledDisplayVersion string `json:"installed_display_version,omitempty"`
	AvailableDisplayVersion string `json:"available_display_version,omitempty"`
	UpdateAvailable         bool   `json:"update_available"`
	MarkersAbsent           bool   `json:"markers_absent,omitempty"`
}

func makeFirewallAuthorizationState(observed collector.MaintenanceResult, available string) firewallAuthorizationState {
	state := firewallAuthorizationState{Status: observed.Status, AvailableVersion: available, MarkersAbsent: observed.MarkersAbsent}
	switch state.Status {
	case "installed":
		state.InstalledVersion = observed.Version
		state.UpdateAvailable = observed.Version != "" && available != "" && observed.Version != available
	case "uninstalled", "native":
	default:
		state.Status = "unknown"
	}
	return state
}

func (c *Control) firewallAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := c.target(ctx, r.PathValue("id"))
	if err == nil && b.Kind != "host" {
		err = store.ErrNotFound
	}
	if err != nil {
		report(w, err)
		return
	}
	observed, appVersion, err := c.readFirewallObservation(ctx, b)
	if errors.Is(err, sql.ErrNoRows) {
		probe := c.startFirewallProbe(b)
		select {
		case <-ctx.Done():
			return
		case <-probe.done:
			observed, appVersion, err = probe.result, probe.appVersion, probe.err
		}
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, collectionError(err), "未能读取主机授权状态")
		return
	}
	version, _ := firewall.Version(observed.Architecture)
	state := makeFirewallAuthorizationState(observed, version)
	state.InstalledDisplayVersion = firewallDisplayVersion(appVersion, state.InstalledVersion)
	state.AvailableDisplayVersion = firewallDisplayVersion(c.version, state.AvailableVersion)
	send(w, http.StatusOK, state)
}

func firewallDisplayVersion(appVersion, digest string) string {
	if digest == "" {
		return ""
	}
	short := digest[:min(5, len(digest))]
	if appVersion == "" {
		return short
	}
	return appVersion + " " + short
}

type firewallProbeKey struct {
	targetID string
	revision int64
}

type firewallProbe struct {
	done       chan struct{}
	result     collector.MaintenanceResult
	appVersion string
	err        error
}

func (c *Control) startFirewallProbe(b binding) *firewallProbe {
	key := firewallProbeKey{b.ID, b.ConnectionRev}
	c.firewallProbeMu.Lock()
	defer c.firewallProbeMu.Unlock()
	if existing := c.firewallProbes[key]; existing != nil {
		return existing
	}
	if c.firewallProbes == nil {
		c.firewallProbes = make(map[firewallProbeKey]*firewallProbe)
	}
	probe := &firewallProbe{done: make(chan struct{})}
	c.firewallProbes[key] = probe
	c.wg.Go(func() {
		defer func() {
			c.firewallProbeMu.Lock()
			delete(c.firewallProbes, key)
			close(probe.done)
			c.firewallProbeMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(c.ctx, 12*time.Second)
		defer cancel()
		probe.result, probe.appVersion, probe.err = c.readFirewallObservation(ctx, b)
		if !errors.Is(probe.err, sql.ErrNoRows) {
			return
		}
		if c.probes != nil {
			select {
			case c.probes <- struct{}{}:
				defer func() { <-c.probes }()
			case <-ctx.Done():
				probe.err = ctx.Err()
				return
			}
		}
		startedAt := time.Now().UnixMilli()
		probe.result, probe.err = collector.DetectFirewall(ctx, b.Config, b.Identity)
		if probe.err != nil {
			return
		}
		probe.appVersion = c.version
		probe.err = c.db.Write(ctx, func(tx *sql.Tx) error {
			if probe.result.Status == "unknown" && probe.result.MarkersAbsent {
				pending, err := firewallHasPendingCleanup(ctx, tx, b.ID)
				if err != nil || pending {
					return err
				}
				confirmed, err := firewallCleanupConfirmed(ctx, tx, b.ID, b.ConnectionRev)
				if err != nil {
					return err
				}
				if confirmed {
					probe.result.Status = "uninstalled"
				}
			}
			return c.recordFirewallObservation(ctx, tx, b, probe.result, startedAt, true)
		})
	})
	return probe
}

func (c *Control) readFirewallObservation(ctx context.Context, b binding) (observed collector.MaintenanceResult, appVersion string, err error) {
	err = c.db.Read(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT status,version,architecture,markers_absent,app_version
			FROM firewall_authorization_observations WHERE target_id=? AND connection_rev=? AND status<>'unknown'`, b.ID, b.ConnectionRev).
			Scan(&observed.Status, &observed.Version, &observed.Architecture, &observed.MarkersAbsent, &appVersion)
	})
	return
}

func (c *Control) recordFirewallObservation(ctx context.Context, tx *sql.Tx, b binding, observed collector.MaintenanceResult, at int64, discovery bool) error {
	if discovery && observed.Status != "installed" && observed.Status != "uninstalled" && observed.Status != "native" {
		return nil // Await a fresh probe if the initial observation was inconclusive.
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO firewall_authorization_observations
		(target_id,connection_rev,status,version,architecture,markers_absent,app_version,observed_at)
		SELECT target_id,connection_rev,?,?,?,?,?,? FROM targets WHERE target_id=? AND connection_rev=? AND enabled=1
		ON CONFLICT(target_id) DO UPDATE SET connection_rev=excluded.connection_rev,status=excluded.status,
			version=CASE WHEN excluded.status='unknown' AND excluded.connection_rev=firewall_authorization_observations.connection_rev
				THEN firewall_authorization_observations.version ELSE excluded.version END,
			architecture=excluded.architecture,markers_absent=excluded.markers_absent,
			app_version=CASE WHEN excluded.connection_rev=firewall_authorization_observations.connection_rev
				AND (excluded.version=firewall_authorization_observations.version OR excluded.status='unknown')
				THEN firewall_authorization_observations.app_version ELSE excluded.app_version END,
			observed_at=excluded.observed_at
		WHERE NOT ? OR excluded.connection_rev<>firewall_authorization_observations.connection_rev
			OR (firewall_authorization_observations.status='unknown' AND excluded.observed_at>firewall_authorization_observations.observed_at)`,
		observed.Status, observed.Version, observed.Architecture, observed.MarkersAbsent, c.version, at, b.ID, b.ConnectionRev, discovery)
	return err
}

func (c *Control) firewallMaintenance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action     string            `json:"action"`
		Credential *collector.Config `json:"credential_ref"`
	}
	if !decode(w, r, &in) {
		return
	}
	c.queueFirewall(w, r, in.Action, in.Credential, "")
}

func (c *Control) firewallUpload(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action    string `json:"action"`
		AutoJobID string `json:"auto_job_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.AutoJobID == "" || (in.Action != "install" && in.Action != "uninstall") {
		report(w, errInvalid)
		return
	}
	c.queueFirewall(w, r, in.Action, nil, in.AutoJobID)
}

func (c *Control) queueFirewall(w http.ResponseWriter, r *http.Request, action string, credential *collector.Config, autoJobID string) {
	if action != "install" && action != "uninstall" && action != "verify" {
		report(w, errInvalid)
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	c.mu.Lock()
	defer c.mu.Unlock()
	var b binding
	var existingJobID string
	job := Job{ID: newID(), TargetID: id, Kind: "firewall", Status: "queued", QueuedAt: time.Now().UnixMilli()}
	err := c.db.Write(ctx, func(tx *sql.Tx) error {
		if err := readBinding(ctx, tx, id, &b); err != nil {
			return err
		}
		if b.Kind != "host" {
			return store.ErrNotFound
		}
		if credential != nil {
			admin := credential.SSH
			if admin.User == "" || admin.User == b.Config.SSH.User || !filepath.IsAbs(admin.KeyFile) || filepath.Clean(admin.KeyFile) == filepath.Clean(b.Config.SSH.KeyFile) {
				return errInvalid
			}
			var ref string
			err := tx.QueryRowContext(ctx, `SELECT credential_ref FROM service_authorizations WHERE target_id=?`, id).Scan(&ref)
			if err == nil {
				var serviceCfg collector.Config
				if err := json.Unmarshal([]byte(ref), &serviceCfg); err != nil {
					return err
				}
				if admin.User == serviceCfg.SSH.User || filepath.Clean(admin.KeyFile) == filepath.Clean(serviceCfg.SSH.KeyFile) {
					return errInvalid
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if autoJobID != "" {
			eligible, err := firewallUploadEligible(ctx, tx, autoJobID, id, b.ConnectionRev, action)
			if err != nil {
				return err
			}
			if !eligible {
				return errConflict
			}
		}
		if action != "verify" && credential == nil {
			// Reopen the outstanding job on an identical request; this does not start another remote operation.
			err := tx.QueryRowContext(ctx, `SELECT j.job_id FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
				WHERE m.target_id=? AND m.connection_rev=? AND m.action=?
				AND j.status IN ('queued','running','unknown','awaiting_admin')
				AND (NOT ? OR json_extract(j.results,'$.upload_only')='true') ORDER BY j.rowid DESC LIMIT 1`,
				id, b.ConnectionRev, action, autoJobID != "").Scan(&existingJobID)
			if err == nil || !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if err := checkNoMutation(ctx, tx, id, true); err != nil {
			return err
		}
		if action == "install" {
			var pending bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
				WHERE m.target_id=? AND m.connection_rev=? AND m.action<>'verify' AND j.status IN ('unknown','awaiting_admin'))`, id, b.ConnectionRev).Scan(&pending); err != nil {
				return err
			}
			if pending {
				return errConflict
			}
		}
		if err := insertJob(ctx, tx, job, b.ConnectionRev); err != nil {
			return err
		}
		if autoJobID != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET results=json_object('upload_only','true') WHERE job_id=?`, job.ID); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO firewall_maintenance(job_id,target_id,connection_rev,action) VALUES(?,?,?,?)`, job.ID, id, b.ConnectionRev, action)
		return err
	})
	if err != nil {
		report(w, err)
		return
	}
	if existingJobID != "" {
		send(w, 202, map[string]string{"job_id": existingJobID})
		return
	}
	c.wg.Go(func() { c.runFirewall(job, b, action, credential, autoJobID != "", false) })
	send(w, 202, map[string]string{"job_id": job.ID})
}

func firewallUploadEligible(ctx context.Context, tx *sql.Tx, jobID, targetID string, revision int64, action string) (bool, error) {
	var eligible bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
		WHERE m.job_id=? AND m.target_id=? AND m.connection_rev=? AND m.action=? AND m.architecture<>''
		AND j.status='failed' AND j.error_code=? AND j.job_id=(SELECT job_id FROM firewall_maintenance latest
		JOIN collection_jobs recent USING(job_id) WHERE latest.target_id=m.target_id AND latest.connection_rev=m.connection_rev
		AND latest.action<>'verify' AND (recent.status='success' OR json_extract(recent.results,'$.upload_only') IS NULL)
		ORDER BY recent.rowid DESC LIMIT 1))`, jobID, targetID, revision, action, collector.FirewallAdministratorRequired).Scan(&eligible)
	return eligible, err
}

func firewallHasPendingCleanup(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var pending bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1
		FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
		WHERE m.target_id=? AND (m.stage_path<>'' OR (
			m.action IN ('install','uninstall') AND j.status IN ('queued','running','awaiting_admin','unknown')
		)))`, id).Scan(&pending)
	return pending, err
}

func firewallCleanupConfirmed(ctx context.Context, tx *sql.Tx, id string, revision int64) (bool, error) {
	var confirmed bool
	err := tx.QueryRowContext(ctx, `SELECT coalesce((
		SELECT coalesce(json_extract(j.results,'$.cleanup_confirmed')='true',0) AND NOT EXISTS (
			SELECT 1 FROM firewall_maintenance newer JOIN collection_jobs newer_job USING(job_id)
			WHERE newer.target_id=m.target_id AND newer.action='install'
				AND newer_job.rowid>j.rowid AND newer_job.status IN ('queued','running','awaiting_admin','unknown')
		)
		FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
		WHERE m.target_id=? AND m.connection_rev=? AND j.status='success'
			AND json_extract(j.results,'$.firewall_status') IN ('installed','uninstalled')
		ORDER BY j.rowid DESC LIMIT 1
	), 0)`, id, revision).Scan(&confirmed)
	return confirmed, err
}

type firewallPendingJob struct {
	id, action, path, version string
}

func (c *Control) firewallPendingJobs(ctx context.Context, b binding, jobID string, includeOtherRevisions bool) ([]firewallPendingJob, error) {
	var pending []firewallPendingJob
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT m.job_id,m.action,m.stage_path,
			coalesce(json_extract(j.results,'$.requested_version'),'')
			FROM firewall_maintenance m JOIN collection_jobs j USING(job_id)
			WHERE m.target_id=? AND m.job_id<>? AND m.action IN ('install','uninstall')
			AND (m.connection_rev=? OR ?)
			AND (m.stage_path<>'' OR j.status IN ('awaiting_admin','unknown')) ORDER BY j.rowid`,
			b.ID, jobID, b.ConnectionRev, includeOtherRevisions)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var entry firewallPendingJob
			if err := rows.Scan(&entry.id, &entry.action, &entry.path, &entry.version); err != nil {
				return err
			}
			pending = append(pending, entry)
		}
		return rows.Err()
	})
	return pending, err
}

func (c *Control) runFirewall(job Job, b binding, action string, admin *collector.Config, uploadOnly, unbind bool) {
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Minute)
	defer cancel()
	if err := c.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE collection_jobs SET status='running' WHERE job_id=? AND status='queued'`, job.ID)
		return err
	}); err != nil {
		return
	}
	var arch string
	var version string
	var script []byte
	var opErr error
	var result collector.MaintenanceResult
	if action == "uninstall" && admin == nil && !uploadOnly {
		// A host with no installed authorization can still have old staged
		// files. Remove those as the collector without requesting privilege.
		observed, err := collector.DetectFirewall(ctx, b.Config, b.Identity)
		if err == nil {
			arch = observed.Architecture
			if unbind && observed.Status == "unknown" && observed.MarkersAbsent {
				opErr = c.db.Read(ctx, func(tx *sql.Tx) error {
					confirmed, err := firewallCleanupConfirmed(ctx, tx, b.ID, b.ConnectionRev)
					if confirmed {
						observed.Status = "uninstalled"
					}
					return err
				})
			}
			if observed.Status == "uninstalled" {
				result = observed
			}
		} else if unbind {
			opErr = err
		}
	}
	if result.Status == "" && opErr == nil && (action != "verify" || admin != nil) {
		if arch == "" {
			arch, opErr = collector.FirewallPlatform(ctx, b.Config, b.Identity)
		}
		if opErr == nil {
			script, opErr = firewall.Script(arch)
			if opErr != nil {
				opErr = &collector.Error{Code: "maintenance_package_unavailable"}
			}
			version, _ = firewall.Version(arch)
		}
	}
	if result.Status == "" && opErr == nil {
		if uploadOnly {
			result, opErr = collector.StageFirewall(ctx, b.Config, b.Identity, action, script)
		} else {
			result, opErr = collector.MaintainFirewall(ctx, b.Config, admin, b.Identity, action, script)
		}
	}
	if arch == "" {
		arch = result.Architecture
	}
	cleanStage := func(ctx context.Context, path string) error {
		return collector.CleanFirewallStage(ctx, b.Config, b.Identity, path)
	}
	status, err := c.finishFirewallMaintenance(ctx, job, b, action, arch, version, result, opErr, uploadOnly, unbind, cleanStage)
	if err == nil && (status == "success" || action == "verify") {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.mu.Lock()
		defer c.mu.Unlock()
		current, err := c.target(finish, b.ID)
		if err == nil && current.ConnectionRev == b.ConnectionRev {
			if _, err = c.enqueue(finish, current, map[string]bool{"firewall": false}, true); err == nil {
				c.signal()
			}
		}
	}
}

func (c *Control) finishFirewallMaintenance(ctx context.Context, job Job, b binding, action, arch, version string,
	result collector.MaintenanceResult, opErr error, uploadOnly, unbind bool, cleanStage func(context.Context, string) error) (string, error) {
	status := "failed"
	facts := map[string]string{}
	if uploadOnly {
		facts["upload_only"] = "true"
	}
	if action == "install" && version != "" {
		facts["requested_version"] = version
	}
	switch result.Status {
	case "verified":
		status = "success"
		facts["firewall_status"] = "installed"
		if action == "uninstall" {
			facts["firewall_status"] = "uninstalled"
		}
	case "installed", "uninstalled":
		status = "success"
		facts["firewall_status"] = result.Status
	case "unknown":
		if action == "verify" && opErr == nil {
			opErr = &collector.Error{Code: "result_unconfirmed"}
		} else if action != "verify" {
			status = "unknown"
		}
	case "awaiting_admin":
		status = "awaiting_admin"
	}
	if result.Version != "" {
		facts["installed_version"] = result.Version
	}
	if status == "success" && action == "install" && (result.Version == "" || result.Version != version) {
		status, opErr = "unknown", &collector.Error{Code: "result_unconfirmed"}
		delete(facts, "firewall_status")
	}
	var cleaned []firewallPendingJob
	if status == "success" && (action == "verify" || action == "uninstall") {
		absent := facts["firewall_status"] == "uninstalled"
		pending, err := c.firewallPendingJobs(ctx, b, job.ID, absent)
		if err != nil {
			status, opErr = "failed", &collector.Error{Code: "storage_unavailable"}
		}
		for _, entry := range pending {
			if !absent && (entry.action != "install" || entry.version != "" && entry.version != result.Version) {
				continue
			}
			if entry.path != "" {
				clean, cancel := context.WithTimeout(ctx, 8*time.Second)
				err := cleanStage(clean, entry.path)
				cancel()
				if err != nil {
					status, opErr = "failed", err
					facts["cleanup_error"] = collectionError(err)
					continue
				}
			}
			cleaned = append(cleaned, entry)
		}
		if absent && status == "success" {
			facts["cleanup_confirmed"] = "true"
		}
	}
	finish, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if unbind {
		facts["unbind_requested"] = "true"
		c.mu.Lock()
		defer c.mu.Unlock()
	}
	var unbound bool
	err := c.db.Write(finish, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(finish, `UPDATE firewall_maintenance SET stage_path=?,sha256=?,architecture=? WHERE job_id=?`, result.StagedPath, result.SHA256, arch, job.ID); err != nil {
			return err
		}
		for _, entry := range cleaned {
			if _, err := tx.ExecContext(finish, `UPDATE firewall_maintenance SET stage_path='' WHERE job_id=?`, entry.id); err != nil {
				return err
			}
			resolution := "success"
			if facts["firewall_status"] == "uninstalled" && entry.action == "install" {
				resolution = "canceled"
			}
			verified, err := json.Marshal(map[string]string{
				"firewall_status": facts["firewall_status"], "staging_cleaned": strconv.FormatBool(entry.path != ""),
			})
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(finish, `UPDATE collection_jobs SET status=?,error_code='',results=?,completed_at=?
				WHERE job_id=? AND status IN ('awaiting_admin','unknown')`,
				resolution, string(verified), time.Now().UnixMilli(), entry.id); err != nil {
				return err
			}
		}
		if unbind && status == "success" {
			if facts["cleanup_confirmed"] != "true" || result.StagedPath != "" {
				status, opErr = "failed", &collector.Error{Code: "result_unconfirmed"}
			} else {
				if err := c.unbindTarget(finish, tx, b); err != nil {
					return err
				}
				facts["unbound"], unbound = "true", true
			}
		}
		if !unbound && (status == "success" || status == "unknown") {
			observed := collector.MaintenanceResult{Status: facts["firewall_status"], Version: result.Version, Architecture: arch, MarkersAbsent: result.MarkersAbsent}
			if status != "success" {
				observed.Status = "unknown"
			}
			if err := c.recordFirewallObservation(finish, tx, b, observed, time.Now().UnixMilli(), false); err != nil {
				return err
			}
		}
		return finishJob(finish, tx, job.ID, status, facts, collectionError(opErr))
	})
	if err == nil && unbound {
		c.cancelCollection(b.ID)
		delete(c.due, b.ID)
	}
	if err != nil && unbind {
		// Keep the binding when the local transaction could not commit.
		_ = c.db.Write(finish, func(tx *sql.Tx) error {
			return finishJob(finish, tx, job.ID, "failed", map[string]string{"unbind_requested": "true"}, "storage_unavailable")
		})
	}
	return status, err
}

func (c *Control) firewallDetails(ctx context.Context, tx *sql.Tx, id string, details *firewallJob) (string, error) {
	var collectorUser, targetID string
	var revision int64
	var sameBinding bool
	var status, errorCode string
	err := tx.QueryRowContext(ctx, `SELECT m.action,m.stage_path,m.sha256,m.architecture,coalesce(json_extract(nullif(t.connection_ref,''),'$.ssh.user'),''),t.enabled AND t.connection_rev=m.connection_rev,j.status,j.error_code,m.target_id,m.connection_rev
		FROM firewall_maintenance m JOIN targets t ON t.target_id=m.target_id JOIN collection_jobs j USING(job_id) WHERE m.job_id=?`, id).
		Scan(&details.Action, &details.StagePath, &details.SHA256, &details.arch, &collectorUser, &sameBinding, &status, &errorCode, &targetID, &revision)
	if err != nil {
		return "", err
	}
	if sameBinding && status == "awaiting_admin" && details.StagePath != "" {
		details.Command = collector.FirewallAdminCommand(details.Action, collectorUser, details.StagePath, details.SHA256)
	}
	if details.arch != "" {
		if details.SHA256 == "" {
			details.DownloadPath = "/api/v1/jobs/" + id + "/firewall-script"
		} else if _, err := firewallScriptForJob(details.arch, details.SHA256); err == nil {
			details.DownloadPath = "/api/v1/jobs/" + id + "/firewall-script"
		}
		if sameBinding && status == "failed" && errorCode == collector.FirewallAdministratorRequired {
			details.ManualUploadAvailable, err = firewallUploadEligible(ctx, tx, id, targetID, revision, details.Action)
			if err != nil {
				return "", err
			}
		}
	}
	return collectorUser, nil
}

func firewallScriptForJob(arch, expected string) ([]byte, error) {
	script, err := firewall.Script(arch)
	if err != nil {
		return nil, store.ErrNotFound
	}
	if expected != "" {
		digest := sha256.Sum256(script)
		if hex.EncodeToString(digest[:]) != expected {
			return nil, store.ErrNotFound
		}
	}
	return script, nil
}

func (c *Control) downloadFirewall(w http.ResponseWriter, r *http.Request) {
	var details firewallJob
	ctx := r.Context()
	err := c.db.Read(ctx, func(tx *sql.Tx) error { _, err := c.firewallDetails(ctx, tx, r.PathValue("id"), &details); return err })
	if err != nil {
		report(w, err)
		return
	}
	script, err := firewallScriptForJob(details.arch, details.SHA256)
	if err != nil {
		report(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="firewall-maintain.sh"`)
	_, _ = w.Write(script)
}
