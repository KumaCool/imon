package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"imon/internal/collector"
	"imon/internal/store"
)

func seedFirewallJob(t *testing.T, c *Control, id, target, action, status, code string, results map[string]string) {
	t.Helper()
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		var revision int64
		if err := tx.QueryRow(`SELECT connection_rev FROM targets WHERE target_id=?`, target).Scan(&revision); err != nil {
			return err
		}
		job := Job{ID: id, TargetID: target, Kind: "firewall", Status: "queued", QueuedAt: time.Now().UnixMilli()}
		if err := insertJob(t.Context(), tx, job, revision); err != nil {
			return err
		}
		var stage, digest string
		if status == "awaiting_admin" {
			stage, digest = "/var/tmp/imon-upload.abc12345/firewall-maintain.sh", strings.Repeat("a", 64)
		}
		if _, err := tx.Exec(`INSERT INTO firewall_maintenance(job_id,target_id,connection_rev,action,architecture,stage_path,sha256) VALUES(?,?,?,?,'amd64',?,?)`, id, target, revision, action, stage, digest); err != nil {
			return err
		}
		if status == "queued" || status == "running" {
			data, err := json.Marshal(results)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`UPDATE collection_jobs SET status=?,results=? WHERE job_id=?`, status, string(data), job.ID)
			return err
		}
		return finishJob(t.Context(), tx, job.ID, status, results, code)
	}); err != nil {
		t.Fatal(err)
	}
}

func firewallJobID(t *testing.T, body []byte) string {
	t.Helper()
	var result struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.JobID == "" {
		t.Fatalf("expected job ID, got %s (%v)", body, err)
	}
	return result.JobID
}

func TestFirewallMaintenanceResumesSameAction(t *testing.T) {
	for _, status := range []string{"queued", "running", "awaiting_admin", "unknown"} {
		t.Run(status, func(t *testing.T) {
			c, mux := setupCollection(t)
			seedCollectionTarget(t, c, "fixture", "host")
			if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
				_, err := tx.Exec(`UPDATE targets SET connection_ref='{"ssh":{"user":"fixture"}}' WHERE target_id='fixture'`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			seedFirewallJob(t, c, "previous", "fixture", "install", status, "", nil)
			path := "/api/v1/hosts/fixture/firewall-maintenance"
			w := collectionHTTP(t, mux, "POST", path, `{"action":"install"}`, 202)
			if id := firewallJobID(t, w.Body.Bytes()); id != "previous" {
				t.Fatalf("expected original job, got %s", id)
			}
			w = collectionHTTP(t, mux, "GET", "/api/v1/jobs/previous", "", 200)
			if !strings.Contains(w.Body.String(), fmt.Sprintf(`"status":%q`, status)) || (status == "awaiting_admin" && !strings.Contains(w.Body.String(), `"command"`)) {
				t.Fatalf("expected original status and manual instructions when staged: %s", w.Body.String())
			}
			collectionHTTP(t, mux, "POST", path, `{"action":"install","credential_ref":{"ssh":{"user":"fixture-admin","key_file":"/fixture/admin-key"}}}`, 409)
			if status == "queued" || status == "running" {
				collectionHTTP(t, mux, "POST", path, `{"action":"uninstall"}`, 409)
			} else {
				// Cleanup can supersede a completed but unresolved install.
				w := collectionHTTP(t, mux, "POST", path, `{"action":"uninstall"}`, 202)
				if id := firewallJobID(t, w.Body.Bytes()); id == "previous" {
					t.Fatal("uninstall reused the earlier install job")
				}
				c.wg.Wait()
			}
		})
	}
}

func TestFirewallAuthorizationComparesHelperVersions(t *testing.T) {
	for _, tc := range []struct {
		name, status, installed, available string
		update                             bool
	}{
		{"new application, same helper", "installed", "a", "a", false},
		{"changed helper", "installed", "a", "b", true},
		{"no compatible platform package", "installed", "a", "", false},
		{"absent", "uninstalled", "", "b", false},
		{"native privileges", "native", "", "b", false},
		{"unconfirmed", "unknown", "", "b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := makeFirewallAuthorizationState(collector.MaintenanceResult{Status: tc.status, Version: tc.installed}, tc.available)
			if state.Status != tc.status || state.InstalledVersion != tc.installed || state.AvailableVersion != tc.available || state.UpdateAvailable != tc.update {
				t.Fatalf("unexpected authorization state: %+v", state)
			}
		})
	}
}

func TestFirewallDoesNotReplaceStagedDownloadWithNewVersion(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE targets SET connection_ref='{"ssh":{"user":"fixture"}}' WHERE target_id='fixture'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	seedFirewallJob(t, c, "old-stage", "fixture", "install", "awaiting_admin", "", nil)
	w := collectionHTTP(t, mux, "GET", "/api/v1/jobs/old-stage", "", 200)
	if body := w.Body.String(); !strings.Contains(body, `"command"`) || strings.Contains(body, `"download_path"`) {
		t.Fatalf("old staged script must stay executable without an incorrect download: %s", body)
	}
	collectionHTTP(t, mux, "GET", "/api/v1/jobs/old-stage/firewall-script", "", 404)
}

func TestFirewallVerificationDoesNotCompleteOlderHelperInstall(t *testing.T) {
	c, _ := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedFirewallJob(t, c, "staged", "fixture", "install", "awaiting_admin", "", map[string]string{"requested_version": "new"})
	for _, observation := range []string{"old", "new"} {
		id := "verify-" + observation
		seedFirewallJob(t, c, id, "fixture", "verify", "running", "", nil)
		var paths []string
		status, err := c.finishFirewallMaintenance(t.Context(), Job{ID: id}, binding{Target: store.Target{ID: "fixture", ConnectionRev: 1}}, "verify", "", "",
			collector.MaintenanceResult{Status: "installed", Version: observation}, nil, false, false, func(_ context.Context, path string) error {
				paths = append(paths, path)
				return nil
			})
		if err != nil || status != "success" || (len(paths) > 0) != (observation == "new") {
			t.Fatalf("observation %s: status=%q paths=%v err=%v", observation, status, paths, err)
		}
	}
}

func TestFirewallRemovalOnlyConfirmsAfterStageCleanup(t *testing.T) {
	c, _ := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedFirewallJob(t, c, "abandoned-install", "fixture", "install", "awaiting_admin", "", map[string]string{"requested_version": "new"})
	for _, failed := range []bool{true, false} {
		id := fmt.Sprintf("remove-%t", failed)
		seedFirewallJob(t, c, id, "fixture", "uninstall", "running", "", nil)
		var paths []string
		status, err := c.finishFirewallMaintenance(t.Context(), Job{ID: id}, binding{Target: store.Target{ID: "fixture", ConnectionRev: 1}}, "uninstall", "", "",
			collector.MaintenanceResult{Status: "uninstalled", MarkersAbsent: true}, nil, false, false, func(_ context.Context, path string) error {
				paths = append(paths, path)
				if failed {
					return &collector.Error{Code: "connection_failed"}
				}
				return nil
			})
		if err != nil || (status == "failed") != failed || len(paths) != 1 {
			t.Fatalf("status=%q paths=%v err=%v", status, paths, err)
		}
		if err := c.db.Read(t.Context(), func(tx *sql.Tx) error {
			pending, err := firewallHasPendingCleanup(t.Context(), tx, "fixture")
			if err != nil {
				return err
			}
			confirmed, err := firewallCleanupConfirmed(t.Context(), tx, "fixture", 1)
			if err == nil && (pending != failed || confirmed == failed) {
				t.Errorf("cleanup failed=%t pending=%t confirmed=%t", failed, pending, confirmed)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostUnbindResumesRunningCleanup(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedFirewallJob(t, c, "in-flight", "fixture", "uninstall", "running", "", map[string]string{"unbind_requested": "true"})
	for range 2 {
		w := collectionHTTP(t, mux, "DELETE", "/api/v1/targets/fixture", "", 202)
		if id := firewallJobID(t, w.Body.Bytes()); id != "in-flight" {
			t.Fatalf("expected existing cleanup task, got %s", id)
		}
	}
	collectionHTTP(t, mux, "GET", "/api/v1/targets/fixture", "", 200)
}

func TestHostUnbindKeepsBindingIfStageCleanupFails(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedFirewallJob(t, c, "staged", "fixture", "install", "awaiting_admin", "", nil)
	b, err := c.target(t.Context(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, want string
		status   int
	}{
		{"failed-cleanup", "failed", 200},
		{"successful-cleanup", "success", 404},
	} {
		seedFirewallJob(t, c, tc.id, b.ID, "uninstall", "running", "", map[string]string{"unbind_requested": "true"})
		result := collector.MaintenanceResult{Status: "uninstalled", MarkersAbsent: true}
		status, err := c.finishFirewallMaintenance(t.Context(), Job{ID: tc.id}, b, "uninstall", "", "", result, nil, false, true,
			func(_ context.Context, _ string) error {
				if tc.want == "failed" {
					return &collector.Error{Code: "connection_failed"}
				}
				return nil
			})
		if err != nil || status != tc.want {
			t.Fatalf("cleanup gave %q, %v; want %q", status, err, tc.want)
		}
		collectionHTTP(t, mux, "GET", "/api/v1/targets/fixture", "", tc.status)
	}
}

func TestFirewallPrunePreservesLatestObservationAndStaging(t *testing.T) {
	c, _ := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	seedFirewallJob(t, c, "old-removal", "fixture", "uninstall", "success", "", map[string]string{"firewall_status": "uninstalled", "cleanup_confirmed": "true"})
	seedFirewallJob(t, c, "new-install", "fixture", "install", "success", "", map[string]string{"firewall_status": "installed"})
	seedFirewallJob(t, c, "failed-upload", "fixture", "install", "failed", "connection_failed", nil)
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE collection_jobs SET completed_at=?`, time.Now().Add(-8*24*time.Hour).UnixMilli()); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE firewall_maintenance SET stage_path='/var/tmp/imon-upload.abc12345/firewall-maintain.sh' WHERE job_id='failed-upload'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	c.prune()
	if err := c.db.Read(t.Context(), func(tx *sql.Tx) error {
		var jobs string
		if err := tx.QueryRow(`SELECT group_concat(job_id, ',') FROM (SELECT job_id FROM collection_jobs ORDER BY rowid)`).Scan(&jobs); err != nil {
			return err
		}
		if jobs != "new-install,failed-upload" {
			t.Errorf("prune retained unexpected jobs: %s", jobs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallUploadResumesMatchingOffer(t *testing.T) {
	for _, status := range []string{"queued", "running", "awaiting_admin", "unknown"} {
		t.Run(status, func(t *testing.T) {
			c, mux := setupCollection(t)
			seedCollectionTarget(t, c, "fixture", "host")
			seedFirewallJob(t, c, "old-offer", "fixture", "install", "failed", collector.FirewallAdministratorRequired, nil)
			seedFirewallJob(t, c, "current-offer", "fixture", "install", "failed", collector.FirewallAdministratorRequired, nil)
			seedFirewallJob(t, c, "staging", "fixture", "install", status, "", map[string]string{"upload_only": "true"})
			path := "/api/v1/targets/fixture/maintenance/upload"
			collectionHTTP(t, mux, "POST", path, `{"action":"install","auto_job_id":"old-offer"}`, 409)
			collectionHTTP(t, mux, "POST", path, `{"action":"uninstall","auto_job_id":"current-offer"}`, 409)
			w := collectionHTTP(t, mux, "POST", path, `{"action":"install","auto_job_id":"current-offer"}`, 202)
			if id := firewallJobID(t, w.Body.Bytes()); id != "staging" {
				t.Fatalf("expected the existing staging job, got %s", id)
			}
			w = collectionHTTP(t, mux, "GET", "/api/v1/jobs/old-offer", "", 200)
			if strings.Contains(w.Body.String(), `"manual_upload_available"`) {
				t.Fatalf("superseded job still offers upload: %s", w.Body.String())
			}
		})
	}
}

func TestFirewallFirstInstallNotBlockedByCollection(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture", "host")
	collectionHTTP(t, mux, "POST", "/api/v1/collection-requests", `{"view":"host_metrics","target_id":"fixture"}`, 202)
	// The incomplete synthetic SSH binding fails validation before any network call.
	w := collectionHTTP(t, mux, "POST", "/api/v1/hosts/fixture/firewall-maintenance", `{"action":"install"}`, 202)
	id := firewallJobID(t, w.Body.Bytes())
	c.wg.Wait()
	w = collectionHTTP(t, mux, "GET", "/api/v1/jobs/"+id, "", 200)
	if body := w.Body.String(); !strings.Contains(body, `"status":"failed"`) || strings.Contains(body, `"manual_upload_available"`) {
		t.Fatalf("expected failed first install without a manual upload offer: %s", body)
	}
}

func TestFirewallUploadRequiresMatchingAutomaticJob(t *testing.T) {
	c, mux := setupCollection(t)
	seedCollectionTarget(t, c, "fixture-a", "host")
	seedCollectionTarget(t, c, "fixture-b", "host")
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, id := range []string{"fixture-a", "fixture-b"} {
			if _, err := tx.Exec(`UPDATE targets SET connection_ref='{"ssh":{"user":"fixture"}}' WHERE target_id=?`, id); err != nil {
				return err
			}
		}
		job := Job{ID: "automatic", TargetID: "fixture-a", Kind: "firewall", Status: "queued", QueuedAt: time.Now().UnixMilli()}
		if err := insertJob(t.Context(), tx, job, 1); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO firewall_maintenance(job_id,target_id,connection_rev,action,architecture) VALUES(?,?,1,'install','amd64')`, job.ID, job.TargetID); err != nil {
			return err
		}
		return finishJob(t.Context(), tx, job.ID, "failed", nil, collector.FirewallAdministratorRequired)
	}); err != nil {
		t.Fatal(err)
	}
	w := collectionHTTP(t, mux, "GET", "/api/v1/jobs/automatic", "", 200)
	if body := w.Body.String(); !strings.Contains(body, `"manual_upload_available":true`) || strings.Contains(body, `"command"`) || strings.Contains(body, `"stage_path"`) {
		t.Fatalf("automatic failure must offer upload without staging: %s", body)
	}
	path := "/api/v1/targets/fixture-a/maintenance/upload"
	collectionHTTP(t, mux, "POST", path, `{"action":"install"}`, 400)
	collectionHTTP(t, mux, "POST", path, `{"action":"verify","auto_job_id":"automatic"}`, 400)
	collectionHTTP(t, mux, "POST", path, `{"action":"uninstall","auto_job_id":"automatic"}`, 409)
	collectionHTTP(t, mux, "POST", "/api/v1/targets/fixture-b/maintenance/upload", `{"action":"install","auto_job_id":"automatic"}`, 409)
	// The invalid fixture address prevents any network requests. A failed upload must not consume the offer.
	for range 2 {
		collectionHTTP(t, mux, "POST", path, `{"action":"install","auto_job_id":"automatic"}`, 202)
		c.wg.Wait()
	}
	if err := c.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE targets SET connection_rev=2 WHERE target_id='fixture-a'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	collectionHTTP(t, mux, "POST", path, `{"action":"install","auto_job_id":"automatic"}`, 409)
	w = collectionHTTP(t, mux, "GET", "/api/v1/jobs/automatic", "", 200)
	if strings.Contains(w.Body.String(), `"manual_upload_available"`) {
		t.Fatalf("stale binding still offers upload: %s", w.Body.String())
	}
}
