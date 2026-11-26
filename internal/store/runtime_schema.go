package store

const runtimeMigration = `
ALTER TABLE targets ADD COLUMN identity TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshot_batches ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
CREATE TABLE sampling_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), poll_enabled INTEGER NOT NULL, host_interval INTEGER NOT NULL,
 network_interval INTEGER NOT NULL, cluster_interval INTEGER NOT NULL, timeout INTEGER NOT NULL, revision INTEGER NOT NULL
) STRICT;
INSERT INTO sampling_settings VALUES (1,1,60,300,60,45,1);
CREATE TABLE collection_jobs (
 job_id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(target_id), connection_rev INTEGER NOT NULL,
 kind TEXT NOT NULL, status TEXT NOT NULL, queued_at INTEGER NOT NULL, completed_at INTEGER,
 results TEXT NOT NULL DEFAULT '{}', error_code TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX collection_finished ON collection_jobs(completed_at);
CREATE TABLE target_probe (
 target_id TEXT PRIMARY KEY REFERENCES targets(target_id), connection_rev INTEGER NOT NULL,
 observed_at INTEGER NOT NULL, reachable INTEGER NOT NULL, error_code TEXT NOT NULL
) STRICT;
CREATE TABLE firewall_maintenance (
 job_id TEXT PRIMARY KEY REFERENCES collection_jobs(job_id) ON DELETE CASCADE,
 target_id TEXT NOT NULL, connection_rev INTEGER NOT NULL, action TEXT NOT NULL,
 stage_path TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL DEFAULT '', architecture TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE TABLE node_links (
 host_id TEXT PRIMARY KEY REFERENCES targets(target_id), cluster_id TEXT NOT NULL REFERENCES targets(target_id),
 node_uid TEXT NOT NULL, UNIQUE(cluster_id,node_uid)
) STRICT;
CREATE TABLE performance_samples (
 target_id TEXT NOT NULL REFERENCES targets(target_id), connection_rev INTEGER NOT NULL,
 metric TEXT NOT NULL, dimension TEXT NOT NULL, batch_id TEXT NOT NULL, observed_at INTEGER NOT NULL,
 value REAL NOT NULL, PRIMARY KEY(target_id,connection_rev,metric,dimension,batch_id)
) STRICT;
CREATE INDEX performance_time ON performance_samples(target_id,connection_rev,observed_at);
CREATE TABLE sampling_baselines (
 target_id TEXT NOT NULL REFERENCES targets(target_id), connection_rev INTEGER NOT NULL,
 source TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(target_id,connection_rev,source)
) STRICT;
CREATE TABLE service_authorizations (
 target_id TEXT PRIMARY KEY REFERENCES targets(target_id), connection_rev INTEGER NOT NULL,
 credential_ref TEXT NOT NULL, object_ids TEXT NOT NULL
) STRICT;
CREATE TABLE deployment_resume (
 target_id TEXT NOT NULL REFERENCES targets(target_id), connection_rev INTEGER NOT NULL, uid TEXT NOT NULL,
 replicas INTEGER NOT NULL, PRIMARY KEY(target_id,connection_rev,uid)
) STRICT;
CREATE TABLE service_action_details (
 job_id TEXT PRIMARY KEY REFERENCES collection_jobs(job_id) ON DELETE CASCADE,
 object_id TEXT NOT NULL, action TEXT NOT NULL, expected_state TEXT NOT NULL,
 expected_desired INTEGER, replicas INTEGER, attempted INTEGER NOT NULL DEFAULT 0, acknowledged INTEGER NOT NULL DEFAULT 0
) STRICT;
`
