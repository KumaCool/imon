package store

var migrations = []string{
	`CREATE TABLE targets (
		target_id TEXT PRIMARY KEY NOT NULL,
		kind TEXT NOT NULL CHECK (kind IN ('host', 'cluster')),
		name TEXT NOT NULL,
		connection_ref TEXT NOT NULL,
		connection_rev INTEGER NOT NULL CHECK (connection_rev >= 1),
		enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
	) STRICT;
	CREATE INDEX targets_enabled_id ON targets (enabled, target_id);

	CREATE TABLE snapshot_batches (
		target_id TEXT NOT NULL REFERENCES targets (target_id),
		connection_rev INTEGER NOT NULL CHECK (connection_rev >= 1),
		group_name TEXT NOT NULL,
		batch_id TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('staging', 'ok', 'failed', 'interrupted')),
		started_at INTEGER NOT NULL,
		completed_at INTEGER,
		observed_at INTEGER,
		error_code TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (target_id, connection_rev, group_name, batch_id)
	) STRICT;
	CREATE UNIQUE INDEX snapshot_staging_group ON snapshot_batches (target_id, connection_rev, group_name)
		WHERE status = 'staging';

	CREATE TABLE group_state (
		target_id TEXT NOT NULL REFERENCES targets (target_id),
		connection_rev INTEGER NOT NULL,
		group_name TEXT NOT NULL,
		attempt_batch_id TEXT NOT NULL,
		published_batch_id TEXT,
		PRIMARY KEY (target_id, connection_rev, group_name),
		FOREIGN KEY (target_id, connection_rev, group_name, attempt_batch_id)
			REFERENCES snapshot_batches (target_id, connection_rev, group_name, batch_id),
		FOREIGN KEY (target_id, connection_rev, group_name, published_batch_id)
			REFERENCES snapshot_batches (target_id, connection_rev, group_name, batch_id)
	) STRICT;

	CREATE TABLE snapshot_rows (
		target_id TEXT NOT NULL,
		connection_rev INTEGER NOT NULL,
		group_name TEXT NOT NULL,
		batch_id TEXT NOT NULL,
		object_key TEXT NOT NULL,
		payload TEXT NOT NULL CHECK (json_valid(payload)),
		PRIMARY KEY (target_id, connection_rev, group_name, batch_id, object_key),
		FOREIGN KEY (target_id, connection_rev, group_name, batch_id)
			REFERENCES snapshot_batches (target_id, connection_rev, group_name, batch_id)
	) STRICT;`,
	runtimeMigration,
	AlertMigration,
	`CREATE TABLE firewall_authorization_observations (
		target_id TEXT PRIMARY KEY REFERENCES targets(target_id),
		connection_rev INTEGER NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('installed', 'uninstalled', 'unknown')),
		version TEXT NOT NULL,
		architecture TEXT NOT NULL,
		markers_absent INTEGER NOT NULL CHECK (markers_absent IN (0, 1)),
		app_version TEXT NOT NULL,
		observed_at INTEGER NOT NULL
	) STRICT;`,
	`CREATE TABLE firewall_authorization_observations_v2 (
		target_id TEXT PRIMARY KEY REFERENCES targets(target_id),
		connection_rev INTEGER NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('installed', 'uninstalled', 'native', 'unknown')),
		version TEXT NOT NULL,
		architecture TEXT NOT NULL,
		markers_absent INTEGER NOT NULL CHECK (markers_absent IN (0, 1)),
		app_version TEXT NOT NULL,
		observed_at INTEGER NOT NULL
	) STRICT;
	INSERT INTO firewall_authorization_observations_v2
		(target_id,connection_rev,status,version,architecture,markers_absent,app_version,observed_at)
		SELECT target_id,connection_rev,status,version,architecture,markers_absent,app_version,observed_at
		FROM firewall_authorization_observations;
	DROP TABLE firewall_authorization_observations;
	ALTER TABLE firewall_authorization_observations_v2 RENAME TO firewall_authorization_observations;`,
}
