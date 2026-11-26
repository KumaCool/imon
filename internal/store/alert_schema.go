package store

// AlertMigration adds the rule state machine, event history and notification queue.
const AlertMigration = `
CREATE TABLE alert_rules (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES targets(target_id),
  group_name TEXT NOT NULL,
  connection_rev INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  config TEXT NOT NULL CHECK(json_valid(config))
) STRICT;
CREATE INDEX alert_rules_by_target ON alert_rules(target_id, group_name, enabled, connection_rev);
CREATE TABLE rule_state (
  rule_id TEXT PRIMARY KEY REFERENCES alert_rules(id) ON DELETE CASCADE,
  pending_count INTEGER NOT NULL DEFAULT 0,
  pending_start INTEGER NOT NULL DEFAULT 0,
  last_batch TEXT NOT NULL DEFAULT '',
  last_observed INTEGER NOT NULL DEFAULT 0,
  last_pending INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE alert_events (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  target_id TEXT NOT NULL REFERENCES targets(target_id),
  connection_rev INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','recovered','monitoring_stopped','configuration_changed')),
  snapshot TEXT NOT NULL CHECK(json_valid(snapshot)),
  latest_value TEXT NOT NULL CHECK(json_valid(latest_value)),
  observed_at INTEGER NOT NULL,
  triggered_at INTEGER NOT NULL,
  recovered_at INTEGER,
  ended_at INTEGER,
  detail_state TEXT NOT NULL DEFAULT '',
  panel_revision INTEGER NOT NULL DEFAULT 0,
  panel_read_revision INTEGER NOT NULL DEFAULT 0,
  CHECK(panel_read_revision >= 0 AND panel_read_revision <= panel_revision)
) STRICT;
CREATE UNIQUE INDEX alert_one_active_per_rule ON alert_events(rule_id) WHERE status='active';
CREATE INDEX alert_events_trigger_order ON alert_events(triggered_at DESC,id DESC);
CREATE INDEX alert_events_unread ON alert_events(id) WHERE panel_revision > panel_read_revision;
CREATE TABLE notification_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  config TEXT NOT NULL CHECK(json_valid(config))
) STRICT;
INSERT INTO notification_settings VALUES(1,'{"panel":true,"telegram":false,"email":false}');
CREATE TABLE notification_targets (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL CHECK(channel IN ('telegram','email')),
  config TEXT NOT NULL CHECK(json_valid(config))
) STRICT;
CREATE TABLE deliveries (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES alert_events(id),
  phase TEXT NOT NULL CHECK(phase IN ('trigger','recovery')),
  channel TEXT NOT NULL CHECK(channel IN ('panel','telegram','email')),
  address TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('not_selected','disabled','not_configured','delivered','queued','sending','accepted','failed','unknown')),
  detail TEXT NOT NULL DEFAULT '',
  attempts INTEGER NOT NULL DEFAULT 0,
  due_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  config TEXT NOT NULL CHECK(json_valid(config)),
  message TEXT NOT NULL,
  UNIQUE(event_id,phase,channel,address)
) STRICT;
CREATE INDEX deliveries_due ON deliveries(due_at,id) WHERE status='queued';
CREATE INDEX deliveries_event ON deliveries(event_id,phase,channel,address,status);
`
