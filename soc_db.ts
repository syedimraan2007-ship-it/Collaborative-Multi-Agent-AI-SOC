/**
 * Dedicated Native SQLite Database Engine for SOC Platform.
 * Uses Node.js native DatabaseSync (node:sqlite) for zero-dependency,
 * persistent relational storage on disk.
 */

import { DatabaseSync } from 'node:sqlite';
import path from 'path';

const DB_PATH = path.resolve(process.cwd(), 'soc_vault.db');
export const db = new DatabaseSync(DB_PATH);

// Enable Write-Ahead Logging for concurrency & durability
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// Initialize Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_product TEXT,
    event_timestamp TEXT NOT NULL,
    hostname TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    destination_port INTEGER,
    username TEXT,
    process_name TEXT,
    domain TEXT,
    event_category TEXT NOT NULL,
    event_action TEXT NOT NULL,
    event_outcome TEXT NOT NULL,
    severity INTEGER DEFAULT 1,
    tags TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    mitre_technique_id TEXT NOT NULL,
    mitre_technique_name TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    description TEXT NOT NULL,
    triggering_conditions TEXT NOT NULL,
    triggering_event_ids TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    affected_user TEXT,
    affected_host TEXT,
    event_count INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    state TEXT NOT NULL,
    severity TEXT NOT NULL,
    priority INTEGER DEFAULT 3,
    source_alert_ids TEXT,
    correlated_event_ids TEXT,
    affected_hosts TEXT,
    affected_users TEXT,
    affected_ips TEXT,
    timeline_json TEXT,
    findings_json TEXT,
    mitre_mappings_json TEXT,
    risk_assessment_json TEXT,
    recs_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS human_approvals (
    approval_id TEXT PRIMARY KEY,
    recommendation_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    approver_username TEXT NOT NULL,
    status TEXT NOT NULL,
    decision_timestamp TEXT NOT NULL,
    reason TEXT,
    signature TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS response_executions (
    execution_id TEXT PRIMARY KEY,
    recommendation_id TEXT NOT NULL,
    approval_id TEXT,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    dry_run INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    logs_json TEXT
  );

  CREATE TABLE IF NOT EXISTS agent_traces (
    trace_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    sanitized_prompt_summary TEXT,
    sanitized_response_summary TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS control_plane_state (
    entity_type TEXT NOT NULL, -- 'blocked_ip', 'disabled_user', 'isolated_host'
    entity_value TEXT NOT NULL,
    enforced_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (entity_type, entity_value)
  );

  CREATE TABLE IF NOT EXISTS system_config (
    config_key TEXT PRIMARY KEY,
    config_value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

console.log(`[SOC DATABASE] Initialized persistent SQLite database at ${DB_PATH}`);

export function resetDatabase() {
  db.exec(`
    DELETE FROM security_events;
    DELETE FROM detection_alerts;
    DELETE FROM incidents;
    DELETE FROM human_approvals;
    DELETE FROM response_executions;
    DELETE FROM agent_traces;
    DELETE FROM control_plane_state;
  `);
  console.log('[SOC DATABASE] Cleaned all tables. Database restored to fresh state.');
}

