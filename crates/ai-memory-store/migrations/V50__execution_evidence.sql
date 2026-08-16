-- Metadata-only receipts for cross-component TaskBlu executions.
--
-- The keyed ingest row already commits atomically with its observation, which
-- makes it the correct durable receipt. Keep correlation here rather than in
-- observation bodies: these columns must never contain prompts, responses,
-- tool arguments, credentials, or other captured content.
ALTER TABLE ingest_keys ADD COLUMN taskblu_execution_id TEXT;
ALTER TABLE ingest_keys ADD COLUMN paperclip_run_id TEXT;
ALTER TABLE ingest_keys ADD COLUMN session_id BLOB;
ALTER TABLE ingest_keys ADD COLUMN event_kind TEXT;
ALTER TABLE ingest_keys ADD COLUMN source_event TEXT;
ALTER TABLE ingest_keys ADD COLUMN capture_owner TEXT;
ALTER TABLE ingest_keys ADD COLUMN replay_count INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_ingest_keys_execution
    ON ingest_keys (taskblu_execution_id, seen_at)
    WHERE taskblu_execution_id IS NOT NULL;
