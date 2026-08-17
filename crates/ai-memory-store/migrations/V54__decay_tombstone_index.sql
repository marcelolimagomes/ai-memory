-- RENUMBERED IN THIS FORK: upstream shipped this as V49 in v1.26.1, but the
-- Taskblu lineage had already used V49 (project memberships) and V50
-- (execution evidence), and both are applied in the deployed database.
-- Refinery keys its history by version, so two V49s collide outright
-- (UNIQUE constraint failed: refinery_schema_history.version) and renumbering
-- an already-applied migration would break the recorded history of a live
-- database. Moving the newer, never-applied upstream migration is the only
-- direction that costs nothing here.
--
-- Consequence to know when pulling upstream again: a database that ran pure
-- upstream v1.26.1 before switching to this fork would have V49 recorded under
-- the other name. That is not the deployment here, but it is why this comment
-- exists.
--
-- A decay tombstone is identified by superseded_at, the only column written
-- by the forget-sweep eviction path. Rewritten page heads legitimately carry
-- a non-NULL supersedes pointer, so filtering those rows out made their
-- tombstones permanent and left this partial index unusable by the corrected
-- cleanup query.
DROP INDEX idx_pages_evicted;

CREATE INDEX idx_pages_evicted
    ON pages(workspace_id, project_id, superseded_at)
    WHERE is_latest = 0 AND superseded_at IS NOT NULL;
