-- Canonical registry of TaskBlu product executions.
--
-- V50 added correlation columns to ingest_keys: they record which execution an
-- observation *claimed* to belong to. That is evidence, not authorization —
-- the value arrives in a request and nothing proves the caller was entitled to
-- it. This table is the trusted source the identity contract requires: the
-- launcher registers an execution before the lane starts, and the server
-- resolves project and workspace from here rather than from anything the
-- caller sends.
--
-- Why the id is TEXT and caller-supplied: the launcher must know the id before
-- the lane process exists, so it cannot be a value the server invents at
-- registration time. Uniqueness is enforced by the primary key, so a replayed
-- registration collides instead of forking a second execution.
--
-- Nothing here may hold prompts, responses, tool arguments or credentials.
-- Only identifiers and timestamps.

CREATE TABLE executions (
    taskblu_execution_id TEXT NOT NULL PRIMARY KEY,
    -- Identity that owns the execution. An execution registered for one lane
    -- is not usable by another, which is what stops a valid credential from
    -- borrowing someone else's authorization context.
    user_id              BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id         BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id           BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- Effective lane, for attribution. Never consulted for authorization:
    -- capability comes from identity_scopes, not from this label.
    lane                 TEXT,
    -- Optional Paperclip correlation. Never grants anything on its own.
    paperclip_run_id     TEXT,
    created_at           INTEGER NOT NULL,
    -- Hard expiry. An execution that outlives its window stops authorizing
    -- even if nobody closed it, so a crashed launcher cannot leave a
    -- permanently valid context behind.
    expires_at           INTEGER NOT NULL,
    -- Set when the launcher closes the execution. A closed execution is
    -- retained for audit and never authorizes again.
    closed_at            INTEGER
);

-- The workspace/project pair is part of every scope contract; keep it
-- invariant at the database boundary the same way memberships do.
CREATE TRIGGER executions_workspace_project_guard
BEFORE INSERT ON executions
WHEN NEW.workspace_id IS NOT (
    SELECT workspace_id FROM projects WHERE id = NEW.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'executions workspace/project mismatch');
END;

CREATE INDEX idx_executions_user ON executions(user_id, expires_at);
