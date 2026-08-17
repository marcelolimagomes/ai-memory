-- Project authorization foundation.
--
-- Membership is deliberately separate from users and projects: one user may
-- belong to many projects and each project may have many users. The active
-- flag is a reversible suspension; rows remain for audit/provenance.

CREATE TABLE project_memberships (
    user_id       BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id  BLOB NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id    BLOB NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('viewer','contributor','curator','owner')),
    active        INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (user_id, workspace_id, project_id)
);

CREATE INDEX idx_project_memberships_project
    ON project_memberships(workspace_id, project_id, active, role);

CREATE INDEX idx_project_memberships_user
    ON project_memberships(user_id, active);

-- Project ids are globally unique, but the paired workspace id is part of
-- every scope contract. Keep the pair invariant at the database boundary.
CREATE TRIGGER project_memberships_workspace_project_guard
BEFORE INSERT ON project_memberships
WHEN NEW.workspace_id IS NOT (
    SELECT workspace_id FROM projects WHERE id = NEW.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'project_memberships workspace/project mismatch');
END;

CREATE TRIGGER project_memberships_workspace_project_update_guard
BEFORE UPDATE OF workspace_id, project_id ON project_memberships
WHEN NEW.workspace_id IS NOT (
    SELECT workspace_id FROM projects WHERE id = NEW.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'project_memberships workspace/project mismatch');
END;

