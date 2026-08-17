-- Capability scopes granted to an identity.
--
-- Separate from project_memberships on purpose: membership answers "which
-- projects may this identity touch", a scope answers "which class of operation
-- may it perform at all". A lane credential with `memory:read` and owner-level
-- membership on a project still may not write — the two gates are conjunctive.
--
-- An identity with NO rows here is unscoped, which the server reads as the
-- historical unrestricted behaviour. That keeps the capability opt-in per
-- credential: granting the first scope is what starts enforcing, and it is a
-- deliberate operator action rather than a side effect of an upgrade.
--
-- Rows carry no secret. The credential itself lives only as a hash in `users`.

CREATE TABLE identity_scopes (
    user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope       TEXT NOT NULL CHECK (scope IN (
                    'memory:read',
                    'memory:handoff.accept',
                    'memory:write',
                    'memory:curate',
                    'memory:admin'
                )),
    granted_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, scope)
);

CREATE INDEX idx_identity_scopes_user ON identity_scopes(user_id);
