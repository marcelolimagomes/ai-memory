-- Federated identity mapping and token revocation.
--
-- A validated OIDC token proves *who* the caller is at the IdP. It says
-- nothing about what that caller may do here: capability scopes live on the
-- `users` row (V51), keyed by user_id. This table is the bridge, and without
-- it a federated token would authenticate into a vacuum.
--
-- The key is the (issuer, subject) PAIR, never the subject alone. A `sub` is
-- unique only within its issuer, so accepting it bare would let a second
-- trusted issuer impersonate an identity from the first. The proxy rung
-- already reached this conclusion; `IdentityKey::Subject` encodes it, and this
-- table stores the same shape rather than inventing a second one.
--
-- No secret lives here. A subject is a public identifier, not a credential.

CREATE TABLE federated_identities (
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    user_id     BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Human-facing label for audit ("hermes_worker"). Never consulted for
    -- authorization: capability comes from identity_scopes.
    lane        TEXT,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (issuer, subject)
);

CREATE INDEX idx_federated_identities_user ON federated_identities(user_id);

-- Revocation denylist.
--
-- An access token is valid until it expires; there is no way to un-issue one.
-- Revocation is therefore a local refusal to honour a token that is otherwise
-- cryptographically sound.
--
-- Two granularities, because they answer different incidents: `jti` kills one
-- leaked token, `subject` kills every token an identity holds — which is what
-- an operator needs when the credential itself is compromised and new tokens
-- are still being minted.
--
-- `expires_at` is when the row may be swept, not when the revocation weakens:
-- once the revoked token could no longer be valid anyway, keeping the row buys
-- nothing but table growth.
CREATE TABLE revoked_tokens (
    kind        TEXT NOT NULL CHECK (kind IN ('jti', 'subject')),
    value       TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    reason      TEXT,
    revoked_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (kind, issuer, value)
);

CREATE INDEX idx_revoked_tokens_sweep ON revoked_tokens(expires_at);
