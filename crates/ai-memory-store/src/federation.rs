//! Federated identity mapping and token revocation.
//!
//! Two small tables with one job each. `federated_identities` answers "which
//! local identity is this OIDC subject?", and `revoked_tokens` answers "should
//! I refuse this token even though its signature is fine?".
//!
//! Both are keyed by issuer. A subject is unique only inside its issuer, so a
//! lookup that ignored the issuer would let a second trusted IdP mint an
//! identity belonging to the first.

use ai_memory_core::UserId;
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{StoreError, StoreResult};

/// A federated identity, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    /// Exact `iss` value the token must carry.
    pub issuer: String,
    /// Exact `sub` value.
    pub subject: String,
    /// Local identity carrying the capability scopes.
    pub user_id: UserId,
    /// Lane label for audit; never consulted for authorization.
    pub lane: Option<String>,
}

/// What a revocation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationKind {
    /// One specific token, by its `jti`.
    Jti,
    /// Every token belonging to a subject.
    Subject,
}

impl RevocationKind {
    /// Stable database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jti => "jti",
            Self::Subject => "subject",
        }
    }
}

/// Bind an OIDC `(issuer, subject)` to a local identity. Idempotent.
pub fn upsert_identity(
    conn: &Connection,
    issuer: &str,
    subject: &str,
    user_id: UserId,
    lane: Option<&str>,
) -> StoreResult<()> {
    let issuer = issuer.trim();
    let subject = subject.trim();
    if issuer.is_empty() || subject.is_empty() {
        return Err(StoreError::InvalidState(
            "federated identity requires a non-empty issuer and subject".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO federated_identities (issuer, subject, user_id, lane, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(issuer, subject) DO UPDATE SET \
           user_id = excluded.user_id, lane = excluded.lane",
        params![
            issuer,
            subject,
            user_id.as_bytes(),
            lane,
            Timestamp::now().as_microsecond(),
        ],
    )?;
    Ok(())
}

/// Remove a binding. Returns whether a row existed.
pub fn delete_identity(conn: &Connection, issuer: &str, subject: &str) -> StoreResult<bool> {
    let removed = conn.execute(
        "DELETE FROM federated_identities WHERE issuer = ?1 AND subject = ?2",
        params![issuer.trim(), subject.trim()],
    )?;
    Ok(removed > 0)
}

/// Resolve an `(issuer, subject)` pair to its local identity.
pub fn find_identity(
    conn: &Connection,
    issuer: &str,
    subject: &str,
) -> StoreResult<Option<FederatedIdentity>> {
    conn.query_row(
        "SELECT issuer, subject, user_id, lane FROM federated_identities \
         WHERE issuer = ?1 AND subject = ?2",
        params![issuer.trim(), subject.trim()],
        |row| {
            let user_id = UserId::from_slice(&row.get::<_, Vec<u8>>(2)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Blob,
                    Box::new(error),
                )
            })?;
            Ok(FederatedIdentity {
                issuer: row.get(0)?,
                subject: row.get(1)?,
                user_id,
                lane: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// Record a revocation. `expires_at` is when the row may be swept — it must be
/// at or after the moment the revoked material could no longer be valid, or
/// the sweep would silently un-revoke a live token.
pub fn revoke(
    conn: &Connection,
    kind: RevocationKind,
    issuer: &str,
    value: &str,
    reason: Option<&str>,
    expires_at: i64,
) -> StoreResult<()> {
    let value = value.trim();
    if value.is_empty() {
        return Err(StoreError::InvalidState(
            "revocation requires a non-empty value".to_string(),
        ));
    }
    conn.execute(
        "INSERT INTO revoked_tokens (kind, value, issuer, reason, revoked_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(kind, issuer, value) DO UPDATE SET \
           reason = excluded.reason, \
           revoked_at = excluded.revoked_at, \
           expires_at = max(revoked_tokens.expires_at, excluded.expires_at)",
        params![
            kind.as_str(),
            value,
            issuer.trim(),
            reason,
            Timestamp::now().as_microsecond(),
            expires_at,
        ],
    )?;
    Ok(())
}

/// Whether a token is revoked, by `jti` or by its subject.
///
/// One query covering both granularities: an operator who revoked a subject
/// expects every token of that subject to stop working immediately, including
/// ones whose `jti` was never seen.
pub fn is_revoked(
    conn: &Connection,
    issuer: &str,
    jti: Option<&str>,
    subject: &str,
    now_micros: i64,
) -> StoreResult<bool> {
    let issuer = issuer.trim();
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM revoked_tokens \
             WHERE issuer = ?1 AND expires_at > ?4 \
               AND ((kind = 'subject' AND value = ?2) \
                 OR (kind = 'jti' AND ?3 IS NOT NULL AND value = ?3)) \
             LIMIT 1",
            params![issuer, subject.trim(), jti.map(str::trim), now_micros],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Drop revocation rows that can no longer matter.
pub fn sweep_revocations(conn: &Connection, now_micros: i64) -> StoreResult<usize> {
    let removed = conn.execute(
        "DELETE FROM revoked_tokens WHERE expires_at <= ?1",
        params![now_micros],
    )?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://auth.taskblu.com/realms/taskblu";
    const OTHER_ISS: &str = "https://evil.example/realms/taskblu";
    const HOUR: i64 = 3_600 * 1_000_000;

    fn conn_with_schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id BLOB NOT NULL PRIMARY KEY);
             CREATE TABLE federated_identities (
                 issuer TEXT NOT NULL, subject TEXT NOT NULL,
                 user_id BLOB NOT NULL, lane TEXT, created_at INTEGER NOT NULL,
                 PRIMARY KEY (issuer, subject));
             CREATE TABLE revoked_tokens (
                 kind TEXT NOT NULL CHECK (kind IN ('jti','subject')),
                 value TEXT NOT NULL, issuer TEXT NOT NULL, reason TEXT,
                 revoked_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                 PRIMARY KEY (kind, issuer, value));",
        )
        .unwrap();
        conn
    }

    fn seed_user(conn: &Connection) -> UserId {
        let id = UserId::new();
        conn.execute("INSERT INTO users (id) VALUES (?1)", params![id.as_bytes()])
            .unwrap();
        id
    }

    #[test]
    fn identity_round_trips_and_upsert_is_idempotent() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        upsert_identity(&conn, ISS, "svc-worker", user, Some("hermes_worker")).unwrap();
        upsert_identity(&conn, ISS, "svc-worker", user, Some("hermes_worker")).unwrap();
        let found = find_identity(&conn, ISS, "svc-worker").unwrap().unwrap();
        assert_eq!(found.user_id, user);
        assert_eq!(found.lane.as_deref(), Some("hermes_worker"));
    }

    #[test]
    fn the_same_subject_from_another_issuer_is_a_different_identity() {
        // The containment property the composite key exists for: a second
        // issuer must not be able to mint an identity belonging to the first.
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        upsert_identity(&conn, ISS, "svc-worker", user, None).unwrap();
        assert!(
            find_identity(&conn, OTHER_ISS, "svc-worker")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unmapped_subject_resolves_to_nothing() {
        let conn = conn_with_schema();
        assert!(find_identity(&conn, ISS, "never-bound").unwrap().is_none());
    }

    #[test]
    fn deleting_a_binding_stops_resolution() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        upsert_identity(&conn, ISS, "svc-worker", user, None).unwrap();
        assert!(delete_identity(&conn, ISS, "svc-worker").unwrap());
        assert!(!delete_identity(&conn, ISS, "svc-worker").unwrap());
        assert!(find_identity(&conn, ISS, "svc-worker").unwrap().is_none());
    }

    #[test]
    fn revoking_a_jti_blocks_only_that_token() {
        let conn = conn_with_schema();
        let now = Timestamp::now().as_microsecond();
        revoke(&conn, RevocationKind::Jti, ISS, "tok-1", None, now + HOUR).unwrap();
        assert!(is_revoked(&conn, ISS, Some("tok-1"), "svc-worker", now).unwrap());
        assert!(!is_revoked(&conn, ISS, Some("tok-2"), "svc-worker", now).unwrap());
    }

    #[test]
    fn revoking_a_subject_blocks_every_token_including_unseen_jtis() {
        // The incident this covers: the credential itself leaked and new
        // tokens are still being minted, so per-jti revocation cannot keep up.
        let conn = conn_with_schema();
        let now = Timestamp::now().as_microsecond();
        revoke(
            &conn,
            RevocationKind::Subject,
            ISS,
            "svc-worker",
            Some("credential rotated"),
            now + HOUR,
        )
        .unwrap();
        assert!(is_revoked(&conn, ISS, Some("never-seen"), "svc-worker", now).unwrap());
        assert!(is_revoked(&conn, ISS, None, "svc-worker", now).unwrap());
        assert!(!is_revoked(&conn, ISS, Some("tok-1"), "other-subject", now).unwrap());
    }

    #[test]
    fn a_revocation_from_another_issuer_does_not_apply() {
        let conn = conn_with_schema();
        let now = Timestamp::now().as_microsecond();
        revoke(
            &conn,
            RevocationKind::Subject,
            OTHER_ISS,
            "svc-worker",
            None,
            now + HOUR,
        )
        .unwrap();
        assert!(!is_revoked(&conn, ISS, None, "svc-worker", now).unwrap());
    }

    #[test]
    fn an_expired_revocation_row_stops_matching_and_sweeps() {
        let conn = conn_with_schema();
        let now = Timestamp::now().as_microsecond();
        revoke(&conn, RevocationKind::Jti, ISS, "tok-1", None, now + HOUR).unwrap();
        let later = now + HOUR + 1;
        assert!(!is_revoked(&conn, ISS, Some("tok-1"), "svc", later).unwrap());
        assert_eq!(sweep_revocations(&conn, later).unwrap(), 1);
    }

    #[test]
    fn re_revoking_never_shortens_an_existing_window() {
        // Re-revoking with a nearer expiry must not let a token come back to
        // life earlier than the first revocation promised.
        let conn = conn_with_schema();
        let now = Timestamp::now().as_microsecond();
        revoke(&conn, RevocationKind::Jti, ISS, "tok-1", None, now + HOUR).unwrap();
        revoke(&conn, RevocationKind::Jti, ISS, "tok-1", None, now + 1).unwrap();
        assert!(is_revoked(&conn, ISS, Some("tok-1"), "svc", now + 60).unwrap());
    }

    #[test]
    fn empty_values_are_refused() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        assert!(upsert_identity(&conn, ISS, "  ", user, None).is_err());
        assert!(upsert_identity(&conn, "  ", "svc", user, None).is_err());
        assert!(revoke(&conn, RevocationKind::Jti, ISS, " ", None, 1).is_err());
    }
}
