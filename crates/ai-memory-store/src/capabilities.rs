//! Persistence for capability scopes granted to an identity.
//!
//! This module holds normalized rows and SQL only. The policy that turns a
//! scope set into a permitted tool surface lives in the MCP layer, next to the
//! tool names it governs, so adding a tool forces an explicit decision there
//! instead of silently inheriting a grant made here.

use std::collections::BTreeSet;

use ai_memory_core::{CapabilityScope, UserId};
use jiff::Timestamp;
use rusqlite::{Connection, params};

use crate::error::{StoreError, StoreResult};

/// Grant one scope. Idempotent: re-granting an existing scope refreshes
/// nothing and fails nothing, which makes operator scripts safe to re-run.
pub fn grant_scope(conn: &Connection, user_id: UserId, scope: CapabilityScope) -> StoreResult<()> {
    let now = Timestamp::now().as_microsecond();
    conn.execute(
        "INSERT INTO identity_scopes (user_id, scope, granted_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(user_id, scope) DO NOTHING",
        params![user_id.as_bytes(), scope.as_str(), now],
    )?;
    Ok(())
}

/// Revoke one scope. Returns whether a row was actually removed so callers can
/// distinguish "revoked" from "was never granted".
pub fn revoke_scope(
    conn: &Connection,
    user_id: UserId,
    scope: CapabilityScope,
) -> StoreResult<bool> {
    let removed = conn.execute(
        "DELETE FROM identity_scopes WHERE user_id = ?1 AND scope = ?2",
        params![user_id.as_bytes(), scope.as_str()],
    )?;
    Ok(removed > 0)
}

/// Replace an identity's entire scope set in one transaction.
///
/// This is the operation operator tooling should prefer: setting a set is
/// declarative and leaves no residue from a previous grant, whereas a sequence
/// of grants can only widen. Passing an empty set removes every scope and
/// returns the identity to unscoped (unrestricted) status — which is a real
/// widening, so callers that expose it must say so.
pub fn replace_scopes(
    conn: &mut Connection,
    user_id: UserId,
    scopes: &BTreeSet<CapabilityScope>,
) -> StoreResult<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM identity_scopes WHERE user_id = ?1",
        params![user_id.as_bytes()],
    )?;
    let now = Timestamp::now().as_microsecond();
    for scope in scopes {
        tx.execute(
            "INSERT INTO identity_scopes (user_id, scope, granted_at) VALUES (?1, ?2, ?3)",
            params![user_id.as_bytes(), scope.as_str(), now],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Read every scope granted to one identity.
///
/// An unknown scope string in the database is a hard error rather than a
/// skipped row. Skipping would silently narrow the credential, and a
/// credential that quietly does less than the operator granted is as much a
/// defect as one that does more.
pub fn find_scopes(conn: &Connection, user_id: UserId) -> StoreResult<BTreeSet<CapabilityScope>> {
    let mut stmt =
        conn.prepare("SELECT scope FROM identity_scopes WHERE user_id = ?1 ORDER BY scope")?;
    let rows = stmt.query_map(params![user_id.as_bytes()], |row| row.get::<_, String>(0))?;
    let mut scopes = BTreeSet::new();
    for row in rows {
        let raw = row?;
        let scope = CapabilityScope::parse(&raw).ok_or_else(|| {
            StoreError::InvalidState(format!(
                "invalid capability scope '{raw}' in identity_scopes"
            ))
        })?;
        scopes.insert(scope);
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Minimal schema: these tests exercise the scope rows, not the user
    /// lifecycle, so the foreign key target is stubbed rather than migrated.
    fn conn_with_schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id BLOB NOT NULL PRIMARY KEY);
             CREATE TABLE identity_scopes (
                 user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                 scope TEXT NOT NULL CHECK (scope IN (
                     'memory:read','memory:handoff.accept','memory:write',
                     'memory:curate','memory:admin')),
                 granted_at INTEGER NOT NULL,
                 PRIMARY KEY (user_id, scope));",
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
    fn granting_is_idempotent() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        grant_scope(&conn, user, CapabilityScope::MemoryRead).unwrap();
        grant_scope(&conn, user, CapabilityScope::MemoryRead).unwrap();
        assert_eq!(
            find_scopes(&conn, user).unwrap(),
            BTreeSet::from([CapabilityScope::MemoryRead])
        );
    }

    #[test]
    fn revoke_reports_whether_it_removed_anything() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        grant_scope(&conn, user, CapabilityScope::MemoryWrite).unwrap();
        assert!(revoke_scope(&conn, user, CapabilityScope::MemoryWrite).unwrap());
        assert!(!revoke_scope(&conn, user, CapabilityScope::MemoryWrite).unwrap());
    }

    #[test]
    fn replacing_narrows_as_well_as_widens() {
        let mut conn = conn_with_schema();
        let user = seed_user(&conn);
        replace_scopes(
            &mut conn,
            user,
            &BTreeSet::from([CapabilityScope::MemoryRead, CapabilityScope::MemoryWrite]),
        )
        .unwrap();
        // A second replace must not leave the previous write grant behind — a
        // set operation that could only widen would make demotion impossible.
        replace_scopes(
            &mut conn,
            user,
            &BTreeSet::from([CapabilityScope::MemoryRead]),
        )
        .unwrap();
        assert_eq!(
            find_scopes(&conn, user).unwrap(),
            BTreeSet::from([CapabilityScope::MemoryRead])
        );
    }

    #[test]
    fn scopes_are_isolated_between_identities() {
        let conn = conn_with_schema();
        let alice = seed_user(&conn);
        let bob = seed_user(&conn);
        grant_scope(&conn, alice, CapabilityScope::MemoryWrite).unwrap();
        assert!(find_scopes(&conn, bob).unwrap().is_empty());
    }

    #[test]
    fn unknown_stored_scope_fails_loudly() {
        let conn = conn_with_schema();
        let user = seed_user(&conn);
        // Bypass the CHECK constraint the way a future migration bug might.
        conn.execute("DROP TABLE identity_scopes", []).unwrap();
        conn.execute(
            "CREATE TABLE identity_scopes (user_id BLOB NOT NULL, scope TEXT NOT NULL, \
             granted_at INTEGER NOT NULL, PRIMARY KEY (user_id, scope))",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO identity_scopes (user_id, scope, granted_at) VALUES (?1, 'memory:root', 0)",
            params![user.as_bytes()],
        )
        .unwrap();
        assert!(find_scopes(&conn, user).is_err());
    }
}
