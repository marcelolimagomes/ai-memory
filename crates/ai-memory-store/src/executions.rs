//! The canonical execution registry and its validation.
//!
//! The identity contract separates three things that are easy to conflate:
//! *who* the caller is (the credential), *what* it may do (capability scopes),
//! and *which execution context* it is acting inside. This module owns the
//! third one.
//!
//! The rule it enforces is narrow and worth stating plainly: an execution id
//! arriving in a request is a claim, not a credential. It authorizes nothing
//! by itself. The server accepts it only after finding a registration that
//! (a) exists, (b) belongs to the calling identity, and (c) is neither closed
//! nor expired. Project and workspace are then read from the registration, so
//! a caller cannot widen its own context by asserting a different project.

use ai_memory_core::{ProjectId, UserId, WorkspaceId};
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{StoreError, StoreResult};

/// A registered execution, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// Caller-supplied canonical identifier.
    pub taskblu_execution_id: String,
    /// Identity that registered and owns it.
    pub user_id: UserId,
    /// Workspace resolved at registration time.
    pub workspace_id: WorkspaceId,
    /// Project resolved at registration time.
    pub project_id: ProjectId,
    /// Effective lane label, for attribution only.
    pub lane: Option<String>,
    /// Optional Paperclip correlation.
    pub paperclip_run_id: Option<String>,
    /// Microseconds since epoch.
    pub created_at: i64,
    /// Microseconds since epoch; a hard bound, not a hint.
    pub expires_at: i64,
    /// Microseconds since epoch when the launcher closed it.
    pub closed_at: Option<i64>,
}

/// Why an execution claim was refused.
///
/// The variants exist for logging and tests. Callers must **not** map them to
/// distinct client-facing errors: telling an unauthorized caller that an id
/// exists but belongs to somebody else turns this registry into an oracle for
/// enumerating other lanes' executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRejection {
    /// No registration with that id.
    Unknown,
    /// Registered, but to a different identity.
    ForeignIdentity,
    /// Registered and owned, but already closed.
    Closed,
    /// Registered and owned, but past its expiry.
    Expired,
}

impl ExecutionRejection {
    /// The single client-facing message every rejection shares.
    #[must_use]
    pub const fn client_message() -> &'static str {
        "execution context is not valid for this credential"
    }
}

/// Register an execution. Fails when the id is already registered, so a
/// replayed registration cannot fork a second execution over the same id.
pub fn register(conn: &Connection, execution: &NewExecution) -> StoreResult<()> {
    let id = execution.taskblu_execution_id.trim();
    if id.is_empty() {
        return Err(StoreError::InvalidState(
            "taskblu_execution_id must not be empty".to_string(),
        ));
    }
    if execution.ttl_micros <= 0 {
        return Err(StoreError::InvalidState(
            "execution ttl must be positive".to_string(),
        ));
    }
    let now = Timestamp::now().as_microsecond();
    conn.execute(
        "INSERT INTO executions \
         (taskblu_execution_id, user_id, workspace_id, project_id, lane, \
          paperclip_run_id, created_at, expires_at, closed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        params![
            id,
            execution.user_id.as_bytes(),
            execution.workspace_id.as_bytes(),
            execution.project_id.as_bytes(),
            execution.lane.as_deref(),
            execution.paperclip_run_id.as_deref(),
            now,
            now.saturating_add(execution.ttl_micros),
        ],
    )?;
    Ok(())
}

/// Input for [`register`].
#[derive(Debug, Clone)]
pub struct NewExecution {
    /// Caller-supplied canonical identifier.
    pub taskblu_execution_id: String,
    /// Owning identity.
    pub user_id: UserId,
    /// Workspace the execution is bound to.
    pub workspace_id: WorkspaceId,
    /// Project the execution is bound to.
    pub project_id: ProjectId,
    /// Lane label, attribution only.
    pub lane: Option<String>,
    /// Optional Paperclip correlation.
    pub paperclip_run_id: Option<String>,
    /// Lifetime in microseconds from registration.
    pub ttl_micros: i64,
}

/// Close an execution. Idempotent; returns whether a row moved from open to
/// closed.
pub fn close(conn: &Connection, id: &str, user_id: UserId) -> StoreResult<bool> {
    let now = Timestamp::now().as_microsecond();
    let changed = conn.execute(
        "UPDATE executions SET closed_at = ?3 \
         WHERE taskblu_execution_id = ?1 AND user_id = ?2 AND closed_at IS NULL",
        params![id.trim(), user_id.as_bytes(), now],
    )?;
    Ok(changed > 0)
}

/// Resolve an execution claim to its authorization context.
///
/// `now_micros` is injected rather than read here so expiry is testable
/// without sleeping.
pub fn resolve(
    conn: &Connection,
    id: &str,
    user_id: UserId,
    now_micros: i64,
) -> StoreResult<Result<Execution, ExecutionRejection>> {
    let Some(execution) = find(conn, id)? else {
        return Ok(Err(ExecutionRejection::Unknown));
    };
    // Ownership before state: a caller must not learn that somebody else's
    // execution expired.
    if execution.user_id != user_id {
        return Ok(Err(ExecutionRejection::ForeignIdentity));
    }
    if execution.closed_at.is_some() {
        return Ok(Err(ExecutionRejection::Closed));
    }
    if execution.expires_at <= now_micros {
        return Ok(Err(ExecutionRejection::Expired));
    }
    Ok(Ok(execution))
}

/// Read one registration regardless of owner or state.
pub fn find(conn: &Connection, id: &str) -> StoreResult<Option<Execution>> {
    conn.query_row(
        "SELECT taskblu_execution_id, user_id, workspace_id, project_id, lane, \
                paperclip_run_id, created_at, expires_at, closed_at \
         FROM executions WHERE taskblu_execution_id = ?1",
        params![id.trim()],
        execution_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn execution_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Execution> {
    let user_id = UserId::from_slice(&row.get::<_, Vec<u8>>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let workspace_id = WorkspaceId::from_slice(&row.get::<_, Vec<u8>>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let project_id = ProjectId::from_slice(&row.get::<_, Vec<u8>>(3)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    Ok(Execution {
        taskblu_execution_id: row.get(0)?,
        user_id,
        workspace_id,
        project_id,
        lane: row.get(4)?,
        paperclip_run_id: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
        closed_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_with_schema() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id BLOB NOT NULL PRIMARY KEY);
             CREATE TABLE workspaces (id BLOB NOT NULL PRIMARY KEY);
             CREATE TABLE projects (id BLOB NOT NULL PRIMARY KEY, workspace_id BLOB NOT NULL);
             CREATE TABLE executions (
                 taskblu_execution_id TEXT NOT NULL PRIMARY KEY,
                 user_id BLOB NOT NULL,
                 workspace_id BLOB NOT NULL,
                 project_id BLOB NOT NULL,
                 lane TEXT,
                 paperclip_run_id TEXT,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 closed_at INTEGER);",
        )
        .unwrap();
        conn
    }

    struct Fixture {
        conn: Connection,
        user: UserId,
        workspace: WorkspaceId,
        project: ProjectId,
    }

    fn fixture() -> Fixture {
        let conn = conn_with_schema();
        let user = UserId::new();
        let workspace = WorkspaceId::new();
        let project = ProjectId::new();
        conn.execute(
            "INSERT INTO users (id) VALUES (?1)",
            params![user.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspaces (id) VALUES (?1)",
            params![workspace.as_bytes()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO projects (id, workspace_id) VALUES (?1, ?2)",
            params![project.as_bytes(), workspace.as_bytes()],
        )
        .unwrap();
        Fixture {
            conn,
            user,
            workspace,
            project,
        }
    }

    fn new_execution(f: &Fixture, id: &str, ttl_micros: i64) -> NewExecution {
        NewExecution {
            taskblu_execution_id: id.to_string(),
            user_id: f.user,
            workspace_id: f.workspace,
            project_id: f.project,
            lane: Some("hermes_orchestrator".into()),
            paperclip_run_id: None,
            ttl_micros,
        }
    }

    const ONE_HOUR: i64 = 3_600 * 1_000_000;

    #[test]
    fn a_registered_execution_resolves_to_its_bound_project() {
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        let now = Timestamp::now().as_microsecond();
        let resolved = resolve(&f.conn, "exec-1", f.user, now).unwrap().unwrap();
        // Project and workspace come from the registry, never from the caller.
        assert_eq!(resolved.project_id, f.project);
        assert_eq!(resolved.workspace_id, f.workspace);
    }

    #[test]
    fn an_unknown_execution_is_rejected() {
        let f = fixture();
        let now = Timestamp::now().as_microsecond();
        assert_eq!(
            resolve(&f.conn, "never-registered", f.user, now).unwrap(),
            Err(ExecutionRejection::Unknown)
        );
    }

    #[test]
    fn another_identitys_execution_is_rejected() {
        // The core containment property: a valid credential cannot borrow an
        // execution context registered by a different lane.
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        let intruder = UserId::new();
        let now = Timestamp::now().as_microsecond();
        assert_eq!(
            resolve(&f.conn, "exec-1", intruder, now).unwrap(),
            Err(ExecutionRejection::ForeignIdentity)
        );
    }

    #[test]
    fn an_expired_execution_stops_authorizing() {
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        // Look at it from an hour and a second in the future.
        let later = Timestamp::now().as_microsecond() + ONE_HOUR + 1_000_000;
        assert_eq!(
            resolve(&f.conn, "exec-1", f.user, later).unwrap(),
            Err(ExecutionRejection::Expired)
        );
    }

    #[test]
    fn a_closed_execution_stops_authorizing_and_close_is_idempotent() {
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        assert!(close(&f.conn, "exec-1", f.user).unwrap());
        assert!(!close(&f.conn, "exec-1", f.user).unwrap());
        let now = Timestamp::now().as_microsecond();
        assert_eq!(
            resolve(&f.conn, "exec-1", f.user, now).unwrap(),
            Err(ExecutionRejection::Closed)
        );
    }

    #[test]
    fn another_identity_cannot_close_an_execution() {
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        let intruder = UserId::new();
        assert!(!close(&f.conn, "exec-1", intruder).unwrap());
        // Still usable by its owner: the failed close changed nothing.
        let now = Timestamp::now().as_microsecond();
        assert!(resolve(&f.conn, "exec-1", f.user, now).unwrap().is_ok());
    }

    #[test]
    fn re_registering_the_same_id_fails() {
        let f = fixture();
        register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).unwrap();
        assert!(register(&f.conn, &new_execution(&f, "exec-1", ONE_HOUR)).is_err());
    }

    #[test]
    fn empty_id_and_non_positive_ttl_are_refused() {
        let f = fixture();
        assert!(register(&f.conn, &new_execution(&f, "   ", ONE_HOUR)).is_err());
        assert!(register(&f.conn, &new_execution(&f, "exec-2", 0)).is_err());
    }

    #[test]
    fn every_rejection_shares_one_client_message() {
        // Distinct client messages would let a caller probe which execution
        // ids exist and who owns them.
        assert_eq!(
            ExecutionRejection::client_message(),
            "execution context is not valid for this credential"
        );
    }
}
