//! Project membership and scope-authorization persistence.
//!
//! This module contains only normalized membership data and SQL operations.
//! The MCP layer owns transport/auth decisions; it asks these functions for a
//! current membership and then applies the role policy to the requested
//! operation.

use ai_memory_core::{AuthLevel, ProjectId, UserId, WorkspaceId};
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{StoreError, StoreResult};

/// Project role understood by the first ACL gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectRole {
    /// May discover and read project content.
    Viewer,
    /// May create and revise project content.
    Contributor,
    /// May curate/approve project content and manage project guidance.
    Curator,
    /// Project administrator; may manage memberships.
    Owner,
}

impl ProjectRole {
    /// Parse the stable wire/database representation.
    pub fn parse(value: &str) -> StoreResult<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "viewer" => Ok(Self::Viewer),
            "contributor" => Ok(Self::Contributor),
            "curator" => Ok(Self::Curator),
            "owner" => Ok(Self::Owner),
            other => Err(StoreError::InvalidState(format!(
                "invalid project membership role '{other}'"
            ))),
        }
    }

    /// Stable wire/database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Contributor => "contributor",
            Self::Curator => "curator",
            Self::Owner => "owner",
        }
    }

    /// Whether the role may read project-scoped content.
    #[must_use]
    pub const fn can_read(self) -> bool {
        true
    }

    /// Whether the role may create/revise project-scoped content.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Contributor | Self::Curator | Self::Owner)
    }

    /// Whether the role may approve or curate project-scoped content.
    #[must_use]
    pub const fn can_curate(self) -> bool {
        matches!(self, Self::Curator | Self::Owner)
    }
}

/// Durable membership row returned to authorization callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMembership {
    /// User receiving the membership.
    pub user_id: UserId,
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Project inside the workspace.
    pub project_id: ProjectId,
    /// Assigned role.
    pub role: ProjectRole,
    /// False means suspended without deleting provenance.
    pub active: bool,
}

/// Operation protected by the project scope authorizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAction {
    /// Retrieve project content or metadata.
    Read,
    /// Create or revise project content.
    Write,
    /// Curate or approve governed content.
    Curate,
}

/// Canonical principal presented to the scope authorizer. `Local` represents
/// stdio/in-process access where the caller already owns the data directory;
/// it is retained for backwards compatibility and never comes from HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPrincipal {
    /// No HTTP auth middleware was involved (stdio/in-process).
    Local,
    /// Authenticated root/operator identity.
    Root,
    /// Authenticated DB/proxy user without an active project role.
    User(UserId),
    /// Auth middleware ran but resolved an anonymous request.
    Anonymous,
    /// Auth middleware said `User`, but did not attach a stable user id.
    MissingUserIdentity,
    /// An explicitly configured background service principal. This variant is
    /// never produced by HTTP authentication; callers must additionally bind
    /// it to a configured scope allowlist before invoking a job.
    Service,
}

impl AccessPrincipal {
    /// Build a principal from the canonical auth extensions. Raw actor headers
    /// are intentionally not accepted here.
    #[must_use]
    pub fn from_auth(level: Option<AuthLevel>, user_id: Option<UserId>) -> Self {
        match level {
            None => Self::Local,
            Some(AuthLevel::Root) => Self::Root,
            Some(AuthLevel::Anonymous) => Self::Anonymous,
            Some(AuthLevel::User) => user_id.map_or(Self::MissingUserIdentity, Self::User),
        }
    }
}

/// Result of an authorization check without leaking whether a project exists
/// to a caller that is not allowed to access it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// The operation may proceed.
    Allowed,
    /// The operation must be rejected with a generic authorization error.
    Denied,
}

/// Shared, opt-in project authorization policy used by MCP, web/API and hook
/// boundaries. The policy itself is pure; membership lookups are delegated to
/// the read pool so every transport evaluates the same role semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeAuthorizer {
    enabled: bool,
}

impl ScopeAuthorizer {
    /// Construct an authorizer. Disabled mode preserves the historical
    /// single-tenant behavior.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether project authorization is active.
    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Authorize a project-scoped operation.
    pub async fn check_project(
        self,
        reader: &crate::ReaderPool,
        principal: AccessPrincipal,
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        action: AccessAction,
    ) -> StoreResult<AccessDecision> {
        if !self.enabled {
            return Ok(AccessDecision::Allowed);
        }
        match principal {
            AccessPrincipal::Local | AccessPrincipal::Root | AccessPrincipal::Service => {
                Ok(AccessDecision::Allowed)
            }
            AccessPrincipal::Anonymous | AccessPrincipal::MissingUserIdentity => {
                Ok(AccessDecision::Denied)
            }
            AccessPrincipal::User(user_id) => {
                let Some(membership) = reader
                    .project_membership(user_id, workspace_id, project_id)
                    .await?
                else {
                    return Ok(AccessDecision::Denied);
                };
                let allowed = membership.active
                    && match action {
                        AccessAction::Read => membership.role.can_read(),
                        AccessAction::Write => membership.role.can_write(),
                        AccessAction::Curate => membership.role.can_curate(),
                    };
                Ok(if allowed {
                    AccessDecision::Allowed
                } else {
                    AccessDecision::Denied
                })
            }
        }
    }

    /// Authorize access to information stored in the reserved global scope.
    /// Global content is shared between authenticated users; anonymous HTTP
    /// callers are denied when the gate is active.
    #[must_use]
    pub const fn check_global_read(self, principal: AccessPrincipal) -> AccessDecision {
        if !self.enabled {
            return AccessDecision::Allowed;
        }
        match principal {
            AccessPrincipal::Local
            | AccessPrincipal::Root
            | AccessPrincipal::User(_)
            | AccessPrincipal::Service => AccessDecision::Allowed,
            AccessPrincipal::Anonymous | AccessPrincipal::MissingUserIdentity => {
                AccessDecision::Denied
            }
        }
    }

    /// Return the project scopes a user may include in an ACL-protected global
    /// search. `None` means the caller is a local/root compatibility principal
    /// and may retain the existing unrestricted global query path.
    pub async fn visible_project_scopes(
        self,
        reader: &crate::ReaderPool,
        principal: AccessPrincipal,
    ) -> StoreResult<Option<Vec<(WorkspaceId, ProjectId)>>> {
        if !self.enabled {
            return Ok(None);
        }
        match principal {
            AccessPrincipal::Local | AccessPrincipal::Root => Ok(None),
            AccessPrincipal::Service => Ok(Some(Vec::new())),
            AccessPrincipal::User(user_id) => {
                Ok(Some(reader.active_project_scopes(user_id).await?))
            }
            AccessPrincipal::Anonymous | AccessPrincipal::MissingUserIdentity => {
                Ok(Some(Vec::new()))
            }
        }
    }
}

/// Insert or update one membership. The writer actor serializes concurrent
/// changes and the composite primary key makes the operation idempotent.
pub fn upsert_membership(
    conn: &Connection,
    user_id: UserId,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    role: ProjectRole,
    active: bool,
) -> StoreResult<()> {
    let now = Timestamp::now().as_microsecond();
    conn.execute(
        "INSERT INTO project_memberships \
         (user_id, workspace_id, project_id, role, active, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6) \
         ON CONFLICT(user_id, workspace_id, project_id) DO UPDATE SET \
           role = excluded.role, active = excluded.active, updated_at = excluded.updated_at",
        params![
            user_id.as_bytes(),
            workspace_id.as_bytes(),
            project_id.as_bytes(),
            role.as_str(),
            i64::from(active),
            now,
        ],
    )?;
    Ok(())
}

/// Return one membership, including inactive rows so callers can distinguish
/// a suspended user from a user that was never assigned.
pub fn find_membership(
    conn: &Connection,
    user_id: UserId,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
) -> StoreResult<Option<ProjectMembership>> {
    conn.query_row(
        "SELECT user_id, workspace_id, project_id, role, active \
         FROM project_memberships \
         WHERE user_id = ?1 AND workspace_id = ?2 AND project_id = ?3",
        params![
            user_id.as_bytes(),
            workspace_id.as_bytes(),
            project_id.as_bytes()
        ],
        membership_from_row,
    )
    .optional()
    .map_err(StoreError::from)
}

fn membership_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectMembership> {
    let role: String = row.get(3)?;
    let role = ProjectRole::parse(&role).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let user_id = UserId::from_slice(&row.get::<_, Vec<u8>>(0)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let workspace_id = WorkspaceId::from_slice(&row.get::<_, Vec<u8>>(1)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    let project_id = ProjectId::from_slice(&row.get::<_, Vec<u8>>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, Box::new(error))
    })?;
    Ok(ProjectMembership {
        user_id,
        workspace_id,
        project_id,
        role,
        active: row.get::<_, i64>(4)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_memory_core::UserId;
    use rusqlite::Connection;

    #[test]
    fn role_policy_is_monotonic() {
        assert!(ProjectRole::Viewer.can_read());
        assert!(!ProjectRole::Viewer.can_write());
        assert!(ProjectRole::Contributor.can_write());
        assert!(!ProjectRole::Contributor.can_curate());
        assert!(ProjectRole::Curator.can_curate());
        assert!(ProjectRole::Owner.can_curate());
    }

    #[test]
    fn invalid_role_is_rejected_without_sql() {
        assert!(ProjectRole::parse("admin").is_err());
        let _ = UserId::new();
        let _ = Connection::open_in_memory();
    }
}
