//! Web router state — the handle a request handler receives.
//!
//! Holds the read-only store pool + the wiki handle. Cheap to clone
//! (everything inside is `Arc`-shaped already), so axum's
//! `State<Arc<WebState>>` extractor stays free of clone-heavy code.

use std::collections::HashSet;

use ai_memory_core::{AuthLevel, ProjectId, UserId, WorkspaceId};
use ai_memory_store::{
    AccessAction, AccessDecision, AccessPrincipal, ReaderPool, ScopeAuthorizer, StoreResult,
};
use ai_memory_wiki::Wiki;

/// Shared state for every web route. Construct once via
/// [`crate::router`].
#[derive(Clone)]
pub struct WebState {
    /// Read-only SQLite pool — drives FTS5 search, page metadata,
    /// project list aggregates.
    pub reader: ReaderPool,
    /// Wiki handle — reads page bodies from disk.
    pub wiki: Wiki,
    /// Whether shared project-membership authorization is enforced.
    pub project_acl_enabled: bool,
}

impl WebState {
    /// Build a new shared state.
    #[must_use]
    pub fn new(reader: ReaderPool, wiki: Wiki) -> Self {
        Self::new_with_acl(reader, wiki, false)
    }

    /// Build state with opt-in project authorization.
    #[must_use]
    pub fn new_with_acl(reader: ReaderPool, wiki: Wiki, project_acl_enabled: bool) -> Self {
        Self {
            reader,
            wiki,
            project_acl_enabled,
        }
    }

    /// Evaluate a project action using canonical auth extensions.
    pub async fn check_project(
        &self,
        level: Option<AuthLevel>,
        user_id: Option<UserId>,
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        action: AccessAction,
    ) -> StoreResult<AccessDecision> {
        ScopeAuthorizer::new(self.project_acl_enabled)
            .check_project(
                &self.reader,
                AccessPrincipal::from_auth(level, user_id),
                workspace_id,
                project_id,
                action,
            )
            .await
    }

    /// Resolve the project allowlist to apply before global retrieval.
    pub async fn visible_project_scopes(
        &self,
        level: Option<AuthLevel>,
        user_id: Option<UserId>,
    ) -> StoreResult<Option<Vec<(WorkspaceId, ProjectId)>>> {
        ScopeAuthorizer::new(self.project_acl_enabled)
            .visible_project_scopes(&self.reader, AccessPrincipal::from_auth(level, user_id))
            .await
    }

    /// Resolve the names visible to project/workspace list endpoints.
    /// `None` means the deployment is unrestricted; `Some(empty)` means the
    /// authenticated principal has no active memberships.
    pub async fn visible_project_names(
        &self,
        level: Option<AuthLevel>,
        user_id: Option<UserId>,
    ) -> StoreResult<Option<HashSet<(String, String)>>> {
        let Some(scopes) = self.visible_project_scopes(level, user_id).await? else {
            return Ok(None);
        };
        let mut names = HashSet::with_capacity(scopes.len());
        for (workspace_id, project_id) in scopes {
            let Some(workspace_name) = self.reader.workspace_name_by_id(workspace_id).await? else {
                continue;
            };
            let Some(project_name) = self
                .reader
                .project_name_by_id(workspace_id, project_id)
                .await?
            else {
                continue;
            };
            names.insert((workspace_name, project_name));
        }
        Ok(Some(names))
    }
}
