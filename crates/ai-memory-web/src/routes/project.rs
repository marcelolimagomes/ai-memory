//! `GET /w/:workspace/:project` — page tree + recent activity.

use std::collections::BTreeMap;
use std::sync::Arc;

use ai_memory_store::{AccessAction, AccessDecision, lookup_existing_scope};
use askama::Template;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Html;

use crate::state::WebState;
use crate::templates::{Folder, PageRow, ProjectView, humanize, page_href};

/// Handler for `GET /w/:workspace/:project`.
pub(crate) async fn handler(
    State(state): State<Arc<WebState>>,
    Path((workspace, project)): Path<(String, String)>,
    auth: Option<axum::Extension<ai_memory_core::AuthLevel>>,
    user_id: Option<axum::Extension<ai_memory_core::UserId>>,
) -> Result<Html<String>, StatusCode> {
    let scope = lookup_existing_scope(&state.reader, &workspace, &project)
        .await
        .map_err(|error| {
            if error.is_not_found() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    let decision = state
        .check_project(
            auth.map(|axum::Extension(level)| level),
            user_id.map(|axum::Extension(id)| id),
            scope.workspace_id,
            scope.project_id,
            AccessAction::Read,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if decision == AccessDecision::Denied {
        return Err(StatusCode::NOT_FOUND);
    }
    let pages = state
        .reader
        .list_pages(&workspace, &project)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build sidebar folder tree (group by first path segment).
    let mut folder_map: BTreeMap<String, Vec<PageRow>> = BTreeMap::new();
    for p in &pages {
        let folder = p
            .path
            .split('/')
            .next()
            .and_then(|seg| {
                // Only treat it as a folder prefix if there's a slash in the path.
                if p.path.contains('/') {
                    Some(seg.to_owned())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "(root)".to_owned());
        folder_map.entry(folder).or_default().push(PageRow {
            path: p.path.clone(),
            href: page_href(&workspace, &project, &p.path),
            title: p.title.clone(),
            kind: p.kind.clone(),
            updated_relative: humanize(&p.updated_at),
        });
    }
    let folders: Vec<Folder> = folder_map
        .into_iter()
        .map(|(name, pages)| Folder { name, pages })
        .collect();

    // Recent pages: sort by updated_at desc, take 20.
    let mut sorted = pages.clone();
    sorted.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    sorted.truncate(20);
    let recent: Vec<PageRow> = sorted
        .into_iter()
        .map(|p| PageRow {
            path: p.path.clone(),
            href: page_href(&workspace, &project, &p.path),
            title: p.title.clone(),
            kind: p.kind.clone(),
            updated_relative: humanize(&p.updated_at),
        })
        .collect();

    let html = ProjectView {
        workspace,
        project,
        folders,
        recent,
    }
    .render()
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Html(html))
}
