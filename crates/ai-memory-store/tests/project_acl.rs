//! Durable project membership and shared scope-policy contract.

use ai_memory_core::{AuthLevel, NewUser};
use ai_memory_store::{
    AccessAction, AccessDecision, AccessPrincipal, ProjectRole, ScopeAuthorizer, Store,
    TOKEN_HASH_LEN,
};

#[tokio::test]
async fn membership_is_durable_scoped_and_enforced_before_retrieval() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let workspace = store
        .writer
        .get_or_create_workspace("taskblu")
        .await
        .unwrap();
    let project = store
        .writer
        .get_or_create_project(workspace, "assistant", None)
        .await
        .unwrap();
    let hidden = store
        .writer
        .get_or_create_project(workspace, "hidden", None)
        .await
        .unwrap();
    let mut new_user = NewUser {
        username: "operator".into(),
        name: None,
        email: None,
    };
    new_user.validate().unwrap();
    let user = store
        .writer
        .create_user(new_user, [7; TOKEN_HASH_LEN])
        .await
        .unwrap();
    store
        .writer
        .upsert_project_membership(user, workspace, project, ProjectRole::Viewer, true)
        .await
        .unwrap();

    let authorizer = ScopeAuthorizer::new(true);
    let principal = AccessPrincipal::from_auth(Some(AuthLevel::User), Some(user));
    assert_eq!(
        authorizer
            .check_project(
                &store.reader,
                principal,
                workspace,
                project,
                AccessAction::Read,
            )
            .await
            .unwrap(),
        AccessDecision::Allowed,
    );
    assert_eq!(
        authorizer
            .check_project(
                &store.reader,
                principal,
                workspace,
                project,
                AccessAction::Write,
            )
            .await
            .unwrap(),
        AccessDecision::Denied,
    );
    assert_eq!(
        authorizer
            .check_project(
                &store.reader,
                principal,
                workspace,
                hidden,
                AccessAction::Read,
            )
            .await
            .unwrap(),
        AccessDecision::Denied,
    );
    assert_eq!(
        authorizer
            .visible_project_scopes(&store.reader, principal)
            .await
            .unwrap(),
        Some(vec![(workspace, project)]),
    );

    store
        .writer
        .upsert_project_membership(user, workspace, project, ProjectRole::Owner, false)
        .await
        .unwrap();
    assert_eq!(
        authorizer
            .check_project(
                &store.reader,
                principal,
                workspace,
                project,
                AccessAction::Read,
            )
            .await
            .unwrap(),
        AccessDecision::Denied,
    );
    assert_eq!(
        authorizer
            .visible_project_scopes(&store.reader, principal)
            .await
            .unwrap(),
        Some(Vec::new()),
    );
}

#[tokio::test]
async fn workspace_project_mismatch_is_rejected_by_sql_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let workspace_a = store.writer.get_or_create_workspace("a").await.unwrap();
    let workspace_b = store.writer.get_or_create_workspace("b").await.unwrap();
    let project_a = store
        .writer
        .get_or_create_project(workspace_a, "project", None)
        .await
        .unwrap();
    let mut new_user = NewUser {
        username: "operator".into(),
        name: None,
        email: None,
    };
    new_user.validate().unwrap();
    let user = store
        .writer
        .create_user(new_user, [9; TOKEN_HASH_LEN])
        .await
        .unwrap();

    assert!(
        store
            .writer
            .upsert_project_membership(user, workspace_b, project_a, ProjectRole::Owner, true)
            .await
            .is_err()
    );
}
