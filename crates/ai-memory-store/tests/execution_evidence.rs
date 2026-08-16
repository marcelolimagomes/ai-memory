//! Contract tests for metadata-only execution receipts.

use ai_memory_core::{
    AgentKind, NewObservation, NewSession, ObservationKind, Sanitized, Sanitizer, SessionId,
};
use ai_memory_store::{IngestCorrelation, IngestObservationOutcome, Store};
use tempfile::TempDir;

#[tokio::test]
async fn correlated_ingest_is_metadata_only_and_rejects_execution_drift() {
    let tmp = TempDir::new().unwrap();
    let store = Store::open(tmp.path()).unwrap();
    let workspace = store
        .writer
        .get_or_create_workspace("default")
        .await
        .unwrap();
    let project = store
        .writer
        .get_or_create_project(workspace, "evidence", None)
        .await
        .unwrap();
    let session = SessionId::new();
    store
        .writer
        .begin_session(NewSession {
            id: session,
            workspace_id: workspace,
            project_id: project,
            agent_kind: AgentKind::Hermes,
            cwd: None,
            actor_user: None,
        })
        .await
        .unwrap();
    let observation = || {
        Sanitized::new(
            NewObservation {
                session_id: session,
                workspace_id: workspace,
                project_id: project,
                kind: ObservationKind::SessionStart,
                extension: None,
                source_event: None,
                title: "PRIVATE_TITLE".into(),
                body: "PRIVATE_BODY".into(),
                importance: 5,
            },
            &Sanitizer::builtin(),
        )
    };
    let correlation = IngestCorrelation {
        taskblu_execution_id: Some("exec-1".into()),
        paperclip_run_id: Some("paperclip-1".into()),
        session_id: Some(session),
        event_kind: Some("session-start".into()),
        source_event: None,
        capture_owner: Some("hermes-observer-bridge".into()),
    };
    store
        .writer
        .insert_observation_ingest_correlated(
            observation(),
            "correlation-key".into(),
            Some(correlation.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .writer
            .insert_observation_ingest_correlated(
                observation(),
                "correlation-key".into(),
                Some(correlation.clone()),
            )
            .await
            .unwrap(),
        IngestObservationOutcome::ResumePending
    );

    let evidence = store
        .reader
        .execution_evidence("exec-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.receipts, 1);
    assert_eq!(evidence.replay_count, 1);
    assert_eq!(evidence.session_ids, vec![session.to_string()]);
    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(!serialized.contains("PRIVATE_TITLE"));
    assert!(!serialized.contains("PRIVATE_BODY"));

    let mut drifted = correlation;
    drifted.taskblu_execution_id = Some("exec-2".into());
    assert!(
        store
            .writer
            .insert_observation_ingest_correlated(
                observation(),
                "correlation-key".into(),
                Some(drifted),
            )
            .await
            .is_err()
    );
    assert!(
        store
            .reader
            .execution_evidence("exec-2")
            .await
            .unwrap()
            .is_none()
    );
}
