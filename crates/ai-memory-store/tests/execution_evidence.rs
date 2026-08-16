//! Contract tests for metadata-only execution receipts.

use ai_memory_core::{
    AgentKind, HandoffAcceptance, NewHandoff, NewObservation, NewSession, ObservationKind,
    OwnerFilter, Sanitized, Sanitizer, SessionId,
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

    let handoff = store
        .writer
        .insert_handoff(NewHandoff {
            workspace_id: workspace,
            project_id: project,
            from_session_id: Some(session),
            from_agent: AgentKind::Hermes,
            to_agent: Some(AgentKind::Codex),
            cwd: None,
            summary: "PRIVATE_HANDOFF".into(),
            open_questions: Vec::new(),
            next_steps: Vec::new(),
            files_touched: Vec::new(),
            owner_user: None,
        })
        .await
        .unwrap();
    let receiver = SessionId::new();
    store
        .writer
        .begin_session(NewSession {
            id: receiver,
            workspace_id: workspace,
            project_id: project,
            agent_kind: AgentKind::Codex,
            cwd: None,
            actor_user: None,
        })
        .await
        .unwrap();
    assert!(
        store
            .writer
            .accept_handoff(HandoffAcceptance {
                handoff_id: handoff,
                workspace_id: workspace,
                project_id: project,
                accepting_agent: AgentKind::Codex,
                accepting_session: Some(receiver),
                accepting_user: None,
                owner_filter: OwnerFilter::Any,
                receiving_cwd: None,
            })
            .await
            .unwrap()
    );
    let evidence = store
        .reader
        .execution_evidence("exec-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence.handoffs_created, 1);
    assert_eq!(evidence.handoffs_accepted, 1);
    assert_eq!(
        evidence.handoff_accepting_session_ids,
        vec![receiver.to_string()]
    );
    assert!(
        !serde_json::to_string(&evidence)
            .unwrap()
            .contains("PRIVATE_HANDOFF")
    );

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

#[tokio::test]
async fn execution_session_lookup_is_project_scoped_and_fails_closed_when_ambiguous() {
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
    let other_project = store
        .writer
        .get_or_create_project(workspace, "other", None)
        .await
        .unwrap();
    let observation = |session_id, project_id| {
        Sanitized::new(
            NewObservation {
                session_id,
                workspace_id: workspace,
                project_id,
                kind: ObservationKind::SessionStart,
                extension: None,
                source_event: None,
                title: "start".into(),
                body: "start".into(),
                importance: 1,
            },
            &Sanitizer::builtin(),
        )
    };
    let correlate = |session_id| IngestCorrelation {
        taskblu_execution_id: Some("paperclip:run-1".into()),
        paperclip_run_id: Some("run-1".into()),
        session_id: Some(session_id),
        event_kind: Some("session-start".into()),
        source_event: None,
        capture_owner: Some("hermes-observer-bridge".into()),
    };

    let first = SessionId::new();
    store
        .writer
        .begin_session(NewSession {
            id: first,
            workspace_id: workspace,
            project_id: project,
            agent_kind: AgentKind::Hermes,
            cwd: None,
            actor_user: None,
        })
        .await
        .unwrap();
    store
        .writer
        .insert_observation_ingest_correlated(
            observation(first, project),
            "start-1".into(),
            Some(correlate(first)),
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .reader
            .execution_session_for_project("paperclip:run-1", project)
            .await
            .unwrap(),
        Some((first, AgentKind::Hermes))
    );
    assert_eq!(
        store
            .reader
            .execution_session_for_project("paperclip:run-1", other_project)
            .await
            .unwrap(),
        None
    );

    let second = SessionId::new();
    store
        .writer
        .begin_session(NewSession {
            id: second,
            workspace_id: workspace,
            project_id: project,
            agent_kind: AgentKind::Hermes,
            cwd: None,
            actor_user: None,
        })
        .await
        .unwrap();
    store
        .writer
        .insert_observation_ingest_correlated(
            observation(second, project),
            "start-2".into(),
            Some(correlate(second)),
        )
        .await
        .unwrap();

    assert!(
        store
            .reader
            .execution_session_for_project("paperclip:run-1", project)
            .await
            .is_err(),
        "an execution with two native sessions must not guess the handoff consumer"
    );
}
