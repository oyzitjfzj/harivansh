use noerith_storage::{
    cancellation_contract::{CancelResolution, CancelState, CancellationError, CancellationRecord},
    effect_contract::CancelAfterAcceptance,
};

#[test]
fn s03_cancel_precommit_is_blocked_not_provider_confirmed() {
    let mut record = CancellationRecord::new();
    assert_eq!(
        record.block_before_commit("outbox-blocked-proof").unwrap(),
        CancelState::BlockedBeforeCommit
    );
    assert_eq!(record.state().as_str(), "BLOCKED_BEFORE_COMMIT");
    assert_ne!(record.state(), CancelState::ConfirmedCancelled);
}

#[test]
fn s03_cancel_after_send_stays_requested_until_provider_path_runs() {
    let mut record = CancellationRecord::new();
    assert_eq!(
        record
            .request_after_send("authenticated-cancel-intent")
            .unwrap(),
        CancelState::Requested
    );
    assert_eq!(record.state().as_str(), "REQUESTED");
}

#[test]
fn s03_cancel_requested_cannot_jump_directly_to_confirmed_cancelled() {
    let mut record = CancellationRecord::new();
    record
        .request_after_send("authenticated-cancel-intent")
        .unwrap();
    assert_eq!(
        record.resolve_provider_result(
            CancelResolution::ConfirmedCancelled,
            "provider-confirmation"
        ),
        Err(CancellationError::InvalidTransition)
    );
}

#[test]
fn s03_cancel_forward_and_provider_evidence_are_distinct_transitions() {
    let mut record = CancellationRecord::new();
    record
        .request_after_send("authenticated-cancel-intent")
        .unwrap();
    assert_eq!(
        record
            .mark_forwarded_to_provider("provider-cancel-request-id")
            .unwrap(),
        CancelState::ForwardedToProvider
    );
    assert_eq!(
        record
            .resolve_provider_result(
                CancelResolution::ConfirmedCancelled,
                "provider-cancelled-receipt"
            )
            .unwrap(),
        CancelState::ConfirmedCancelled
    );
    assert_eq!(record.evidence_refs().len(), 3);
}

#[test]
fn s03_cancel_provider_can_truthfully_resolve_too_late_or_unknown() {
    for (resolution, expected) in [
        (CancelResolution::TooLate, CancelState::TooLate),
        (CancelResolution::Unknown, CancelState::CancelUnknown),
    ] {
        let mut record = CancellationRecord::new();
        record.request_after_send("authenticated-request").unwrap();
        record
            .mark_forwarded_to_provider("provider-request")
            .unwrap();
        assert_eq!(
            record
                .resolve_provider_result(resolution, "provider-result-evidence")
                .unwrap(),
            expected
        );
    }
}

#[test]
fn s03_cancel_after_acceptance_respects_adapter_capability_without_fake_success() {
    let mut unsupported = CancellationRecord::new();
    assert_eq!(
        unsupported
            .request_after_acceptance(CancelAfterAcceptance::Unsupported, "authenticated-request")
            .unwrap(),
        CancelState::TooLate
    );

    let mut supported = CancellationRecord::new();
    assert_eq!(
        supported
            .request_after_acceptance(CancelAfterAcceptance::Supported, "authenticated-request")
            .unwrap(),
        CancelState::Requested
    );
    assert_ne!(supported.state(), CancelState::ConfirmedCancelled);
}

#[test]
fn s03_cancel_state_names_match_frozen_contract() {
    assert_eq!(CancelState::None.as_str(), "NONE");
    assert_eq!(CancelState::Requested.as_str(), "REQUESTED");
    assert_eq!(
        CancelState::BlockedBeforeCommit.as_str(),
        "BLOCKED_BEFORE_COMMIT"
    );
    assert_eq!(
        CancelState::ForwardedToProvider.as_str(),
        "FORWARDED_TO_PROVIDER"
    );
    assert_eq!(
        CancelState::ConfirmedCancelled.as_str(),
        "CONFIRMED_CANCELLED"
    );
    assert_eq!(CancelState::TooLate.as_str(), "TOO_LATE");
    assert_eq!(CancelState::CancelUnknown.as_str(), "CANCEL_UNKNOWN");
}

#[test]
fn s03_cancel_transitions_require_evidence() {
    let mut record = CancellationRecord::new();
    assert_eq!(
        record.request_after_send(""),
        Err(CancellationError::MissingEvidence)
    );
    assert_eq!(record.state(), CancelState::None);
}
