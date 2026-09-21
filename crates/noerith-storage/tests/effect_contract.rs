use noerith_storage::effect_contract::{
    AcceptanceReceipt, AdapterAssuranceProfile, AdapterQualificationEvidence, CallbackSemantics,
    CancelAfterAcceptance, CancelBeforeAcceptance, CompensationCapability, DurationKnowledge,
    EffectClass, EffectContractError, EffectIntent, OperatingClass, Reversibility, StatusQuery,
    TransactionBoundary, derive_operating_class,
};
use std::{collections::BTreeSet, time::Duration};

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn evidence() -> AdapterQualificationEvidence {
    AdapterQualificationEvidence {
        adapter_ref: "adapter-a".into(),
        adapter_version: "1".into(),
        evidence_refs: set(&["conformance-a"]),
        exact_shared_atomic_boundary_ref: None,
        verified: true,
    }
}

fn profile() -> AdapterAssuranceProfile {
    AdapterAssuranceProfile {
        mutates_external_state: false,
        accepts_stable_idempotency_key: false,
        dedup_retention: DurationKnowledge::Unknown,
        returns_acceptance_receipt: AcceptanceReceipt::None,
        status_query: StatusQuery::None,
        callback_semantics: CallbackSemantics::None,
        cancel_before_acceptance: CancelBeforeAcceptance::Unknown,
        cancel_after_acceptance: CancelAfterAcceptance::Unknown,
        compensation: CompensationCapability::None,
        transaction_boundary: TransactionBoundary::None,
        maximum_request_age: DurationKnowledge::Unknown,
        replay_controls: BTreeSet::new(),
        known_ambiguity_failure_modes: BTreeSet::new(),
    }
}

fn external_intent(
    id: &str,
    payload_digest: &str,
    profile: AdapterAssuranceProfile,
) -> EffectIntent {
    EffectIntent {
        effect_intent_id: id.into(),
        operation_type: "external-write".into(),
        principal_context_ref: "principal-a".into(),
        principal_context_digest: "principal-digest-a".into(),
        goal_ref: "goal-a".into(),
        goal_version: 7,
        work_ref: "work-a".into(),
        work_revision: 3,
        target_resources: vec!["resource-a".into()],
        target_accounts: vec!["account-a".into()],
        target_principals: vec!["target-a".into()],
        payload_schema: "urn:noerith:test-payload:1".into(),
        payload_canonical_digest: payload_digest.into(),
        payload_ref: "sealed-payload-a".into(),
        purpose: "user-requested-effect".into(),
        data_classes: set(&["synthetic"]),
        disclosure_classes: BTreeSet::new(),
        effect_class: EffectClass::ExternalConsequential,
        reversibility: Reversibility::Unknown,
        adapter_ref: "adapter-a".into(),
        adapter_version: "1".into(),
        assurance_profile: profile,
        idempotency_key: None,
        expected_evidence_plan_ref: "evidence-plan-a".into(),
        created_by_message_ref: "message-a".into(),
        lifecycle_state: "PROPOSED".into(),
        decision_snapshot_refs: Vec::new(),
        dispatch_attempt_refs: Vec::new(),
        provider_receipt_refs: Vec::new(),
        observation_refs: Vec::new(),
        cancellation_record_ref: None,
        compensation_record_ref: None,
        current_fence: None,
    }
}

#[test]
fn s03_contract_derives_e0_through_e4_from_exact_capability_vector() {
    let mut candidate = profile();
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E0ReadOnly
    );

    candidate.mutates_external_state = true;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E1OpaqueWrite
    );

    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Known(Duration::from_secs(300));
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E2DedupWrite
    );

    candidate.status_query = StatusQuery::ByIntent;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E3ObservableWrite
    );

    candidate.compensation = CompensationCapability::CompensatingAction;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E4CompensatableWrite
    );
}

#[test]
fn s03_contract_e5_requires_proven_exact_shared_atomic_boundary() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.transaction_boundary = TransactionBoundary::SharedAtomic;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()),
        Err(EffectContractError::SharedAtomicBoundaryUnproved)
    );

    let mut proof = evidence();
    proof.exact_shared_atomic_boundary_ref = Some("boundary-proof-a".into());
    assert_eq!(
        derive_operating_class(&candidate, &proof).unwrap(),
        OperatingClass::E5SharedAtomic
    );
}

#[test]
fn s03_contract_unqualified_assurance_cannot_grant_operating_class() {
    let mut proof = evidence();
    proof.verified = false;
    assert_eq!(
        derive_operating_class(&profile(), &proof),
        Err(EffectContractError::UnqualifiedAssurance)
    );

    proof.verified = true;
    proof.evidence_refs.clear();
    assert_eq!(
        derive_operating_class(&profile(), &proof),
        Err(EffectContractError::UnqualifiedAssurance)
    );
}

#[test]
fn s03_contract_e2_requires_known_nonzero_dedup_retention() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Unknown;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E1OpaqueWrite
    );

    candidate.dedup_retention = DurationKnowledge::Known(Duration::ZERO);
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E1OpaqueWrite
    );
}

#[test]
fn s03_contract_e3_requires_observable_acceptance_or_status_path() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Known(Duration::from_secs(60));
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E2DedupWrite
    );

    candidate.returns_acceptance_receipt = AcceptanceReceipt::Verifiable;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E3ObservableWrite
    );
}

#[test]
fn s03_contract_e4_requires_defined_compensation_on_observable_write() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Known(Duration::from_secs(60));
    candidate.status_query = StatusQuery::ObservableState;
    candidate.compensation = CompensationCapability::None;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E3ObservableWrite
    );

    candidate.compensation = CompensationCapability::SemanticUndo;
    assert_eq!(
        derive_operating_class(&candidate, &evidence()).unwrap(),
        OperatingClass::E4CompensatableWrite
    );
}

#[test]
fn s03_contract_same_payload_can_represent_two_distinct_user_intentions() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    let first = external_intent("intent-one", "same-payload-digest", candidate.clone());
    let second = external_intent("intent-two", "same-payload-digest", candidate);
    assert_eq!(
        first.payload_canonical_digest,
        second.payload_canonical_digest
    );
    assert_ne!(first.effect_intent_id, second.effect_intent_id);
    assert!(!first.is_same_retry_identity_as(&second));
}

#[test]
fn s03_contract_retry_preserves_intent_and_idempotency_identity() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Known(Duration::from_secs(120));
    let mut original = external_intent("intent-retry", "payload-a", candidate.clone());
    original.idempotency_key = Some("idem-intent-retry".into());
    assert_eq!(
        original.validate(&evidence()).unwrap(),
        OperatingClass::E2DedupWrite
    );

    let retry = original.clone();
    assert!(original.is_same_retry_identity_as(&retry));

    let mut new_user_intent = external_intent("intent-new", "payload-a", candidate);
    new_user_intent.idempotency_key = Some("idem-intent-new".into());
    assert!(!original.is_same_retry_identity_as(&new_user_intent));
}

#[test]
fn s03_contract_adapter_capability_never_expands_external_ceiling() {
    assert_eq!(
        OperatingClass::E4CompensatableWrite.restricted_to(OperatingClass::E1OpaqueWrite),
        OperatingClass::E1OpaqueWrite
    );
    assert_eq!(
        OperatingClass::E2DedupWrite.restricted_to(OperatingClass::E4CompensatableWrite),
        OperatingClass::E2DedupWrite
    );
}

#[test]
fn s03_contract_effect_validation_requires_matching_qualified_adapter_and_idempotency() {
    let mut candidate = profile();
    candidate.mutates_external_state = true;
    candidate.accepts_stable_idempotency_key = true;
    candidate.dedup_retention = DurationKnowledge::Known(Duration::from_secs(60));
    let intent = external_intent("intent-a", "payload-a", candidate);
    assert_eq!(
        intent.validate(&evidence()),
        Err(EffectContractError::MissingIdempotencyKey)
    );

    let mut wrong = evidence();
    wrong.adapter_ref = "different-adapter".into();
    assert_eq!(
        intent.validate(&wrong),
        Err(EffectContractError::QualificationAdapterMismatch)
    );
}
