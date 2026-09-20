use noerith_cognition::*;
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn policy(name: &str) -> AdaptivePolicyRef {
    AdaptivePolicyRef {
        policy_ref: name.to_owned(),
        version: "qualified-1".into(),
        qualification_evidence_refs: set(&["heldout-qualification"]),
    }
}

fn identity(item_ref: &str, kind: ContextItemKind) -> ContextItemIdentity {
    ContextItemIdentity {
        tenant_ref: "tenant-a".into(),
        purpose_ref: "purpose-a".into(),
        item_ref: item_ref.into(),
        kind,
    }
}

fn boundary_labels(trust: &str) -> ContextBoundaryLabels {
    ContextBoundaryLabels {
        trust_label_ref: trust.into(),
        data_use_label_ref: "use-private".into(),
        lifecycle_label_ref: "current:correction@9".into(),
    }
}

fn instruction_candidate() -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Exact(ExactSourceProjection {
        identity: identity("instruction-a", ContextItemKind::ExactSourceSpan),
        source_ref: "user-message-a".into(),
        source_version: 7,
        span_ref: "instruction-span".into(),
        content_digest: "digest-instruction".into(),
        lineage_ref: "lineage-instruction".into(),
        boundary: boundary_labels("trust-user-source"),
        validity_dependency_refs: set(&["user-message-a@7", "correction@9"]),
    })
}

fn structured_candidate(item_ref: &str, fact_ref: &str, trust: &str) -> ContextCandidateDescriptor {
    ContextCandidateDescriptor::Structured(StructuredFactProjection {
        identity: identity(item_ref, ContextItemKind::StructuredFact),
        fact_ref: fact_ref.into(),
        fact_version: 4,
        content_digest: format!("digest-{item_ref}"),
        provenance_refs: set(&["source-vault-record@7"]),
        boundary: boundary_labels(trust),
        validity_dependency_refs: set(&["correction@9", "authority@5"]),
    })
}

fn delivery(
    item_ref: &str,
    classes: &[ContextInformationClass],
    principal: Option<&str>,
    authority_evidence: Option<&str>,
) -> ContextDeliveryBoundary {
    ContextDeliveryBoundary {
        item_ref: item_ref.into(),
        information_classes: classes.iter().copied().collect(),
        taint_label_ref: "taint-reviewed".into(),
        sensitivity_label_ref: "sensitivity-private".into(),
        principal_scope_ref: principal.map(str::to_owned),
        authority_context_evidence_ref: authority_evidence.map(str::to_owned),
        expiry_ref: Some("correction@9".into()),
        label_transition_evidence: Vec::new(),
    }
}

fn compilation() -> ContextCompilation {
    let candidates = vec![
        instruction_candidate(),
        structured_candidate(
            "authority-a",
            "principal-authority-a",
            "trust-verified-authority",
        ),
        structured_candidate("fact-a", "fact-balance-a", "trust-observed-fact"),
        structured_candidate("excluded-a", "fact-unneeded-a", "trust-observed-fact"),
    ];
    ContextCompilation {
        compilation_id: "compilation-a".into(),
        version: 3,
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a@3".into(),
        purpose_ref: "purpose-a".into(),
        candidate_set_revision_ref: "candidate-set@12".into(),
        candidates,
        delivery_boundaries: vec![
            delivery(
                "instruction-a",
                &[ContextInformationClass::InstructionCandidate],
                Some("principal-a@3"),
                None,
            ),
            delivery(
                "authority-a",
                &[ContextInformationClass::PrincipalAuthorityContext],
                Some("principal-a@3"),
                Some("authority-context-proof@5"),
            ),
            delivery(
                "fact-a",
                &[
                    ContextInformationClass::ContentData,
                    ContextInformationClass::Evidence,
                ],
                Some("principal-a@3"),
                None,
            ),
            delivery(
                "excluded-a",
                &[ContextInformationClass::ContentData],
                Some("principal-a@3"),
                None,
            ),
        ],
        protected_evidence: Vec::new(),
        validity_frontier: ContextValidityFrontier {
            goal: VersionedRef {
                reference: "goal-a".into(),
                version: 8,
            },
            work: VersionedRef {
                reference: "work-a".into(),
                version: 13,
            },
            correction_frontier_ref: "correction@9".into(),
            policy_authority_epoch_ref: "authority@5".into(),
            dependency_refs: set(&["goal-a@8", "work-a@13", "correction@9", "authority@5"]),
        },
        receiver_profile: ReceiverContextProfileRef {
            receiver_ref: "model-a".into(),
            receiver_version: "model-7".into(),
            context_profile_ref: "context-profile@6".into(),
            qualification_evidence_refs: set(&["context-heldout@6"]),
        },
        unresolved_gaps: BTreeSet::new(),
        excluded_but_needed_evidence_refs: BTreeSet::new(),
        effect_refs: BTreeSet::new(),
        obligation_refs: BTreeSet::new(),
        token_budget_requested: Some(8_000),
        token_budget_used: Some(2_000),
        selection_receipt: ContextSelectionReceipt {
            receipt_id: "selection@12".into(),
            candidate_set_revision_ref: "candidate-set@12".into(),
            selector_policy: policy("selector-a"),
            dispositions: vec![
                ContextSelectionDisposition::Selected {
                    item_ref: "instruction-a".into(),
                    policy_evidence_refs: set(&["selected-instruction"]),
                },
                ContextSelectionDisposition::Selected {
                    item_ref: "authority-a".into(),
                    policy_evidence_refs: set(&["selected-authority"]),
                },
                ContextSelectionDisposition::Selected {
                    item_ref: "fact-a".into(),
                    policy_evidence_refs: set(&["selected-fact"]),
                },
                ContextSelectionDisposition::Excluded {
                    item_ref: "excluded-a".into(),
                    reason_refs: set(&["not-needed-for-current-purpose"]),
                    policy_evidence_refs: set(&["selection-decision"]),
                },
            ],
        },
    }
}

fn control_binding() -> ContextControlBinding {
    ContextControlBinding {
        authority_context_item_ref: "authority-a".into(),
        principal_context_ref: "principal-a@3".into(),
        purpose_ref: "purpose-a".into(),
        policy_authority_epoch_ref: "authority@5".into(),
        authority_context_evidence_ref: "authority-context-proof@5".into(),
        binding_evidence_refs: set(&["instruction-authority-binding@12"]),
    }
}

fn influence(input_ref: &str, roles: &[InfluenceRole]) -> InputInfluence {
    InputInfluence {
        input_ref: input_ref.into(),
        roles: roles.iter().copied().collect(),
        role_evidence_refs: set(&["role-classification-evidence"]),
        control_binding: None,
    }
}

fn valid_record() -> ContextInfluenceRecord {
    let mut instruction = influence(
        "instruction-a",
        &[
            InfluenceRole::InstructionCandidate,
            InfluenceRole::AuthorizedCognitiveControl,
        ],
    );
    instruction.control_binding = Some(control_binding());

    ContextInfluenceRecord {
        record_id: "influence@12".into(),
        compilation_id: "compilation-a".into(),
        compilation_version: 3,
        candidate_set_revision_ref: "candidate-set@12".into(),
        selection_receipt_id: "selection@12".into(),
        tenant_ref: "tenant-a".into(),
        principal_context_ref: "principal-a@3".into(),
        purpose_ref: "purpose-a".into(),
        correction_frontier_ref: "correction@9".into(),
        policy_authority_epoch_ref: "authority@5".into(),
        influences: vec![
            instruction,
            influence("authority-a", &[InfluenceRole::PrincipalAuthorityContext]),
            influence(
                "fact-a",
                &[InfluenceRole::DataInput, InfluenceRole::SupportEvidence],
            ),
        ],
    }
}

#[test]
fn influence_is_total_over_selected_items_and_control_is_independently_bound() {
    let validated = validate_context_influence_record(&compilation(), &valid_record())
        .expect("valid influence record");
    assert!(validated.may_supply_cognitive_control("instruction-a"));
    assert!(!validated.may_supply_cognitive_control("fact-a"));
    assert!(!validated.may_supply_cognitive_control("authority-a"));
    assert!(validated_influence_has_no_effect_commit_authority(
        &validated
    ));
}

#[test]
fn excluded_candidate_cannot_become_model_visible_influence() {
    let mut record = valid_record();
    record
        .influences
        .push(influence("excluded-a", &[InfluenceRole::DataInput]));
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::UnselectedInputInfluence)
    );
}

#[test]
fn every_selected_item_must_remain_in_influence_lineage() {
    let mut record = valid_record();
    record.influences.retain(|item| item.input_ref != "fact-a");
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::MissingSelectedInfluence)
    );
}

#[test]
fn arbitrary_role_evidence_cannot_replace_the_independent_control_binding() {
    let mut record = valid_record();
    record.influences[0].control_binding = None;
    record.influences[0]
        .role_evidence_refs
        .insert("attacker-says-authorized".into());
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::ControlBindingMissing)
    );
}

#[test]
fn control_binding_cannot_use_the_instruction_as_its_own_authority_proof() {
    let mut record = valid_record();
    record.influences[0]
        .control_binding
        .as_mut()
        .expect("control binding")
        .authority_context_item_ref = "instruction-a".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::ControlAuthorityItemSelfReference)
    );
}

#[test]
fn control_authority_must_come_from_a_selected_principal_authority_context() {
    let mut record = valid_record();
    record.influences[0]
        .control_binding
        .as_mut()
        .expect("control binding")
        .authority_context_item_ref = "excluded-a".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::ControlAuthorityItemNotSelected)
    );

    let mut wrong_class_compilation = compilation();
    wrong_class_compilation.delivery_boundaries[1].information_classes =
        BTreeSet::from([ContextInformationClass::Evidence]);
    assert_eq!(
        validate_context_influence_record(&wrong_class_compilation, &valid_record()),
        Err(InfluenceError::ControlAuthorityClassMissing)
    );
}

#[test]
fn principal_purpose_and_authority_epoch_cannot_be_replayed_across_control_contexts() {
    let mut principal = valid_record();
    principal.influences[0]
        .control_binding
        .as_mut()
        .unwrap()
        .principal_context_ref = "principal-b@1".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &principal),
        Err(InfluenceError::ControlPrincipalMismatch)
    );

    let mut purpose = valid_record();
    purpose.influences[0]
        .control_binding
        .as_mut()
        .unwrap()
        .purpose_ref = "different-purpose".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &purpose),
        Err(InfluenceError::ControlPurposeMismatch)
    );

    let mut epoch = valid_record();
    epoch.influences[0]
        .control_binding
        .as_mut()
        .unwrap()
        .policy_authority_epoch_ref = "authority@old".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &epoch),
        Err(InfluenceError::ControlAuthorityEpochMismatch)
    );
}

#[test]
fn role_must_match_the_compilers_typed_delivery_classification() {
    let mut record = valid_record();
    record.influences[2].roles = BTreeSet::from([InfluenceRole::InstructionCandidate]);
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::RoleDeliveryMismatch)
    );
}

#[test]
fn correction_evidence_is_not_automatically_control_authority() {
    let mut compiled = compilation();
    compiled.delivery_boundaries[2].information_classes =
        BTreeSet::from([ContextInformationClass::Evidence]);
    let mut record = valid_record();
    record.influences[2].roles = BTreeSet::from([InfluenceRole::CorrectionEvidence]);
    record.influences[2].control_binding = None;

    let validated = validate_context_influence_record(&compiled, &record)
        .expect("correction evidence remains evidence");
    assert!(!validated.may_supply_cognitive_control("fact-a"));
}

#[test]
fn influence_record_cannot_be_replayed_across_selection_or_current_frontier() {
    let mut wrong_selection = valid_record();
    wrong_selection.selection_receipt_id = "selection@old".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &wrong_selection),
        Err(InfluenceError::SelectionReceiptMismatch)
    );

    let mut wrong_correction = valid_record();
    wrong_correction.correction_frontier_ref = "correction@old".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &wrong_correction),
        Err(InfluenceError::CorrectionFrontierMismatch)
    );

    let mut wrong_epoch = valid_record();
    wrong_epoch.policy_authority_epoch_ref = "authority@old".into();
    assert_eq!(
        validate_context_influence_record(&compilation(), &wrong_epoch),
        Err(InfluenceError::PolicyAuthorityEpochMismatch)
    );
}

#[test]
fn empty_role_evidence_fails_before_cognition_can_use_the_item() {
    let mut record = valid_record();
    record.influences[2].role_evidence_refs.clear();
    assert_eq!(
        validate_context_influence_record(&compilation(), &record),
        Err(InfluenceError::InfluenceEvidenceMissing)
    );
}
