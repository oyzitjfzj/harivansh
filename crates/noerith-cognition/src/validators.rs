use crate::{
    ContextCandidateDescriptor, ContextItemKind, ContextSelectionDisposition,
    ContextSelectionReceipt, ContextValidityFrontier, ModelQualificationProfile, ModelRequest,
    ProtectedEvidenceLocator, ProtectedEvidenceRef, ReceiverContextProfileRef, TaskEdgeKind,
    TaskGraph, TaskNode,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CognitionContractError {
    EmptyField(&'static str),
    ContextCandidateInvalidKind,
    ContextCandidateDuplicateIdentity,
    ContextCandidateScopeMismatch,
    ContextDerivedParentMissing,
    ContextDerivedSelfReference,
    ContextDerivedValidityDependencyLost,
    ContextDerivationCycle,
    ContextDerivationUngrounded,
    ContextTransformEvidenceMissing,
    ContextStructuredFactEvidenceMissing,
    ContextSelectionReceiptInvalid,
    ContextSelectionUnknownCandidate,
    ContextSelectionDuplicateDisposition,
    ContextSelectionIncomplete,
    ContextSelectionEvidenceMissing,
    ProtectedEvidenceMissing,
    ProtectedEvidenceLocatorMismatch,
    ReceiverQualificationMissing,
    ContextValidityFrontierInvalid,
    TaskNodeInvalid,
    TaskEdgeEvidenceMissing,
    DuplicateTask,
    DuplicateTaskEdge,
    EdgeReferencesUnknownTask,
    SelfEdge,
    DependencyCycle,
    QualificationEvidenceMissing,
    ModelQualificationProfileInvalid,
    ModelQualificationSurfaceMissing,
    ModelProofExceedsProfile,
    ModelVersionDrift,
    AdapterVersionDrift,
    QualityFloorUnproved,
    PrivacyConstraintUnproved,
    DataConstraintUnproved,
    ModalityUnsupported,
    ToolRequirementUnproved,
    ContextRequirementUnproved,
    StructuredOutputRequirementUnproved,
}

pub fn validate_context_candidate_set(
    candidates: &[ContextCandidateDescriptor],
    tenant_ref: &str,
    purpose_ref: &str,
) -> Result<(), CognitionContractError> {
    require_text(tenant_ref, "context_candidate_set.tenant_ref")?;
    require_text(purpose_ref, "context_candidate_set.purpose_ref")?;

    let mut by_id = BTreeMap::<&str, &ContextCandidateDescriptor>::new();
    for candidate in candidates {
        validate_context_candidate_shape(candidate, tenant_ref, purpose_ref)?;
        let item_ref = candidate.identity().item_ref.as_str();
        if by_id.insert(item_ref, candidate).is_some() {
            return Err(CognitionContractError::ContextCandidateDuplicateIdentity);
        }
    }

    let mut indegree = BTreeMap::<&str, usize>::new();
    let mut outgoing = BTreeMap::<&str, Vec<&str>>::new();
    for item_ref in by_id.keys().copied() {
        indegree.insert(item_ref, 0);
        outgoing.insert(item_ref, Vec::new());
    }

    for (item_ref, candidate) in &by_id {
        let ContextCandidateDescriptor::Derived(derived) = candidate else {
            continue;
        };
        for parent_ref in &derived.parent_item_refs {
            if parent_ref == item_ref {
                return Err(CognitionContractError::ContextDerivedSelfReference);
            }
            let Some(parent) = by_id.get(parent_ref.as_str()) else {
                return Err(CognitionContractError::ContextDerivedParentMissing);
            };
            if !candidate_validity_dependencies(parent).is_subset(&derived.validity_dependency_refs)
            {
                return Err(CognitionContractError::ContextDerivedValidityDependencyLost);
            }
            let children = outgoing
                .get_mut(parent_ref.as_str())
                .expect("known parent candidate inserted");
            children.push(item_ref);
            *indegree
                .get_mut(item_ref)
                .expect("candidate identity inserted") += 1;
        }
    }

    let mut ready: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(item_ref, degree)| (*degree == 0).then_some(*item_ref))
        .collect();
    let mut visited = 0usize;
    let mut grounded = BTreeSet::<&str>::new();

    while let Some(item_ref) = ready.pop_front() {
        visited += 1;
        let candidate = by_id.get(item_ref).expect("candidate identity inserted");
        match candidate {
            ContextCandidateDescriptor::Exact(_) | ContextCandidateDescriptor::Structured(_) => {
                grounded.insert(item_ref);
            }
            ContextCandidateDescriptor::Derived(derived) => {
                if !derived
                    .parent_item_refs
                    .iter()
                    .all(|parent| grounded.contains(parent.as_str()))
                {
                    return Err(CognitionContractError::ContextDerivationUngrounded);
                }
                grounded.insert(item_ref);
            }
        }

        for child in outgoing.get(item_ref).into_iter().flatten() {
            let degree = indegree
                .get_mut(child)
                .expect("derived child identity inserted");
            *degree -= 1;
            if *degree == 0 {
                ready.push_back(child);
            }
        }
    }

    if visited != by_id.len() {
        return Err(CognitionContractError::ContextDerivationCycle);
    }
    if grounded.len() != by_id.len() {
        return Err(CognitionContractError::ContextDerivationUngrounded);
    }
    Ok(())
}

pub fn validate_context_selection_receipt(
    candidates: &[ContextCandidateDescriptor],
    receipt: &ContextSelectionReceipt,
) -> Result<(), CognitionContractError> {
    require_text(receipt.receipt_id.as_str(), "context_selection.receipt_id")?;
    require_text(
        receipt.candidate_set_revision_ref.as_str(),
        "context_selection.candidate_set_revision_ref",
    )?;
    if receipt.selector_policy.policy_ref.trim().is_empty()
        || receipt.selector_policy.version.trim().is_empty()
        || !clean_nonempty_set(&receipt.selector_policy.qualification_evidence_refs)
    {
        return Err(CognitionContractError::ContextSelectionReceiptInvalid);
    }

    let candidate_refs: BTreeSet<&str> = candidates
        .iter()
        .map(|candidate| candidate.identity().item_ref.as_str())
        .collect();
    if candidate_refs.len() != candidates.len() {
        return Err(CognitionContractError::ContextCandidateDuplicateIdentity);
    }

    let mut seen = BTreeSet::<&str>::new();
    for disposition in &receipt.dispositions {
        let item_ref = disposition.item_ref();
        if item_ref.trim().is_empty() {
            return Err(CognitionContractError::ContextSelectionReceiptInvalid);
        }
        if !candidate_refs.contains(item_ref) {
            return Err(CognitionContractError::ContextSelectionUnknownCandidate);
        }
        if !seen.insert(item_ref) {
            return Err(CognitionContractError::ContextSelectionDuplicateDisposition);
        }
        match disposition {
            ContextSelectionDisposition::Selected {
                policy_evidence_refs,
                ..
            } => {
                if !clean_nonempty_set(policy_evidence_refs) {
                    return Err(CognitionContractError::ContextSelectionEvidenceMissing);
                }
            }
            ContextSelectionDisposition::Excluded {
                reason_refs,
                policy_evidence_refs,
                ..
            } => {
                if !clean_nonempty_set(reason_refs) || !clean_nonempty_set(policy_evidence_refs) {
                    return Err(CognitionContractError::ContextSelectionEvidenceMissing);
                }
            }
        }
    }

    if seen != candidate_refs {
        return Err(CognitionContractError::ContextSelectionIncomplete);
    }
    Ok(())
}

pub fn validate_protected_evidence_against_candidates(
    protected: &ProtectedEvidenceRef,
    candidates: &[ContextCandidateDescriptor],
) -> Result<(), CognitionContractError> {
    if protected.field_ref.trim().is_empty()
        || protected.exact_value_digest.trim().is_empty()
        || protected.proving_evidence.is_empty()
    {
        return Err(CognitionContractError::ProtectedEvidenceMissing);
    }

    for locator in &protected.proving_evidence {
        match locator {
            ProtectedEvidenceLocator::SourceSpan {
                source_ref,
                source_version,
                span_ref,
                content_digest,
            } => {
                if source_ref.trim().is_empty()
                    || span_ref.trim().is_empty()
                    || content_digest.trim().is_empty()
                {
                    return Err(CognitionContractError::ProtectedEvidenceLocatorMismatch);
                }
                let matched = candidates.iter().any(|candidate| {
                    let ContextCandidateDescriptor::Exact(exact) = candidate else {
                        return false;
                    };
                    exact.source_ref == *source_ref
                        && exact.source_version == *source_version
                        && exact.span_ref == *span_ref
                        && exact.content_digest == *content_digest
                });
                if !matched {
                    return Err(CognitionContractError::ProtectedEvidenceLocatorMismatch);
                }
            }
            ProtectedEvidenceLocator::StructuredFact {
                fact_ref,
                fact_version,
                fact_digest,
            } => {
                if fact_ref.trim().is_empty() || fact_digest.trim().is_empty() {
                    return Err(CognitionContractError::ProtectedEvidenceLocatorMismatch);
                }
                let matched = candidates.iter().any(|candidate| {
                    let ContextCandidateDescriptor::Structured(fact) = candidate else {
                        return false;
                    };
                    fact.fact_ref == *fact_ref
                        && fact.fact_version == *fact_version
                        && fact.content_digest == *fact_digest
                });
                if !matched {
                    return Err(CognitionContractError::ProtectedEvidenceLocatorMismatch);
                }
            }
        }
    }
    Ok(())
}

pub fn validate_context_validity_frontier(
    frontier: &ContextValidityFrontier,
) -> Result<(), CognitionContractError> {
    if frontier.goal.reference.trim().is_empty()
        || frontier.work.reference.trim().is_empty()
        || frontier.correction_frontier_ref.trim().is_empty()
        || frontier.policy_authority_epoch_ref.trim().is_empty()
        || !clean_set_allow_empty(&frontier.dependency_refs)
    {
        return Err(CognitionContractError::ContextValidityFrontierInvalid);
    }
    Ok(())
}

pub fn validate_receiver_context_profile(
    receiver: &ReceiverContextProfileRef,
) -> Result<(), CognitionContractError> {
    if receiver.receiver_ref.trim().is_empty()
        || receiver.receiver_version.trim().is_empty()
        || receiver.context_profile_ref.trim().is_empty()
        || !clean_nonempty_set(&receiver.qualification_evidence_refs)
    {
        return Err(CognitionContractError::ReceiverQualificationMissing);
    }
    Ok(())
}

fn validate_context_candidate_shape(
    candidate: &ContextCandidateDescriptor,
    tenant_ref: &str,
    purpose_ref: &str,
) -> Result<(), CognitionContractError> {
    let identity = candidate.identity();
    if identity.tenant_ref.trim().is_empty()
        || identity.purpose_ref.trim().is_empty()
        || identity.item_ref.trim().is_empty()
        || identity.tenant_ref != tenant_ref
        || identity.purpose_ref != purpose_ref
    {
        return Err(CognitionContractError::ContextCandidateScopeMismatch);
    }
    let boundary = candidate.boundary();
    if boundary.trust_label_ref.trim().is_empty()
        || boundary.data_use_label_ref.trim().is_empty()
        || boundary.lifecycle_label_ref.trim().is_empty()
        || candidate.content_digest().trim().is_empty()
    {
        return Err(CognitionContractError::EmptyField(
            "context_candidate.boundary_or_digest",
        ));
    }

    match candidate {
        ContextCandidateDescriptor::Exact(exact) => {
            if identity.kind != ContextItemKind::ExactSourceSpan {
                return Err(CognitionContractError::ContextCandidateInvalidKind);
            }
            if exact.source_ref.trim().is_empty()
                || exact.span_ref.trim().is_empty()
                || exact.lineage_ref.trim().is_empty()
                || !clean_set_allow_empty(&exact.validity_dependency_refs)
            {
                return Err(CognitionContractError::EmptyField(
                    "context_candidate.exact_projection",
                ));
            }
        }
        ContextCandidateDescriptor::Structured(fact) => {
            if identity.kind != ContextItemKind::StructuredFact {
                return Err(CognitionContractError::ContextCandidateInvalidKind);
            }
            if fact.fact_ref.trim().is_empty()
                || !clean_nonempty_set(&fact.provenance_refs)
                || !clean_set_allow_empty(&fact.validity_dependency_refs)
            {
                return Err(CognitionContractError::ContextStructuredFactEvidenceMissing);
            }
        }
        ContextCandidateDescriptor::Derived(derived) => {
            if identity.kind != ContextItemKind::DerivedView {
                return Err(CognitionContractError::ContextCandidateInvalidKind);
            }
            if derived.parent_item_refs.is_empty() {
                return Err(CognitionContractError::ContextDerivedParentMissing);
            }
            if derived
                .parent_item_refs
                .contains(identity.item_ref.as_str())
            {
                return Err(CognitionContractError::ContextDerivedSelfReference);
            }
            if derived.provenance_ref.trim().is_empty()
                || derived.transform_policy.policy_ref.trim().is_empty()
                || derived.transform_policy.version.trim().is_empty()
                || !clean_nonempty_set(&derived.transform_policy.qualification_evidence_refs)
                || !clean_set_allow_empty(&derived.validity_dependency_refs)
            {
                return Err(CognitionContractError::ContextTransformEvidenceMissing);
            }
        }
    }
    Ok(())
}

fn candidate_validity_dependencies(candidate: &ContextCandidateDescriptor) -> &BTreeSet<String> {
    match candidate {
        ContextCandidateDescriptor::Exact(exact) => &exact.validity_dependency_refs,
        ContextCandidateDescriptor::Structured(fact) => &fact.validity_dependency_refs,
        ContextCandidateDescriptor::Derived(derived) => &derived.validity_dependency_refs,
    }
}

pub fn validate_task_graph(graph: &TaskGraph) -> Result<(), CognitionContractError> {
    if graph.graph_id.trim().is_empty()
        || !clean_set_allow_empty(&graph.promise_refs)
        || !clean_set_allow_empty(&graph.recurrence_revision_refs)
    {
        return Err(CognitionContractError::EmptyField(
            "task_graph.identity_or_refs",
        ));
    }

    let mut nodes = BTreeMap::<&str, &TaskNode>::new();
    for node in &graph.nodes {
        validate_task_node_shape(node)?;
        if nodes.insert(node.task_ref.as_str(), node).is_some() {
            return Err(CognitionContractError::DuplicateTask);
        }
    }

    let mut indegree = BTreeMap::<&str, usize>::new();
    let mut outgoing = BTreeMap::<&str, Vec<&str>>::new();
    for task_ref in nodes.keys().copied() {
        indegree.insert(task_ref, 0);
        outgoing.insert(task_ref, Vec::new());
    }

    let mut seen_edges = BTreeSet::<(String, String, u8)>::new();
    for edge in &graph.edges {
        if edge.from_task_ref.trim().is_empty() || edge.to_task_ref.trim().is_empty() {
            return Err(CognitionContractError::EdgeReferencesUnknownTask);
        }
        if edge.from_task_ref == edge.to_task_ref {
            return Err(CognitionContractError::SelfEdge);
        }
        if !nodes.contains_key(edge.from_task_ref.as_str())
            || !nodes.contains_key(edge.to_task_ref.as_str())
        {
            return Err(CognitionContractError::EdgeReferencesUnknownTask);
        }
        if !clean_nonempty_set(&edge.evidence_refs) {
            return Err(CognitionContractError::TaskEdgeEvidenceMissing);
        }
        let edge_kind = match edge.kind {
            TaskEdgeKind::Dependency => 0,
            TaskEdgeKind::Ordering => 1,
            TaskEdgeKind::Conflict => 2,
        };
        if !seen_edges.insert((
            edge.from_task_ref.clone(),
            edge.to_task_ref.clone(),
            edge_kind,
        )) {
            return Err(CognitionContractError::DuplicateTaskEdge);
        }
        if matches!(edge.kind, TaskEdgeKind::Dependency | TaskEdgeKind::Ordering) {
            outgoing
                .get_mut(edge.from_task_ref.as_str())
                .expect("validated node")
                .push(edge.to_task_ref.as_str());
            *indegree
                .get_mut(edge.to_task_ref.as_str())
                .expect("validated node") += 1;
        }
    }

    let mut ready: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(task, degree)| (*degree == 0).then_some(*task))
        .collect();
    let mut visited = 0usize;
    while let Some(task) = ready.pop_front() {
        visited += 1;
        for next in outgoing.get(task).into_iter().flatten() {
            let degree = indegree.get_mut(next).expect("validated node");
            *degree -= 1;
            if *degree == 0 {
                ready.push_back(next);
            }
        }
    }

    if visited != nodes.len() {
        return Err(CognitionContractError::DependencyCycle);
    }
    Ok(())
}

fn validate_task_node_shape(node: &TaskNode) -> Result<(), CognitionContractError> {
    for value in [
        node.task_ref.as_str(),
        node.goal.reference.as_str(),
        node.work.reference.as_str(),
        node.semantic_operation_ref.as_str(),
        node.state_class_ref.as_str(),
        node.completion_test_ref.as_str(),
    ] {
        if value.trim().is_empty() {
            return Err(CognitionContractError::TaskNodeInvalid);
        }
    }

    if !clean_set_allow_empty(&node.required_capability_refs)
        || !clean_set_allow_empty(&node.required_evidence_refs)
        || !clean_set_allow_empty(&node.protected_aggregate_refs)
        || !clean_set_allow_empty(&node.resource_envelope.resource_refs)
        || !clean_set_allow_empty(&node.resource_envelope.placement_constraints)
        || !clean_set_allow_empty(&node.blocker_refs)
        || optional_ref_is_empty(
            node.resource_envelope
                .externally_calibrated_budget_ref
                .as_deref(),
        )
        || optional_ref_is_empty(node.waiting_condition_ref.as_deref())
        || optional_ref_is_empty(node.wake_condition_ref.as_deref())
        || optional_ref_is_empty(node.permission_requirement_ref.as_deref())
        || optional_ref_is_empty(node.trajectory_checkpoint_ref.as_deref())
        || optional_ref_is_empty(node.interrupt_scope_ref.as_deref())
        || optional_ref_is_empty(node.cancellation_scope_ref.as_deref())
    {
        return Err(CognitionContractError::TaskNodeInvalid);
    }

    if let Some(timing) = &node.timing
        && (optional_ref_is_empty(timing.schedule_ref.as_deref())
            || optional_ref_is_empty(timing.timezone_ref.as_deref())
            || optional_ref_is_empty(timing.recurrence_revision_ref.as_deref())
            || optional_ref_is_empty(timing.tolerated_window_ref.as_deref())
            || optional_ref_is_empty(timing.time_source_confidence_ref.as_deref()))
    {
        return Err(CognitionContractError::TaskNodeInvalid);
    }
    Ok(())
}

pub fn protected_conflict_pairs(graph: &TaskGraph) -> BTreeSet<(String, String)> {
    let mut pairs = BTreeSet::new();
    for (left_index, left) in graph.nodes.iter().enumerate() {
        for right in graph.nodes.iter().skip(left_index + 1) {
            if !left
                .protected_aggregate_refs
                .is_disjoint(&right.protected_aggregate_refs)
            {
                pairs.insert((left.task_ref.clone(), right.task_ref.clone()));
            }
        }
    }
    pairs
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEligibilityProof {
    pub qualification_profile_ref: String,
    pub current_model_version: String,
    pub current_adapter_version: String,
    pub quality_floor_ref: String,
    pub satisfied_privacy_constraint_refs: BTreeSet<String>,
    pub satisfied_data_constraint_refs: BTreeSet<String>,
    pub supported_modality_refs: BTreeSet<String>,
    pub supported_tool_requirement_refs: BTreeSet<String>,
    pub context_requirement_ref: String,
    pub structured_output_requirement_ref: Option<String>,
    pub evidence_refs: BTreeSet<String>,
}

pub fn validate_model_eligibility(
    request: &ModelRequest,
    profile: &ModelQualificationProfile,
    proof: &ModelEligibilityProof,
) -> Result<(), CognitionContractError> {
    validate_model_request_shape(request)?;
    validate_model_profile_shape(request, profile)?;

    if proof.qualification_profile_ref.trim().is_empty()
        || proof.current_model_version.trim().is_empty()
        || proof.current_adapter_version.trim().is_empty()
        || proof.quality_floor_ref.trim().is_empty()
        || proof.context_requirement_ref.trim().is_empty()
        || !clean_nonempty_set(&proof.evidence_refs)
        || !clean_set_allow_empty(&proof.satisfied_privacy_constraint_refs)
        || !clean_set_allow_empty(&proof.satisfied_data_constraint_refs)
        || !clean_set_allow_empty(&proof.supported_modality_refs)
        || !clean_set_allow_empty(&proof.supported_tool_requirement_refs)
        || optional_ref_is_empty(proof.structured_output_requirement_ref.as_deref())
    {
        return Err(CognitionContractError::QualificationEvidenceMissing);
    }
    if !proof
        .supported_modality_refs
        .is_subset(&profile.modality_refs)
    {
        return Err(CognitionContractError::ModelProofExceedsProfile);
    }
    if profile.model_version != proof.current_model_version {
        return Err(CognitionContractError::ModelVersionDrift);
    }
    if profile.adapter_version != proof.current_adapter_version {
        return Err(CognitionContractError::AdapterVersionDrift);
    }
    if request.quality_floor_ref != proof.quality_floor_ref {
        return Err(CognitionContractError::QualityFloorUnproved);
    }
    if !request
        .privacy_constraint_refs
        .is_subset(&proof.satisfied_privacy_constraint_refs)
    {
        return Err(CognitionContractError::PrivacyConstraintUnproved);
    }
    if !request
        .data_constraint_refs
        .is_subset(&proof.satisfied_data_constraint_refs)
    {
        return Err(CognitionContractError::DataConstraintUnproved);
    }
    if !request
        .required_modalities
        .is_subset(&proof.supported_modality_refs)
    {
        return Err(CognitionContractError::ModalityUnsupported);
    }
    if !request
        .tool_requirement_refs
        .is_subset(&proof.supported_tool_requirement_refs)
    {
        return Err(CognitionContractError::ToolRequirementUnproved);
    }
    if request.context_requirement_ref != proof.context_requirement_ref {
        return Err(CognitionContractError::ContextRequirementUnproved);
    }
    if request.structured_output_requirement_ref != proof.structured_output_requirement_ref {
        return Err(CognitionContractError::StructuredOutputRequirementUnproved);
    }
    Ok(())
}

fn validate_model_request_shape(request: &ModelRequest) -> Result<(), CognitionContractError> {
    if request.request_id.trim().is_empty()
        || request.quality_floor_ref.trim().is_empty()
        || request.context_requirement_ref.trim().is_empty()
        || request.verification_plan_ref.trim().is_empty()
        || !clean_set_allow_empty(&request.regime_refs)
        || !clean_set_allow_empty(&request.domain_refs)
        || !clean_set_allow_empty(&request.privacy_constraint_refs)
        || !clean_set_allow_empty(&request.data_constraint_refs)
        || !clean_set_allow_empty(&request.required_modalities)
        || !clean_set_allow_empty(&request.tool_requirement_refs)
        || optional_ref_is_empty(request.structured_output_requirement_ref.as_deref())
        || optional_ref_is_empty(request.deadline_resource_envelope_ref.as_deref())
    {
        return Err(CognitionContractError::QualificationEvidenceMissing);
    }
    Ok(())
}

fn validate_model_profile_shape(
    request: &ModelRequest,
    profile: &ModelQualificationProfile,
) -> Result<(), CognitionContractError> {
    if profile.model_ref.trim().is_empty()
        || profile.provider_ref.trim().is_empty()
        || profile.model_version.trim().is_empty()
        || profile.adapter_version.trim().is_empty()
        || profile.provenance_ref.trim().is_empty()
        || profile.health_ref.trim().is_empty()
        || profile.calibration_validity_ref.trim().is_empty()
        || !clean_set_allow_empty(&profile.regime_evidence_refs)
        || !clean_set_allow_empty(&profile.domain_evidence_refs)
        || !clean_set_allow_empty(&profile.heldout_distribution_refs)
        || !clean_set_allow_empty(&profile.structured_output_evidence_refs)
        || !clean_set_allow_empty(&profile.tool_reliability_evidence_refs)
        || !clean_set_allow_empty(&profile.modality_refs)
        || !clean_set_allow_empty(&profile.context_behavior_evidence_refs)
        || !clean_set_allow_empty(&profile.privacy_policy_refs)
        || !clean_set_allow_empty(&profile.data_residency_refs)
        || !clean_set_allow_empty(&profile.retention_policy_refs)
    {
        return Err(CognitionContractError::ModelQualificationProfileInvalid);
    }

    if !request.regime_refs.is_empty() && profile.regime_evidence_refs.is_empty()
        || !request.domain_refs.is_empty() && profile.domain_evidence_refs.is_empty()
        || profile.heldout_distribution_refs.is_empty()
        || request.structured_output_requirement_ref.is_some()
            && profile.structured_output_evidence_refs.is_empty()
        || !request.tool_requirement_refs.is_empty()
            && profile.tool_reliability_evidence_refs.is_empty()
        || profile.context_behavior_evidence_refs.is_empty()
        || !request.privacy_constraint_refs.is_empty() && profile.privacy_policy_refs.is_empty()
    {
        return Err(CognitionContractError::ModelQualificationSurfaceMissing);
    }
    Ok(())
}

fn clean_nonempty_set(values: &BTreeSet<String>) -> bool {
    !values.is_empty() && clean_set_allow_empty(values)
}

fn clean_set_allow_empty(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn optional_ref_is_empty(value: Option<&str>) -> bool {
    value.is_some_and(|reference| reference.trim().is_empty())
}

fn require_text(value: &str, field: &'static str) -> Result<(), CognitionContractError> {
    if value.trim().is_empty() {
        return Err(CognitionContractError::EmptyField(field));
    }
    Ok(())
}
