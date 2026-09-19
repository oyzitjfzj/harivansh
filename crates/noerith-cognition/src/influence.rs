use crate::{
    CognitionContractError, ContextCompilation, ContextDeliveryBoundary, ContextDeliveryError,
    ContextInformationClass, validate_context_candidate_set, validate_context_delivery_boundaries,
    validate_context_selection_receipt, validate_context_validity_frontier,
};
use std::collections::{BTreeMap, BTreeSet};

/// Semantic ways in which one selected context item may influence cognition.
/// These are descriptive roles. Only `AuthorizedCognitiveControl` has an
/// additional authority binding, and even that binding grants no external
/// effect/credential/permission capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InfluenceRole {
    DataInput,
    InstructionCandidate,
    SupportEvidence,
    ContradictionEvidence,
    CorrectionEvidence,
    PrincipalAuthorityContext,
    AuthorizedCognitiveControl,
}

/// Independent authority context required before an instruction candidate may
/// be treated as authoritative cognitive control. Authority is bound to the
/// current principal, purpose and policy-authority frontier rather than to a
/// free-form evidence string supplied by the instruction itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextControlBinding {
    pub authority_context_item_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub policy_authority_epoch_ref: String,
    pub authority_context_evidence_ref: String,
    pub binding_evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputInfluence {
    pub input_ref: String,
    pub roles: BTreeSet<InfluenceRole>,
    pub role_evidence_refs: BTreeSet<String>,
    pub control_binding: Option<ContextControlBinding>,
}

/// Exact binding to the compilation whose selected inputs were actually exposed
/// to cognition. Replaying this record against another compilation, selection,
/// correction frontier or authority epoch fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextInfluenceRecord {
    pub record_id: String,
    pub compilation_id: String,
    pub compilation_version: u64,
    pub candidate_set_revision_ref: String,
    pub selection_receipt_id: String,
    pub tenant_ref: String,
    pub principal_context_ref: String,
    pub purpose_ref: String,
    pub correction_frontier_ref: String,
    pub policy_authority_epoch_ref: String,
    pub influences: Vec<InputInfluence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfluenceError {
    EmptyField(&'static str),
    Contract(CognitionContractError),
    Delivery(ContextDeliveryError),
    CompilationIdentityMismatch,
    CandidateSetRevisionMismatch,
    SelectionReceiptMismatch,
    TenantMismatch,
    PrincipalContextMismatch,
    PurposeMismatch,
    CorrectionFrontierMismatch,
    PolicyAuthorityEpochMismatch,
    DuplicateInputInfluence,
    MissingSelectedInfluence,
    UnselectedInputInfluence,
    MissingInfluenceRole,
    InfluenceEvidenceMissing,
    RoleDeliveryMismatch,
    ControlBindingMissing,
    UnexpectedControlBinding,
    ControlAuthorityItemSelfReference,
    ControlAuthorityItemNotSelected,
    ControlAuthorityClassMissing,
    ControlPrincipalMismatch,
    ControlPurposeMismatch,
    ControlAuthorityEpochMismatch,
    ControlAuthorityEvidenceMismatch,
    ControlBindingEvidenceMissing,
}

/// Result of deterministic influence validation. Possessing this value means an
/// input is allowed to shape a cognition proposal; it is deliberately not a
/// credential, permission grant or external-effect authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedContextInfluence {
    pub record_id: String,
    pub compilation_id: String,
    authorized_cognitive_control_refs: BTreeSet<String>,
}

impl ValidatedContextInfluence {
    pub fn may_supply_cognitive_control(&self, input_ref: &str) -> bool {
        self.authorized_cognitive_control_refs.contains(input_ref)
    }
}

pub fn validate_context_influence_record(
    compilation: &ContextCompilation,
    record: &ContextInfluenceRecord,
) -> Result<ValidatedContextInfluence, InfluenceError> {
    for (name, value) in [
        ("influence.record_id", record.record_id.as_str()),
        ("influence.compilation_id", record.compilation_id.as_str()),
        (
            "influence.candidate_set_revision_ref",
            record.candidate_set_revision_ref.as_str(),
        ),
        (
            "influence.selection_receipt_id",
            record.selection_receipt_id.as_str(),
        ),
        ("influence.tenant_ref", record.tenant_ref.as_str()),
        (
            "influence.principal_context_ref",
            record.principal_context_ref.as_str(),
        ),
        ("influence.purpose_ref", record.purpose_ref.as_str()),
        (
            "influence.correction_frontier_ref",
            record.correction_frontier_ref.as_str(),
        ),
        (
            "influence.policy_authority_epoch_ref",
            record.policy_authority_epoch_ref.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(InfluenceError::EmptyField(name));
        }
    }

    // A public data record is never trusted merely because a caller constructed
    // it. Re-check all structural context contracts before its metadata may
    // justify cognitive influence.
    validate_context_candidate_set(
        &compilation.candidates,
        &compilation.tenant_ref,
        &compilation.purpose_ref,
    )
    .map_err(InfluenceError::Contract)?;
    validate_context_delivery_boundaries(&compilation.candidates, &compilation.delivery_boundaries)
        .map_err(InfluenceError::Delivery)?;
    validate_context_selection_receipt(&compilation.candidates, &compilation.selection_receipt)
        .map_err(InfluenceError::Contract)?;
    validate_context_validity_frontier(&compilation.validity_frontier)
        .map_err(InfluenceError::Contract)?;

    if record.compilation_id != compilation.compilation_id
        || record.compilation_version != compilation.version
    {
        return Err(InfluenceError::CompilationIdentityMismatch);
    }
    if record.candidate_set_revision_ref != compilation.candidate_set_revision_ref
        || record.candidate_set_revision_ref
            != compilation.selection_receipt.candidate_set_revision_ref
    {
        return Err(InfluenceError::CandidateSetRevisionMismatch);
    }
    if record.selection_receipt_id != compilation.selection_receipt.receipt_id {
        return Err(InfluenceError::SelectionReceiptMismatch);
    }
    if record.tenant_ref != compilation.tenant_ref {
        return Err(InfluenceError::TenantMismatch);
    }
    if record.principal_context_ref != compilation.principal_context_ref {
        return Err(InfluenceError::PrincipalContextMismatch);
    }
    if record.purpose_ref != compilation.purpose_ref {
        return Err(InfluenceError::PurposeMismatch);
    }
    if record.correction_frontier_ref != compilation.validity_frontier.correction_frontier_ref {
        return Err(InfluenceError::CorrectionFrontierMismatch);
    }
    if record.policy_authority_epoch_ref != compilation.validity_frontier.policy_authority_epoch_ref
    {
        return Err(InfluenceError::PolicyAuthorityEpochMismatch);
    }

    let selected: BTreeSet<&str> = compilation.selected_item_refs();
    let boundaries: BTreeMap<&str, &ContextDeliveryBoundary> = compilation
        .delivery_boundaries
        .iter()
        .map(|boundary| (boundary.item_ref.as_str(), boundary))
        .collect();

    let mut seen = BTreeSet::new();
    let mut authorized_controls = BTreeSet::new();

    for influence in &record.influences {
        if influence.input_ref.trim().is_empty() {
            return Err(InfluenceError::EmptyField("influence.input_ref"));
        }
        if !selected.contains(influence.input_ref.as_str()) {
            return Err(InfluenceError::UnselectedInputInfluence);
        }
        if !seen.insert(influence.input_ref.as_str()) {
            return Err(InfluenceError::DuplicateInputInfluence);
        }
        if influence.roles.is_empty() {
            return Err(InfluenceError::MissingInfluenceRole);
        }
        if influence.role_evidence_refs.is_empty()
            || influence
                .role_evidence_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(InfluenceError::InfluenceEvidenceMissing);
        }

        let boundary = boundaries
            .get(influence.input_ref.as_str())
            .expect("validated delivery boundary is total");

        for role in &influence.roles {
            let required_class = match role {
                InfluenceRole::DataInput => ContextInformationClass::ContentData,
                InfluenceRole::InstructionCandidate | InfluenceRole::AuthorizedCognitiveControl => {
                    ContextInformationClass::InstructionCandidate
                }
                InfluenceRole::SupportEvidence
                | InfluenceRole::ContradictionEvidence
                | InfluenceRole::CorrectionEvidence => ContextInformationClass::Evidence,
                InfluenceRole::PrincipalAuthorityContext => {
                    ContextInformationClass::PrincipalAuthorityContext
                }
            };
            if !boundary.information_classes.contains(&required_class) {
                return Err(InfluenceError::RoleDeliveryMismatch);
            }
        }

        let asks_for_control = influence
            .roles
            .contains(&InfluenceRole::AuthorizedCognitiveControl);
        match (asks_for_control, influence.control_binding.as_ref()) {
            (true, None) => return Err(InfluenceError::ControlBindingMissing),
            (false, Some(_)) => return Err(InfluenceError::UnexpectedControlBinding),
            (false, None) => {}
            (true, Some(binding)) => {
                validate_control_binding(
                    compilation,
                    record,
                    influence,
                    binding,
                    &selected,
                    &boundaries,
                )?;
                authorized_controls.insert(influence.input_ref.clone());
            }
        }
    }

    if seen != selected {
        return Err(InfluenceError::MissingSelectedInfluence);
    }

    Ok(ValidatedContextInfluence {
        record_id: record.record_id.clone(),
        compilation_id: record.compilation_id.clone(),
        authorized_cognitive_control_refs: authorized_controls,
    })
}

fn validate_control_binding(
    compilation: &ContextCompilation,
    record: &ContextInfluenceRecord,
    influence: &InputInfluence,
    binding: &ContextControlBinding,
    selected: &BTreeSet<&str>,
    boundaries: &BTreeMap<&str, &ContextDeliveryBoundary>,
) -> Result<(), InfluenceError> {
    for (name, value) in [
        (
            "control.authority_context_item_ref",
            binding.authority_context_item_ref.as_str(),
        ),
        (
            "control.principal_context_ref",
            binding.principal_context_ref.as_str(),
        ),
        ("control.purpose_ref", binding.purpose_ref.as_str()),
        (
            "control.policy_authority_epoch_ref",
            binding.policy_authority_epoch_ref.as_str(),
        ),
        (
            "control.authority_context_evidence_ref",
            binding.authority_context_evidence_ref.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(InfluenceError::EmptyField(name));
        }
    }
    if binding.binding_evidence_refs.is_empty()
        || binding
            .binding_evidence_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
    {
        return Err(InfluenceError::ControlBindingEvidenceMissing);
    }
    if binding.authority_context_item_ref == influence.input_ref {
        return Err(InfluenceError::ControlAuthorityItemSelfReference);
    }
    if !selected.contains(binding.authority_context_item_ref.as_str()) {
        return Err(InfluenceError::ControlAuthorityItemNotSelected);
    }

    let authority_boundary = boundaries
        .get(binding.authority_context_item_ref.as_str())
        .expect("selected item has validated delivery boundary");
    if !authority_boundary
        .information_classes
        .contains(&ContextInformationClass::PrincipalAuthorityContext)
    {
        return Err(InfluenceError::ControlAuthorityClassMissing);
    }

    if binding.principal_context_ref != record.principal_context_ref
        || binding.principal_context_ref != compilation.principal_context_ref
        || authority_boundary.principal_scope_ref.as_deref()
            != Some(binding.principal_context_ref.as_str())
    {
        return Err(InfluenceError::ControlPrincipalMismatch);
    }
    if binding.purpose_ref != record.purpose_ref || binding.purpose_ref != compilation.purpose_ref {
        return Err(InfluenceError::ControlPurposeMismatch);
    }
    if binding.policy_authority_epoch_ref != record.policy_authority_epoch_ref
        || binding.policy_authority_epoch_ref
            != compilation.validity_frontier.policy_authority_epoch_ref
    {
        return Err(InfluenceError::ControlAuthorityEpochMismatch);
    }
    if authority_boundary.authority_context_evidence_ref.as_deref()
        != Some(binding.authority_context_evidence_ref.as_str())
    {
        return Err(InfluenceError::ControlAuthorityEvidenceMismatch);
    }
    Ok(())
}

/// A validated influence record is evidence about how selected context may
/// shape cognition only. It is not effect permission or release authority.
pub const fn validated_influence_has_no_effect_commit_authority(
    _validated: &ValidatedContextInfluence,
) -> bool {
    true
}
