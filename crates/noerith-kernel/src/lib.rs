#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    TenantMismatch,
    PrincipalMismatch,
    TargetAccountNotAllowed,
    Expired,
    Revoked,
    DelegationAmplification,
    GrantExhausted,
    MessageIntegrityConflict,
    StaleGoal,
    StaleWork,
    StaleState,
    StalePolicy,
    StaleGrant,
    StaleRevocationEpoch,
    StaleFence,
    StaleInterruptWatermark,
    PayloadChanged,
    CancelledBeforeRelease,
    PolicyDenied,
    PolicyIndeterminate,
    MissingObligationEvidence,
    InvalidTransition,
    StaleLifecycleEpoch,
    SourceDeleted,
    StaleBackup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockClock {
    now: u64,
}

impl MockClock {
    pub fn new(now: u64) -> Self {
        Self { now }
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn advance(&mut self, delta: u64) {
        self.now = self.now.saturating_add(delta);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalContext {
    pub tenant_namespace: String,
    pub controlling_principal: String,
    pub acting_workload: Option<String>,
    pub target_accounts: BTreeSet<String>,
    pub revocation_epoch: u64,
    pub expires_at: u64,
}

impl PrincipalContext {
    pub fn authorize(
        &self,
        now: u64,
        expected_tenant: &str,
        expected_principal: &str,
        target_account: &str,
        minimum_revocation_epoch: u64,
    ) -> Result<(), KernelError> {
        if self.tenant_namespace != expected_tenant {
            return Err(KernelError::TenantMismatch);
        }
        if self.controlling_principal != expected_principal {
            return Err(KernelError::PrincipalMismatch);
        }
        if !self.target_accounts.contains(target_account) {
            return Err(KernelError::TargetAccountNotAllowed);
        }
        if now >= self.expires_at {
            return Err(KernelError::Expired);
        }
        if self.revocation_epoch < minimum_revocation_epoch {
            return Err(KernelError::Revoked);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Autonomy {
    Observe,
    Suggest,
    Prepare,
    Once,
    BoundedAuto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationGrant {
    pub grant_id: String,
    pub allowed_operations: BTreeSet<String>,
    pub allowed_targets: BTreeSet<String>,
    pub allowed_audiences: BTreeSet<String>,
    pub purposes: BTreeSet<String>,
    pub data_classes: BTreeSet<String>,
    pub autonomy_ceiling: Autonomy,
    pub expires_at: u64,
    pub use_limit: u64,
    pub consumed_count: u64,
    pub revocation_epoch: u64,
}

impl DelegationGrant {
    pub fn validate_subgrant_of(&self, parent: &Self) -> Result<(), KernelError> {
        let subset = self
            .allowed_operations
            .is_subset(&parent.allowed_operations)
            && self.allowed_targets.is_subset(&parent.allowed_targets)
            && self.allowed_audiences.is_subset(&parent.allowed_audiences)
            && self.purposes.is_subset(&parent.purposes)
            && self.data_classes.is_subset(&parent.data_classes);
        let bounded = self.autonomy_ceiling <= parent.autonomy_ceiling
            && self.expires_at <= parent.expires_at
            && self.use_limit <= parent.use_limit.saturating_sub(parent.consumed_count);
        if !subset || !bounded {
            return Err(KernelError::DelegationAmplification);
        }
        Ok(())
    }

    pub fn consume(&mut self, now: u64, current_revocation_epoch: u64) -> Result<(), KernelError> {
        if now >= self.expires_at {
            return Err(KernelError::Expired);
        }
        if self.revocation_epoch < current_revocation_epoch {
            return Err(KernelError::Revoked);
        }
        if self.consumed_count >= self.use_limit {
            return Err(KernelError::GrantExhausted);
        }
        self.consumed_count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeAccept {
    New,
    Duplicate,
}

#[derive(Debug, Default)]
pub struct EnvelopeLedger {
    seen: BTreeMap<String, String>,
}

impl EnvelopeLedger {
    pub fn accept(
        &mut self,
        message_id: impl Into<String>,
        payload_digest: impl Into<String>,
    ) -> Result<EnvelopeAccept, KernelError> {
        let message_id = message_id.into();
        let payload_digest = payload_digest.into();
        match self.seen.get(&message_id) {
            None => {
                self.seen.insert(message_id, payload_digest);
                Ok(EnvelopeAccept::New)
            }
            Some(existing) if existing == &payload_digest => Ok(EnvelopeAccept::Duplicate),
            Some(_) => Err(KernelError::MessageIntegrityConflict),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSnapshot {
    pub goal_version: u64,
    pub work_version: u64,
    pub state_revision: u64,
    pub policy_version: u64,
    pub grant_id: String,
    pub revocation_epoch: u64,
    pub fence: u64,
    pub interrupt_watermark: u64,
    pub payload_digest: String,
    pub target_account: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentDecisionState {
    pub goal_version: u64,
    pub work_version: u64,
    pub state_revision: u64,
    pub policy_version: u64,
    pub grant_id: String,
    pub revocation_epoch: u64,
    pub fence: u64,
    pub interrupt_watermark: u64,
    pub payload_digest: String,
    pub target_account: String,
    pub cancel_before_release: bool,
}

pub fn validate_snapshot(
    snapshot: &DecisionSnapshot,
    current: &CurrentDecisionState,
    now: u64,
) -> Result<(), KernelError> {
    if now >= snapshot.expires_at {
        return Err(KernelError::Expired);
    }
    if current.cancel_before_release {
        return Err(KernelError::CancelledBeforeRelease);
    }
    if snapshot.goal_version != current.goal_version {
        return Err(KernelError::StaleGoal);
    }
    if snapshot.work_version != current.work_version {
        return Err(KernelError::StaleWork);
    }
    if snapshot.state_revision != current.state_revision {
        return Err(KernelError::StaleState);
    }
    if snapshot.policy_version != current.policy_version {
        return Err(KernelError::StalePolicy);
    }
    if snapshot.grant_id != current.grant_id {
        return Err(KernelError::StaleGrant);
    }
    if snapshot.revocation_epoch != current.revocation_epoch {
        return Err(KernelError::StaleRevocationEpoch);
    }
    if snapshot.fence != current.fence {
        return Err(KernelError::StaleFence);
    }
    if snapshot.interrupt_watermark != current.interrupt_watermark {
        return Err(KernelError::StaleInterruptWatermark);
    }
    if snapshot.payload_digest != current.payload_digest {
        return Err(KernelError::PayloadChanged);
    }
    if snapshot.target_account != current.target_account {
        return Err(KernelError::TargetAccountNotAllowed);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResult {
    Permit,
    Deny,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub policy_version: u64,
    pub result: PolicyResult,
    pub obligations: BTreeSet<String>,
}

pub fn validate_policy(
    decision: &PolicyDecision,
    expected_policy_version: u64,
    satisfied_evidence: &BTreeSet<String>,
) -> Result<(), KernelError> {
    if decision.policy_version != expected_policy_version {
        return Err(KernelError::StalePolicy);
    }
    match decision.result {
        PolicyResult::Deny => return Err(KernelError::PolicyDenied),
        PolicyResult::Indeterminate => return Err(KernelError::PolicyIndeterminate),
        PolicyResult::Permit => {}
    }
    if !decision.obligations.is_subset(satisfied_evidence) {
        return Err(KernelError::MissingObligationEvidence);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectState {
    Prepared,
    Claimed,
    Dispatched,
    AcceptanceUnknown,
    Accepted,
    Verified,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectIntent {
    pub intent_id: String,
    pub idempotency_key: String,
    pub state: EffectState,
    pub claim_fence: Option<u64>,
    seen_callbacks: BTreeSet<String>,
}

impl EffectIntent {
    pub fn new(intent_id: impl Into<String>, idempotency_key: impl Into<String>) -> Self {
        Self {
            intent_id: intent_id.into(),
            idempotency_key: idempotency_key.into(),
            state: EffectState::Prepared,
            claim_fence: None,
            seen_callbacks: BTreeSet::new(),
        }
    }

    pub fn claim(&mut self, worker_fence: u64, current_fence: u64) -> Result<(), KernelError> {
        if self.state != EffectState::Prepared {
            return Err(KernelError::InvalidTransition);
        }
        if worker_fence != current_fence {
            return Err(KernelError::StaleFence);
        }
        self.claim_fence = Some(worker_fence);
        self.state = EffectState::Claimed;
        Ok(())
    }

    pub fn cancel_before_release(&mut self) -> Result<(), KernelError> {
        match self.state {
            EffectState::Prepared | EffectState::Claimed => {
                self.state = EffectState::Cancelled;
                Ok(())
            }
            _ => Err(KernelError::InvalidTransition),
        }
    }

    pub fn mark_dispatched(&mut self, current_fence: u64) -> Result<(), KernelError> {
        if self.state != EffectState::Claimed {
            return Err(KernelError::InvalidTransition);
        }
        if self.claim_fence != Some(current_fence) {
            return Err(KernelError::StaleFence);
        }
        self.state = EffectState::Dispatched;
        Ok(())
    }

    pub fn possible_send_then_crash(&mut self) -> Result<(), KernelError> {
        if self.state != EffectState::Dispatched {
            return Err(KernelError::InvalidTransition);
        }
        self.state = EffectState::AcceptanceUnknown;
        Ok(())
    }

    pub fn may_retry_after_unknown(&self, provider_has_stable_idempotency: bool) -> bool {
        self.state == EffectState::AcceptanceUnknown && provider_has_stable_idempotency
    }

    pub fn apply_provider_callback(
        &mut self,
        callback_id: impl Into<String>,
        accepted: bool,
    ) -> Result<bool, KernelError> {
        let callback_id = callback_id.into();
        if !self.seen_callbacks.insert(callback_id) {
            return Ok(false);
        }
        match self.state {
            EffectState::Dispatched | EffectState::AcceptanceUnknown => {
                self.state = if accepted {
                    EffectState::Accepted
                } else {
                    EffectState::Failed
                };
                Ok(true)
            }
            EffectState::Accepted | EffectState::Failed | EffectState::Verified => Ok(true),
            _ => Err(KernelError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    Active,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyRecord {
    pub lifecycle_epoch_seen: u64,
    pub purge_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceState {
    pub source_id: String,
    pub lifecycle_epoch: u64,
    pub status: SourceStatus,
    pub copies: BTreeMap<String, CopyRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedUse {
    pub source_id: String,
    pub lifecycle_epoch: u64,
}

impl SourceState {
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            lifecycle_epoch: 0,
            status: SourceStatus::Active,
            copies: BTreeMap::new(),
        }
    }

    pub fn register_copy(&mut self, copy_id: impl Into<String>) {
        self.copies.insert(
            copy_id.into(),
            CopyRecord {
                lifecycle_epoch_seen: self.lifecycle_epoch,
                purge_confirmed: false,
            },
        );
    }

    pub fn prepare_use(&self) -> Result<PreparedUse, KernelError> {
        if self.status != SourceStatus::Active {
            return Err(KernelError::SourceDeleted);
        }
        Ok(PreparedUse {
            source_id: self.source_id.clone(),
            lifecycle_epoch: self.lifecycle_epoch,
        })
    }

    pub fn commit_use(&self, prepared: &PreparedUse) -> Result<(), KernelError> {
        if self.status != SourceStatus::Active {
            return Err(KernelError::SourceDeleted);
        }
        if prepared.source_id != self.source_id || prepared.lifecycle_epoch != self.lifecycle_epoch
        {
            return Err(KernelError::StaleLifecycleEpoch);
        }
        Ok(())
    }

    pub fn delete(&mut self) {
        self.lifecycle_epoch = self.lifecycle_epoch.saturating_add(1);
        self.status = SourceStatus::Deleted;
        for copy in self.copies.values_mut() {
            copy.purge_confirmed = false;
        }
    }

    pub fn accept_restored_copy(
        &self,
        copy_id: &str,
        restored_epoch: u64,
    ) -> Result<(), KernelError> {
        if self.status == SourceStatus::Deleted && restored_epoch < self.lifecycle_epoch {
            return Err(KernelError::StaleBackup);
        }
        let Some(copy) = self.copies.get(copy_id) else {
            return Err(KernelError::StaleBackup);
        };
        if restored_epoch < copy.lifecycle_epoch_seen {
            return Err(KernelError::StaleBackup);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkStatus {
    Running,
    Waiting,
    Completed,
    Cancelled,
}

#[derive(Debug, Default)]
pub struct WorkRegistry {
    work: BTreeMap<String, WorkStatus>,
}

impl WorkRegistry {
    pub fn insert(&mut self, id: impl Into<String>, status: WorkStatus) {
        self.work.insert(id.into(), status);
    }

    pub fn status(&self, id: &str) -> Option<WorkStatus> {
        self.work.get(id).copied()
    }

    pub fn accept_new_request(&mut self, new_id: impl Into<String>) {
        self.work.insert(new_id.into(), WorkStatus::Running);
    }
}

#[derive(Debug, Default)]
pub struct MockStorage {
    pub sources: BTreeMap<String, SourceState>,
    pub effects: BTreeMap<String, EffectIntent>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn snapshot() -> DecisionSnapshot {
        DecisionSnapshot {
            goal_version: 4,
            work_version: 8,
            state_revision: 12,
            policy_version: 3,
            grant_id: "grant-1".into(),
            revocation_epoch: 7,
            fence: 22,
            interrupt_watermark: 15,
            payload_digest: "payload-a".into(),
            target_account: "account-a".into(),
            expires_at: 1_000,
        }
    }

    fn current() -> CurrentDecisionState {
        CurrentDecisionState {
            goal_version: 4,
            work_version: 8,
            state_revision: 12,
            policy_version: 3,
            grant_id: "grant-1".into(),
            revocation_epoch: 7,
            fence: 22,
            interrupt_watermark: 15,
            payload_digest: "payload-a".into(),
            target_account: "account-a".into(),
            cancel_before_release: false,
        }
    }

    #[test]
    fn wrong_account_or_principal_is_rejected() {
        let context = PrincipalContext {
            tenant_namespace: "tenant-a".into(),
            controlling_principal: "user-a".into(),
            acting_workload: Some("worker-a".into()),
            target_accounts: set(&["account-a"]),
            revocation_epoch: 9,
            expires_at: 500,
        };
        assert_eq!(
            context.authorize(100, "tenant-a", "user-b", "account-a", 9),
            Err(KernelError::PrincipalMismatch)
        );
        assert_eq!(
            context.authorize(100, "tenant-a", "user-a", "account-b", 9),
            Err(KernelError::TargetAccountNotAllowed)
        );
    }

    #[test]
    fn delegation_scope_expansion_is_rejected() {
        let parent = DelegationGrant {
            grant_id: "parent".into(),
            allowed_operations: set(&["read", "prepare"]),
            allowed_targets: set(&["account-a"]),
            allowed_audiences: set(&["user-a"]),
            purposes: set(&["project"]),
            data_classes: set(&["private"]),
            autonomy_ceiling: Autonomy::Prepare,
            expires_at: 500,
            use_limit: 2,
            consumed_count: 0,
            revocation_epoch: 1,
        };
        let mut child = parent.clone();
        child.grant_id = "child".into();
        child.allowed_targets.insert("account-b".into());
        assert_eq!(
            child.validate_subgrant_of(&parent),
            Err(KernelError::DelegationAmplification)
        );
    }

    #[test]
    fn stale_goal_snapshot_or_fence_is_rejected() {
        let baseline = snapshot();
        let mut state = current();
        assert_eq!(validate_snapshot(&baseline, &state, 100), Ok(()));

        state.goal_version += 1;
        assert_eq!(
            validate_snapshot(&baseline, &state, 100),
            Err(KernelError::StaleGoal)
        );

        state = current();
        state.payload_digest = "payload-b".into();
        assert_eq!(
            validate_snapshot(&baseline, &state, 100),
            Err(KernelError::PayloadChanged)
        );

        state = current();
        state.fence += 1;
        assert_eq!(
            validate_snapshot(&baseline, &state, 100),
            Err(KernelError::StaleFence)
        );
    }

    #[test]
    fn revoke_or_cancel_before_release_blocks_effect() {
        let baseline = snapshot();
        let mut state = current();
        state.revocation_epoch += 1;
        assert_eq!(
            validate_snapshot(&baseline, &state, 100),
            Err(KernelError::StaleRevocationEpoch)
        );

        state = current();
        state.cancel_before_release = true;
        assert_eq!(
            validate_snapshot(&baseline, &state, 100),
            Err(KernelError::CancelledBeforeRelease)
        );

        let mut effect = EffectIntent::new("intent-1", "idem-1");
        effect.claim(3, 3).expect("current worker may claim");
        effect
            .cancel_before_release()
            .expect("cancel before dispatch must succeed");
        assert_eq!(effect.state, EffectState::Cancelled);
    }

    #[test]
    fn possible_send_followed_by_crash_remains_unknown_and_no_blind_retry() {
        let mut effect = EffectIntent::new("intent-1", "idem-1");
        effect.claim(8, 8).expect("claim");
        effect.mark_dispatched(8).expect("dispatch");
        effect.possible_send_then_crash().expect("ambiguous crash");
        assert_eq!(effect.state, EffectState::AcceptanceUnknown);
        assert!(!effect.may_retry_after_unknown(false));
        assert!(effect.may_retry_after_unknown(true));
        assert_eq!(effect.intent_id, "intent-1");
        assert_eq!(effect.idempotency_key, "idem-1");
    }

    #[test]
    fn duplicate_provider_callbacks_do_not_duplicate_transition() {
        let mut effect = EffectIntent::new("intent-1", "idem-1");
        effect.claim(2, 2).expect("claim");
        effect.mark_dispatched(2).expect("dispatch");
        assert_eq!(effect.apply_provider_callback("cb-1", true), Ok(true));
        assert_eq!(effect.state, EffectState::Accepted);
        assert_eq!(effect.apply_provider_callback("cb-1", true), Ok(false));
        assert_eq!(effect.state, EffectState::Accepted);
    }

    #[test]
    fn one_use_grant_cannot_be_reused() {
        let mut grant = DelegationGrant {
            grant_id: "one".into(),
            allowed_operations: set(&["publish"]),
            allowed_targets: set(&["account-a"]),
            allowed_audiences: set(&["user-a"]),
            purposes: set(&["project"]),
            data_classes: set(&["private"]),
            autonomy_ceiling: Autonomy::Once,
            expires_at: 500,
            use_limit: 1,
            consumed_count: 0,
            revocation_epoch: 4,
        };
        assert_eq!(grant.consume(100, 4), Ok(()));
        assert_eq!(grant.consume(101, 4), Err(KernelError::GrantExhausted));
    }

    #[test]
    fn delete_between_prepare_and_disclose_blocks_stale_use() {
        let mut source = SourceState::new("source-1");
        let prepared = source.prepare_use().expect("active source");
        source.delete();
        assert_eq!(
            source.commit_use(&prepared),
            Err(KernelError::SourceDeleted)
        );
    }

    #[test]
    fn stale_backup_cannot_resurrect_deleted_source() {
        let mut source = SourceState::new("source-1");
        source.register_copy("backup-1");
        let old_epoch = source.lifecycle_epoch;
        source.delete();
        assert_eq!(
            source.accept_restored_copy("backup-1", old_epoch),
            Err(KernelError::StaleBackup)
        );
    }

    #[test]
    fn new_request_does_not_pause_unrelated_existing_work() {
        let mut registry = WorkRegistry::default();
        registry.insert("existing", WorkStatus::Running);
        registry.accept_new_request("new");
        assert_eq!(registry.status("existing"), Some(WorkStatus::Running));
        assert_eq!(registry.status("new"), Some(WorkStatus::Running));
    }

    #[test]
    fn same_message_with_different_payload_is_integrity_conflict() {
        let mut ledger = EnvelopeLedger::default();
        assert_eq!(ledger.accept("m-1", "digest-a"), Ok(EnvelopeAccept::New));
        assert_eq!(
            ledger.accept("m-1", "digest-a"),
            Ok(EnvelopeAccept::Duplicate)
        );
        assert_eq!(
            ledger.accept("m-1", "digest-b"),
            Err(KernelError::MessageIntegrityConflict)
        );
    }

    #[test]
    fn stale_worker_fence_cannot_release() {
        let mut effect = EffectIntent::new("intent-1", "idem-1");
        assert_eq!(effect.claim(7, 8), Err(KernelError::StaleFence));
        assert_eq!(effect.state, EffectState::Prepared);
        effect.claim(8, 8).expect("current fence may claim");
        assert_eq!(effect.mark_dispatched(9), Err(KernelError::StaleFence));
        assert_eq!(effect.state, EffectState::Claimed);
    }

    #[test]
    fn policy_is_fail_closed_and_obligations_are_required() {
        let obligations = set(&["confirm-target", "record-receipt"]);
        let permit = PolicyDecision {
            policy_version: 5,
            result: PolicyResult::Permit,
            obligations: obligations.clone(),
        };
        assert_eq!(
            validate_policy(&permit, 5, &set(&["confirm-target"])),
            Err(KernelError::MissingObligationEvidence)
        );
        assert_eq!(validate_policy(&permit, 5, &obligations), Ok(()));

        let deny = PolicyDecision {
            policy_version: 5,
            result: PolicyResult::Deny,
            obligations: BTreeSet::new(),
        };
        assert_eq!(
            validate_policy(&deny, 5, &BTreeSet::new()),
            Err(KernelError::PolicyDenied)
        );

        let indeterminate = PolicyDecision {
            policy_version: 5,
            result: PolicyResult::Indeterminate,
            obligations: BTreeSet::new(),
        };
        assert_eq!(
            validate_policy(&indeterminate, 5, &BTreeSet::new()),
            Err(KernelError::PolicyIndeterminate)
        );
    }

    #[test]
    fn mock_clock_is_monotonic_for_test_durations() {
        let mut clock = MockClock::new(10);
        clock.advance(5);
        assert_eq!(clock.now(), 15);
    }
}
