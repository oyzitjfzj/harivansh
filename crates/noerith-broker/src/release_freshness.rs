use crate::BrokerError;
use noerith_effects::{DigestRef, MonotonicDeadline, SynchronizationState, VersionedRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueVersionRef {
    pub ref_id: String,
    pub version: String,
}

/// Decision-sensitive time observed at the final controlled-release gate.
///
/// `unix_time_ms` is a physical-time center. The true instant is conservatively
/// treated as lying in `[center - uncertainty_before_ms, center +
/// uncertainty_after_ms]`. `monotonic_*` is meaningful only inside the
/// qualified runtime identified by `monotonic_clock_ref`; it is never a global
/// timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseTimeObservation {
    pub unix_time_ms: u64,
    pub uncertainty_before_ms: u64,
    pub uncertainty_after_ms: u64,
    pub clock_source: String,
    pub synchronization_state: SynchronizationState,
    pub monotonic_clock_ref: String,
    pub monotonic_tick: u64,
}

impl ReleaseTimeObservation {
    pub fn latest_possible_ms(&self) -> Result<u64, ReleaseFreshnessError> {
        if self.clock_source.trim().is_empty() || self.monotonic_clock_ref.trim().is_empty() {
            return Err(ReleaseFreshnessError::InvalidTimeObservation);
        }
        if self.synchronization_state != SynchronizationState::Synced {
            return Err(ReleaseFreshnessError::ClockUnqualified);
        }
        self.unix_time_ms
            .checked_add(self.uncertainty_after_ms)
            .ok_or(ReleaseFreshnessError::ClockUncertaintyOverflow)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFreshnessSnapshot {
    pub tenant_namespace: String,
    pub effect_intent_id: String,
    pub decision_snapshot: DigestRef,
    pub principal_context: DigestRef,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub state_revision: u64,
    pub policy: OpaqueVersionRef,
    pub authority_grant_ref: String,
    pub revocation_epoch: u64,
    pub interrupt_watermark: u64,
    pub payload_digest: String,
    pub target_resources: BTreeSet<String>,
    pub target_accounts: BTreeSet<String>,
    pub target_principals: BTreeSet<String>,
    pub capability: OpaqueVersionRef,
    pub environment: OpaqueVersionRef,
    pub dispatch_owner: String,
    pub dispatch_lease_expires_at_ms: u64,
    pub fence: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentReleaseState {
    pub tenant_namespace: String,
    pub effect_intent_id: String,
    pub decision_snapshot: DigestRef,
    pub principal_context: DigestRef,
    pub goal: VersionedRef,
    pub work: VersionedRef,
    pub state_revision: u64,
    pub policy: OpaqueVersionRef,
    pub authority_grant_ref: String,
    pub revocation_epoch: u64,
    pub interrupt_watermark: u64,
    pub payload_digest: String,
    pub target_resources: BTreeSet<String>,
    pub target_accounts: BTreeSet<String>,
    pub target_principals: BTreeSet<String>,
    pub capability: OpaqueVersionRef,
    pub environment: OpaqueVersionRef,
    pub dispatch_owner: String,
    pub dispatch_lease_expires_at_ms: u64,
    pub fence: u64,
    pub cancel_before_release: bool,
    pub execution_healthy: bool,
}

/// A guard returned by the authoritative owner of protected release state.
///
/// Existing S03 callers expose `current_state` and a scalar observation while
/// the typed-time + immutable-pinned-snapshot integration is being wired into
/// the actual sink. Those legacy methods are intentionally kept only to avoid a
/// half-migrated uncompilable branch; they are not final-grade freshness proof.
///
/// A final qualified implementation must additionally source the pinned
/// projection from the immutable Decision Snapshot owner and use a typed final
/// time observation. It must not reconstruct either from caller assertions.
pub trait ReleaseFreshnessGuard {
    fn current_state(&self) -> &CurrentReleaseState;
    fn observed_at_ms(&self) -> u64;

    fn pinned_snapshot(&self) -> Option<&ReleaseFreshnessSnapshot> {
        None
    }

    fn time_observation(&self) -> Option<&ReleaseTimeObservation> {
        None
    }
}

/// Boundary through which the broker obtains authoritative release-time state.
///
/// `expected` is a lookup/binding hint only. Final-grade implementations must
/// load immutable pinned snapshot truth independently rather than trusting it.
pub trait ReleaseFreshnessAuthority {
    type Guard<'a>: ReleaseFreshnessGuard
    where
        Self: 'a;

    fn acquire<'a>(
        &'a mut self,
        expected: &ReleaseFreshnessSnapshot,
    ) -> Result<Self::Guard<'a>, BrokerError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFreshnessProof {
    decision_snapshot: DigestRef,
    dispatch_owner: String,
    dispatch_lease_expires_at_ms: u64,
    fence: u64,
    verified_at_ms: u64,
    snapshot_digest: String,
    current_state_digest: String,
}

impl ReleaseFreshnessProof {
    pub fn decision_snapshot(&self) -> &DigestRef {
        &self.decision_snapshot
    }

    pub fn dispatch_owner(&self) -> &str {
        &self.dispatch_owner
    }

    pub fn dispatch_lease_expires_at_ms(&self) -> u64 {
        self.dispatch_lease_expires_at_ms
    }

    pub fn fence(&self) -> u64 {
        self.fence
    }

    pub fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    /// Internal projection digest only. The protected Decision Snapshot's
    /// canonical digest remains `decision_snapshot.digest`.
    pub fn snapshot_digest(&self) -> &str {
        &self.snapshot_digest
    }

    pub fn current_state_digest(&self) -> &str {
        &self.current_state_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseFreshnessError {
    InvalidSnapshot,
    SnapshotProjectionMismatch,
    InvalidTimeObservation,
    ClockUnqualified,
    ClockUncertaintyOverflow,
    MonotonicClockMismatch,
    MonotonicDeadlineExpired,
    Expired,
    Cancelled,
    ExecutionUnhealthy,
    ScopeChanged,
    DecisionSnapshotChanged,
    StalePrincipal,
    StaleGoal,
    StaleWork,
    StaleState,
    StalePolicy,
    StaleGrant,
    StaleRevocationEpoch,
    StaleInterruptWatermark,
    PayloadChanged,
    TargetsChanged,
    CapabilityChanged,
    EnvironmentChanged,
    StaleDispatchClaim,
    StaleFence,
}

impl std::fmt::Display for ReleaseFreshnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "release freshness rejected: {self:?}")
    }
}

impl std::error::Error for ReleaseFreshnessError {}

/// Compatibility verifier for the still-migrating sink. This proves equality
/// against authoritative current state but does not prove that the caller's
/// projection came from the immutable Decision Snapshot and does not model
/// clock uncertainty. New final-sink code must use `verify_bound_release_freshness`.
pub fn verify_release_freshness(
    snapshot: &ReleaseFreshnessSnapshot,
    current: &CurrentReleaseState,
    observed_at_ms: u64,
) -> Result<ReleaseFreshnessProof, ReleaseFreshnessError> {
    validate_snapshot_shape(snapshot)?;
    verify_material_state(snapshot, current, observed_at_ms)?;
    build_proof(snapshot, current, observed_at_ms)
}

/// Final-grade verifier: three-way binds caller expectation -> immutable pinned
/// Decision Snapshot projection -> authoritative current state, then checks an
/// uncertainty-aware physical bound and a same-runtime monotonic deadline.
pub fn verify_bound_release_freshness(
    expected: &ReleaseFreshnessSnapshot,
    pinned: &ReleaseFreshnessSnapshot,
    current: &CurrentReleaseState,
    observed: &ReleaseTimeObservation,
    monotonic_deadline: &MonotonicDeadline,
) -> Result<ReleaseFreshnessProof, ReleaseFreshnessError> {
    validate_snapshot_shape(expected)?;
    validate_snapshot_shape(pinned)?;
    if expected != pinned {
        return Err(ReleaseFreshnessError::SnapshotProjectionMismatch);
    }

    let latest_possible_ms = observed.latest_possible_ms()?;
    if monotonic_deadline.clock_ref.trim().is_empty() || monotonic_deadline.deadline_tick == 0 {
        return Err(ReleaseFreshnessError::InvalidTimeObservation);
    }
    if observed.monotonic_clock_ref != monotonic_deadline.clock_ref {
        return Err(ReleaseFreshnessError::MonotonicClockMismatch);
    }
    if observed.monotonic_tick >= monotonic_deadline.deadline_tick {
        return Err(ReleaseFreshnessError::MonotonicDeadlineExpired);
    }

    verify_material_state(pinned, current, latest_possible_ms)?;
    build_proof(pinned, current, latest_possible_ms)
}

pub fn release_freshness_snapshot_digest(
    snapshot: &ReleaseFreshnessSnapshot,
) -> Result<String, ReleaseFreshnessError> {
    validate_snapshot_shape(snapshot)?;
    digest_json(snapshot)
}

fn verify_material_state(
    snapshot: &ReleaseFreshnessSnapshot,
    current: &CurrentReleaseState,
    observed_at_ms: u64,
) -> Result<(), ReleaseFreshnessError> {
    if observed_at_ms >= snapshot.expires_at_ms {
        return Err(ReleaseFreshnessError::Expired);
    }
    if current.cancel_before_release {
        return Err(ReleaseFreshnessError::Cancelled);
    }
    if !current.execution_healthy {
        return Err(ReleaseFreshnessError::ExecutionUnhealthy);
    }
    if snapshot.tenant_namespace != current.tenant_namespace
        || snapshot.effect_intent_id != current.effect_intent_id
    {
        return Err(ReleaseFreshnessError::ScopeChanged);
    }
    if snapshot.decision_snapshot != current.decision_snapshot {
        return Err(ReleaseFreshnessError::DecisionSnapshotChanged);
    }
    if snapshot.principal_context != current.principal_context {
        return Err(ReleaseFreshnessError::StalePrincipal);
    }
    if snapshot.goal != current.goal {
        return Err(ReleaseFreshnessError::StaleGoal);
    }
    if snapshot.work != current.work {
        return Err(ReleaseFreshnessError::StaleWork);
    }
    if snapshot.state_revision != current.state_revision {
        return Err(ReleaseFreshnessError::StaleState);
    }
    if snapshot.policy != current.policy {
        return Err(ReleaseFreshnessError::StalePolicy);
    }
    if snapshot.authority_grant_ref != current.authority_grant_ref {
        return Err(ReleaseFreshnessError::StaleGrant);
    }
    if snapshot.revocation_epoch != current.revocation_epoch {
        return Err(ReleaseFreshnessError::StaleRevocationEpoch);
    }
    if snapshot.interrupt_watermark != current.interrupt_watermark {
        return Err(ReleaseFreshnessError::StaleInterruptWatermark);
    }
    if snapshot.payload_digest != current.payload_digest {
        return Err(ReleaseFreshnessError::PayloadChanged);
    }
    if snapshot.target_resources != current.target_resources
        || snapshot.target_accounts != current.target_accounts
        || snapshot.target_principals != current.target_principals
    {
        return Err(ReleaseFreshnessError::TargetsChanged);
    }
    if snapshot.capability != current.capability {
        return Err(ReleaseFreshnessError::CapabilityChanged);
    }
    if snapshot.environment != current.environment {
        return Err(ReleaseFreshnessError::EnvironmentChanged);
    }
    if snapshot.dispatch_owner != current.dispatch_owner
        || observed_at_ms >= snapshot.dispatch_lease_expires_at_ms
        || observed_at_ms >= current.dispatch_lease_expires_at_ms
        || current.dispatch_lease_expires_at_ms < snapshot.dispatch_lease_expires_at_ms
    {
        return Err(ReleaseFreshnessError::StaleDispatchClaim);
    }
    if snapshot.fence != current.fence {
        return Err(ReleaseFreshnessError::StaleFence);
    }
    Ok(())
}

fn build_proof(
    snapshot: &ReleaseFreshnessSnapshot,
    current: &CurrentReleaseState,
    verified_at_ms: u64,
) -> Result<ReleaseFreshnessProof, ReleaseFreshnessError> {
    let snapshot_digest = digest_json(snapshot)?;
    let current_state_digest = digest_json(current)?;
    Ok(ReleaseFreshnessProof {
        decision_snapshot: snapshot.decision_snapshot.clone(),
        dispatch_owner: snapshot.dispatch_owner.clone(),
        dispatch_lease_expires_at_ms: snapshot.dispatch_lease_expires_at_ms,
        fence: snapshot.fence,
        verified_at_ms,
        snapshot_digest,
        current_state_digest,
    })
}

fn validate_snapshot_shape(
    snapshot: &ReleaseFreshnessSnapshot,
) -> Result<(), ReleaseFreshnessError> {
    let required = [
        snapshot.tenant_namespace.as_str(),
        snapshot.effect_intent_id.as_str(),
        snapshot.decision_snapshot.ref_id.as_str(),
        snapshot.decision_snapshot.digest.as_str(),
        snapshot.principal_context.ref_id.as_str(),
        snapshot.principal_context.digest.as_str(),
        snapshot.goal.ref_id.as_str(),
        snapshot.work.ref_id.as_str(),
        snapshot.policy.ref_id.as_str(),
        snapshot.policy.version.as_str(),
        snapshot.authority_grant_ref.as_str(),
        snapshot.payload_digest.as_str(),
        snapshot.capability.ref_id.as_str(),
        snapshot.capability.version.as_str(),
        snapshot.environment.ref_id.as_str(),
        snapshot.environment.version.as_str(),
        snapshot.dispatch_owner.as_str(),
    ];
    if required.iter().any(|value| value.trim().is_empty())
        || snapshot.target_resources.is_empty()
            && snapshot.target_accounts.is_empty()
            && snapshot.target_principals.is_empty()
        || snapshot.dispatch_lease_expires_at_ms == 0
        || snapshot.fence == 0
        || snapshot.expires_at_ms == 0
    {
        return Err(ReleaseFreshnessError::InvalidSnapshot);
    }
    Ok(())
}

fn digest_json(value: &impl Serialize) -> Result<String, ReleaseFreshnessError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ReleaseFreshnessError::InvalidSnapshot)?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
