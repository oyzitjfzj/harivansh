use crate::{
    BrokerError, ControlledAdapter, CredentialHandle, CredentialSource, CurrentReleaseState,
    PostReturnTimeSource, ReleaseFreshnessAuthority, ReleaseFreshnessGuard, ReleaseFreshnessProof,
    ReleaseFreshnessSnapshot, ReleaseRequest, ReleaseTimeObservation,
    verify_bound_release_freshness,
};
use noerith_effects::{LifecycleState, MonotonicDeadline};
use noerith_storage::KeyProvider;
use std::path::Path;

/// Source-bound public facade over the S03 controlled-release runtime.
///
/// It refuses a freshness authority that cannot independently provide both the
/// immutable pinned Decision Snapshot projection and typed final-gate time
/// evidence. The authority guard remains held through the last equality checks
/// and durable one-shot release consumption. Provider-return time is supplied
/// through a separate post-return source and can never be substituted by the
/// pre-send authorization observation.
pub struct SourceBoundReleaseBroker {
    inner: crate::runtime::ControlledReleaseBroker,
}

impl SourceBoundReleaseBroker {
    pub fn open(path: impl AsRef<Path>, provider: &impl KeyProvider) -> Result<Self, BrokerError> {
        Ok(Self {
            inner: crate::runtime::ControlledReleaseBroker::open(path, provider)?,
        })
    }

    pub fn register_handle(
        &mut self,
        handle: &CredentialHandle,
        now_ms: u64,
    ) -> Result<bool, BrokerError> {
        self.inner.register_handle(handle, now_ms)
    }

    pub fn advance_revocation_epoch(
        &mut self,
        tenant_namespace: &str,
        authority_grant_ref: &str,
        new_epoch: u64,
        now_ms: u64,
    ) -> Result<(), BrokerError> {
        self.inner.advance_revocation_epoch(
            tenant_namespace,
            authority_grant_ref,
            new_epoch,
            now_ms,
        )
    }

    pub fn dispatch(
        &mut self,
        request: &ReleaseRequest,
        expected_snapshot: &ReleaseFreshnessSnapshot,
        freshness_authority: &mut impl ReleaseFreshnessAuthority,
        credential_source: &mut impl CredentialSource,
        adapter: &mut impl ControlledAdapter,
        post_return_time_source: &mut impl PostReturnTimeSource,
    ) -> Result<LifecycleState, BrokerError> {
        let mut authority = SourceBoundAuthority {
            inner: freshness_authority,
            monotonic_deadline: &request.monotonic_deadline,
        };
        self.inner.dispatch(
            request,
            expected_snapshot,
            &mut authority,
            credential_source,
            adapter,
            post_return_time_source,
        )
    }

    /// Recovery never authorizes another provider send. The typed observation is
    /// used only as a trustworthy processing-time bound when a previously
    /// captured result lacked qualified physical time or when uncaptured
    /// ambiguity must be materialized locally.
    pub fn recover_release(
        &mut self,
        tenant_namespace: &str,
        release_id: &str,
        recovery_observation: &ReleaseTimeObservation,
    ) -> Result<LifecycleState, BrokerError> {
        let recovery_time_ms = recovery_observation.latest_possible_ms()?;
        self.inner
            .recover_release(tenant_namespace, release_id, recovery_time_ms)
    }

    pub fn release_state(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<&'static str, BrokerError> {
        self.inner.release_state(tenant_namespace, release_id)
    }

    pub fn release_freshness_proof(
        &self,
        tenant_namespace: &str,
        release_id: &str,
    ) -> Result<Option<ReleaseFreshnessProof>, BrokerError> {
        self.inner
            .release_freshness_proof(tenant_namespace, release_id)
    }
}

struct SourceBoundAuthority<'a, A> {
    inner: &'a mut A,
    monotonic_deadline: &'a MonotonicDeadline,
}

struct SourceBoundGuard<G> {
    inner: G,
    verified_at_ms: u64,
}

impl<G: ReleaseFreshnessGuard> ReleaseFreshnessGuard for SourceBoundGuard<G> {
    fn current_state(&self) -> &CurrentReleaseState {
        self.inner.current_state()
    }

    fn observed_at_ms(&self) -> u64 {
        self.verified_at_ms
    }

    fn pinned_snapshot(&self) -> Option<&ReleaseFreshnessSnapshot> {
        self.inner.pinned_snapshot()
    }

    fn time_observation(&self) -> Option<&ReleaseTimeObservation> {
        self.inner.time_observation()
    }
}

impl<A: ReleaseFreshnessAuthority> ReleaseFreshnessAuthority for SourceBoundAuthority<'_, A> {
    type Guard<'a>
        = SourceBoundGuard<A::Guard<'a>>
    where
        Self: 'a;

    fn acquire<'a>(
        &'a mut self,
        expected: &ReleaseFreshnessSnapshot,
    ) -> Result<Self::Guard<'a>, BrokerError> {
        let guard = self.inner.acquire(expected)?;
        let pinned = guard
            .pinned_snapshot()
            .ok_or(BrokerError::FreshnessAuthorityUnavailable)?;
        let observed = guard
            .time_observation()
            .ok_or(BrokerError::FreshnessAuthorityUnavailable)?;
        let proof = verify_bound_release_freshness(
            expected,
            pinned,
            guard.current_state(),
            observed,
            self.monotonic_deadline,
        )?;
        Ok(SourceBoundGuard {
            inner: guard,
            verified_at_ms: proof.verified_at_ms(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpaqueVersionRef, ReleaseFreshnessError};
    use noerith_effects::{DigestRef, SynchronizationState, VersionedRef};
    use std::collections::BTreeSet;

    fn set(value: &str) -> BTreeSet<String> {
        [value.to_owned()].into_iter().collect()
    }

    fn snapshot() -> ReleaseFreshnessSnapshot {
        ReleaseFreshnessSnapshot {
            tenant_namespace: "tenant-a".into(),
            effect_intent_id: "effect-a".into(),
            decision_snapshot: DigestRef {
                ref_id: "decision-a".into(),
                digest: "decision-digest-a".into(),
            },
            principal_context: DigestRef {
                ref_id: "principal-a".into(),
                digest: "principal-digest-a".into(),
            },
            goal: VersionedRef {
                ref_id: "goal-a".into(),
                version: 3,
            },
            work: VersionedRef {
                ref_id: "work-a".into(),
                version: 5,
            },
            state_revision: 7,
            policy: OpaqueVersionRef {
                ref_id: "policy-a".into(),
                version: "p7".into(),
            },
            authority_grant_ref: "grant-a".into(),
            revocation_epoch: 2,
            interrupt_watermark: 9,
            payload_digest: "payload-a".into(),
            target_resources: set("resource-a"),
            target_accounts: set("account-a"),
            target_principals: set("target-a"),
            capability: OpaqueVersionRef {
                ref_id: "capability-a".into(),
                version: "cap-v".into(),
            },
            environment: OpaqueVersionRef {
                ref_id: "environment-a".into(),
                version: "env-v".into(),
            },
            dispatch_owner: "worker-a".into(),
            dispatch_lease_expires_at_ms: 20_000,
            fence: 11,
            expires_at_ms: 21_000,
        }
    }

    fn current(pinned: &ReleaseFreshnessSnapshot) -> CurrentReleaseState {
        CurrentReleaseState {
            tenant_namespace: pinned.tenant_namespace.clone(),
            effect_intent_id: pinned.effect_intent_id.clone(),
            decision_snapshot: pinned.decision_snapshot.clone(),
            principal_context: pinned.principal_context.clone(),
            goal: pinned.goal.clone(),
            work: pinned.work.clone(),
            state_revision: pinned.state_revision,
            policy: pinned.policy.clone(),
            authority_grant_ref: pinned.authority_grant_ref.clone(),
            revocation_epoch: pinned.revocation_epoch,
            interrupt_watermark: pinned.interrupt_watermark,
            payload_digest: pinned.payload_digest.clone(),
            target_resources: pinned.target_resources.clone(),
            target_accounts: pinned.target_accounts.clone(),
            target_principals: pinned.target_principals.clone(),
            capability: pinned.capability.clone(),
            environment: pinned.environment.clone(),
            dispatch_owner: pinned.dispatch_owner.clone(),
            dispatch_lease_expires_at_ms: pinned.dispatch_lease_expires_at_ms,
            fence: pinned.fence,
            cancel_before_release: false,
            execution_healthy: true,
        }
    }

    struct Guard<'a> {
        pinned: &'a ReleaseFreshnessSnapshot,
        current: &'a CurrentReleaseState,
        time: &'a ReleaseTimeObservation,
    }

    impl ReleaseFreshnessGuard for Guard<'_> {
        fn current_state(&self) -> &CurrentReleaseState {
            self.current
        }

        fn observed_at_ms(&self) -> u64 {
            self.time.unix_time_ms
        }

        fn pinned_snapshot(&self) -> Option<&ReleaseFreshnessSnapshot> {
            Some(self.pinned)
        }

        fn time_observation(&self) -> Option<&ReleaseTimeObservation> {
            Some(self.time)
        }
    }

    struct Authority {
        pinned: ReleaseFreshnessSnapshot,
        current: CurrentReleaseState,
        time: ReleaseTimeObservation,
    }

    impl ReleaseFreshnessAuthority for Authority {
        type Guard<'a>
            = Guard<'a>
        where
            Self: 'a;

        fn acquire<'a>(
            &'a mut self,
            _expected: &ReleaseFreshnessSnapshot,
        ) -> Result<Self::Guard<'a>, BrokerError> {
            Ok(Guard {
                pinned: &self.pinned,
                current: &self.current,
                time: &self.time,
            })
        }
    }

    struct LegacyGuard<'a>(&'a CurrentReleaseState);

    impl ReleaseFreshnessGuard for LegacyGuard<'_> {
        fn current_state(&self) -> &CurrentReleaseState {
            self.0
        }

        fn observed_at_ms(&self) -> u64 {
            10_000
        }
    }

    struct LegacyAuthority(CurrentReleaseState);

    impl ReleaseFreshnessAuthority for LegacyAuthority {
        type Guard<'a>
            = LegacyGuard<'a>
        where
            Self: 'a;

        fn acquire<'a>(
            &'a mut self,
            _expected: &ReleaseFreshnessSnapshot,
        ) -> Result<Self::Guard<'a>, BrokerError> {
            Ok(LegacyGuard(&self.0))
        }
    }

    fn authority() -> Authority {
        let pinned = snapshot();
        let current = current(&pinned);
        Authority {
            pinned,
            current,
            time: ReleaseTimeObservation {
                unix_time_ms: 10_000,
                uncertainty_before_ms: 2,
                uncertainty_after_ms: 2,
                clock_source: "qualified-clock-a".into(),
                synchronization_state: SynchronizationState::Synced,
                monotonic_clock_ref: "mono-a".into(),
                monotonic_tick: 100,
            },
        }
    }

    fn deadline() -> MonotonicDeadline {
        MonotonicDeadline {
            clock_ref: "mono-a".into(),
            deadline_tick: 200,
        }
    }

    #[test]
    fn source_bound_adapter_requires_exact_immutable_projection() {
        let expected = snapshot();
        let mut authority = authority();
        authority.pinned.policy.version = "pinned-old".into();
        let deadline = deadline();
        let mut adapter = SourceBoundAuthority {
            inner: &mut authority,
            monotonic_deadline: &deadline,
        };
        let result = adapter.acquire(&expected);
        assert!(matches!(
            result,
            Err(BrokerError::Freshness(
                ReleaseFreshnessError::SnapshotProjectionMismatch
            ))
        ));
    }

    #[test]
    fn source_bound_adapter_keeps_guard_and_uses_conservative_time() {
        let expected = snapshot();
        let mut authority = authority();
        let deadline = deadline();
        let mut adapter = SourceBoundAuthority {
            inner: &mut authority,
            monotonic_deadline: &deadline,
        };
        let guard = adapter.acquire(&expected).expect("source-bound guard");
        assert_eq!(guard.observed_at_ms(), 10_002);
        assert_eq!(guard.current_state().fence, expected.fence);
        assert_eq!(
            guard
                .pinned_snapshot()
                .expect("pinned projection")
                .decision_snapshot,
            expected.decision_snapshot
        );
    }

    #[test]
    fn source_bound_adapter_rejects_legacy_authority_without_pinned_or_typed_time() {
        let expected = snapshot();
        let mut authority = LegacyAuthority(current(&expected));
        let deadline = deadline();
        let mut adapter = SourceBoundAuthority {
            inner: &mut authority,
            monotonic_deadline: &deadline,
        };
        assert!(matches!(
            adapter.acquire(&expected),
            Err(BrokerError::FreshnessAuthorityUnavailable)
        ));
    }
}
