use noerith_broker::{
    CurrentReleaseState, OpaqueVersionRef, ReleaseFreshnessError, ReleaseFreshnessSnapshot,
    ReleaseTimeObservation, verify_bound_release_freshness, verify_release_freshness,
};
use noerith_effects::{DigestRef, MonotonicDeadline, SynchronizationState, VersionedRef};
use std::collections::BTreeSet;

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn snapshot() -> ReleaseFreshnessSnapshot {
    ReleaseFreshnessSnapshot {
        tenant_namespace: "tenant-a".into(),
        effect_intent_id: "intent-a".into(),
        decision_snapshot: DigestRef {
            ref_id: "snapshot-a".into(),
            digest: "snapshot-digest-a".into(),
        },
        principal_context: DigestRef {
            ref_id: "principal-context-a".into(),
            digest: "principal-digest-a".into(),
        },
        goal: VersionedRef {
            ref_id: "goal-a".into(),
            version: 7,
        },
        work: VersionedRef {
            ref_id: "work-a".into(),
            version: 11,
        },
        state_revision: 19,
        policy: OpaqueVersionRef {
            ref_id: "policy-bundle-a".into(),
            version: "2026.09.09+r3".into(),
        },
        authority_grant_ref: "grant-a".into(),
        revocation_epoch: 5,
        interrupt_watermark: 13,
        payload_digest: "payload-digest-a".into(),
        target_resources: set(&["resource-a"]),
        target_accounts: set(&["account-a"]),
        target_principals: set(&["target-a"]),
        capability: OpaqueVersionRef {
            ref_id: "capability-a".into(),
            version: "2.4.1".into(),
        },
        environment: OpaqueVersionRef {
            ref_id: "environment-a".into(),
            version: "linux-sandbox-2026.09".into(),
        },
        dispatch_owner: "worker-a".into(),
        dispatch_lease_expires_at_ms: 18_000,
        fence: 23,
        expires_at_ms: 20_000,
    }
}

fn current() -> CurrentReleaseState {
    let snapshot = snapshot();
    CurrentReleaseState {
        tenant_namespace: snapshot.tenant_namespace,
        effect_intent_id: snapshot.effect_intent_id,
        decision_snapshot: snapshot.decision_snapshot,
        principal_context: snapshot.principal_context,
        goal: snapshot.goal,
        work: snapshot.work,
        state_revision: snapshot.state_revision,
        policy: snapshot.policy,
        authority_grant_ref: snapshot.authority_grant_ref,
        revocation_epoch: snapshot.revocation_epoch,
        interrupt_watermark: snapshot.interrupt_watermark,
        payload_digest: snapshot.payload_digest,
        target_resources: snapshot.target_resources,
        target_accounts: snapshot.target_accounts,
        target_principals: snapshot.target_principals,
        capability: snapshot.capability,
        environment: snapshot.environment,
        dispatch_owner: snapshot.dispatch_owner,
        dispatch_lease_expires_at_ms: snapshot.dispatch_lease_expires_at_ms,
        fence: snapshot.fence,
        cancel_before_release: false,
        execution_healthy: true,
    }
}

fn final_time(center_ms: u64) -> ReleaseTimeObservation {
    ReleaseTimeObservation {
        unix_time_ms: center_ms,
        uncertainty_before_ms: 0,
        uncertainty_after_ms: 0,
        clock_source: "qualified-wall-clock-a".into(),
        synchronization_state: SynchronizationState::Synced,
        monotonic_clock_ref: "runtime-monotonic-a".into(),
        monotonic_tick: 100,
    }
}

fn monotonic_deadline() -> MonotonicDeadline {
    MonotonicDeadline {
        clock_ref: "runtime-monotonic-a".into(),
        deadline_tick: 200,
    }
}

#[test]
fn final_release_freshness_accepts_only_exact_current_snapshot() {
    let snapshot = snapshot();
    let proof = verify_release_freshness(&snapshot, &current(), 10_000).expect("fresh proof");
    assert_eq!(proof.decision_snapshot(), &snapshot.decision_snapshot);
    assert_eq!(proof.dispatch_owner(), snapshot.dispatch_owner);
    assert_eq!(
        proof.dispatch_lease_expires_at_ms(),
        snapshot.dispatch_lease_expires_at_ms
    );
    assert_eq!(proof.fence(), snapshot.fence);
    assert_eq!(proof.verified_at_ms(), 10_000);
    assert!(!proof.snapshot_digest().is_empty());
    assert!(!proof.current_state_digest().is_empty());
}

#[test]
fn final_release_freshness_blocks_cancel_unhealthy_expired_and_wrong_scope() {
    let snapshot = snapshot();

    let mut cancelled = current();
    cancelled.cancel_before_release = true;
    assert_eq!(
        verify_release_freshness(&snapshot, &cancelled, 10_000),
        Err(ReleaseFreshnessError::Cancelled)
    );

    let mut unhealthy = current();
    unhealthy.execution_healthy = false;
    assert_eq!(
        verify_release_freshness(&snapshot, &unhealthy, 10_000),
        Err(ReleaseFreshnessError::ExecutionUnhealthy)
    );

    let mut wrong_tenant = current();
    wrong_tenant.tenant_namespace = "tenant-b".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &wrong_tenant, 10_000),
        Err(ReleaseFreshnessError::ScopeChanged)
    );

    let mut wrong_effect = current();
    wrong_effect.effect_intent_id = "intent-b".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &wrong_effect, 10_000),
        Err(ReleaseFreshnessError::ScopeChanged)
    );

    assert_eq!(
        verify_release_freshness(&snapshot, &current(), snapshot.expires_at_ms),
        Err(ReleaseFreshnessError::Expired)
    );
}

#[test]
fn final_release_freshness_blocks_every_protected_staleness_axis() {
    let snapshot = snapshot();

    let mut value = current();
    value.decision_snapshot.digest = "changed".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::DecisionSnapshotChanged)
    );

    let mut value = current();
    value.principal_context.digest = "changed".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StalePrincipal)
    );

    let mut value = current();
    value.goal.version += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleGoal)
    );

    let mut value = current();
    value.work.version += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleWork)
    );

    let mut value = current();
    value.state_revision += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleState)
    );

    let mut value = current();
    value.policy.version = "2026.09.09+r4".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StalePolicy)
    );

    let mut value = current();
    value.authority_grant_ref = "grant-b".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleGrant)
    );

    let mut value = current();
    value.revocation_epoch += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleRevocationEpoch)
    );

    let mut value = current();
    value.interrupt_watermark += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleInterruptWatermark)
    );

    let mut value = current();
    value.payload_digest = "payload-digest-b".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::PayloadChanged)
    );

    let mut value = current();
    value.target_accounts = set(&["other-account"]);
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::TargetsChanged)
    );

    let mut value = current();
    value.capability.version = "2.4.2".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::CapabilityChanged)
    );

    let mut value = current();
    value.environment.version = "linux-sandbox-2026.10".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::EnvironmentChanged)
    );

    let mut value = current();
    value.dispatch_owner = "worker-b".into();
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleDispatchClaim)
    );

    let mut value = current();
    value.dispatch_lease_expires_at_ms = snapshot.dispatch_lease_expires_at_ms - 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleDispatchClaim)
    );

    let mut value = current();
    value.fence += 1;
    assert_eq!(
        verify_release_freshness(&snapshot, &value, 10_000),
        Err(ReleaseFreshnessError::StaleFence)
    );
}

#[test]
fn final_release_freshness_uses_final_observation_time_for_claim_expiry() {
    let snapshot = snapshot();
    assert_eq!(
        verify_release_freshness(&snapshot, &current(), snapshot.dispatch_lease_expires_at_ms),
        Err(ReleaseFreshnessError::StaleDispatchClaim)
    );

    let mut extended = current();
    extended.dispatch_lease_expires_at_ms = snapshot.dispatch_lease_expires_at_ms + 5_000;
    assert!(verify_release_freshness(&snapshot, &extended, 10_000).is_ok());
}

#[test]
fn final_release_freshness_keeps_opaque_versions_exact() {
    let snapshot = snapshot();
    let mut same = current();
    same.capability.version = "2.4.1".into();
    same.environment.version = "linux-sandbox-2026.09".into();
    assert!(verify_release_freshness(&snapshot, &same, 10_000).is_ok());
}

#[test]
fn bound_freshness_rejects_self_consistent_caller_projection_not_in_pinned_snapshot() {
    let pinned = snapshot();
    let mut caller = pinned.clone();
    caller.policy.version = "caller-substituted-current-policy".into();

    assert_eq!(
        verify_bound_release_freshness(
            &caller,
            &pinned,
            &current(),
            &final_time(10_000),
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::SnapshotProjectionMismatch)
    );
}

#[test]
fn bound_freshness_uses_uncertainty_upper_bound_at_expiry() {
    let pinned = snapshot();
    let mut observation = final_time(pinned.dispatch_lease_expires_at_ms - 1);
    observation.uncertainty_after_ms = 1;
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &observation,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::StaleDispatchClaim)
    );

    let mut observation = final_time(pinned.expires_at_ms - 1);
    observation.uncertainty_after_ms = 1;
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &observation,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::Expired)
    );
}

#[test]
fn bound_freshness_fails_closed_on_unqualified_or_incomparable_time() {
    let pinned = snapshot();

    let mut degraded = final_time(10_000);
    degraded.synchronization_state = SynchronizationState::Degraded;
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &degraded,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::ClockUnqualified)
    );

    let mut wrong_clock = final_time(10_000);
    wrong_clock.monotonic_clock_ref = "other-runtime-clock".into();
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &wrong_clock,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::MonotonicClockMismatch)
    );

    let mut elapsed = final_time(10_000);
    elapsed.monotonic_tick = monotonic_deadline().deadline_tick;
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &elapsed,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::MonotonicDeadlineExpired)
    );

    let mut overflow = final_time(u64::MAX);
    overflow.uncertainty_after_ms = 1;
    assert_eq!(
        verify_bound_release_freshness(
            &pinned,
            &pinned,
            &current(),
            &overflow,
            &monotonic_deadline(),
        ),
        Err(ReleaseFreshnessError::ClockUncertaintyOverflow)
    );
}

#[test]
fn bound_freshness_accepts_exact_pinned_current_and_comparable_time() {
    let pinned = snapshot();
    let proof = verify_bound_release_freshness(
        &pinned,
        &pinned,
        &current(),
        &final_time(10_000),
        &monotonic_deadline(),
    )
    .expect("source-bound final freshness proof");
    assert_eq!(proof.decision_snapshot(), &pinned.decision_snapshot);
    assert_eq!(proof.verified_at_ms(), 10_000);
}
