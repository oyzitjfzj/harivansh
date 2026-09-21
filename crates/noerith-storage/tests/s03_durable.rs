use noerith_storage::work::{
    AdapterClass, CallbackInput, CancelOutcome, CancelState, DurableWorkStore, EffectSpec,
    EffectState, HealthState, ObservationOutcome, ReconcileOutcome, RetryDecision, WorkError,
    WorkState,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static CASE_ID: AtomicU64 = AtomicU64::new(1);

fn case_path(name: &str) -> PathBuf {
    let id = CASE_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("noerith-s03-{name}-{}-{id}", std::process::id()));
    fs::create_dir_all(&root).expect("create case directory");
    root.join("work.db")
}

fn open(name: &str) -> (DurableWorkStore, PathBuf) {
    let path = case_path(name);
    let store =
        DurableWorkStore::open(&path, "synthetic-s03-key").expect("open protected work store");
    (store, path)
}

fn effect_spec(
    intent_id: &str,
    work_id: &str,
    payload_digest: &str,
    adapter_class: AdapterClass,
) -> EffectSpec {
    let requires_key = matches!(
        adapter_class,
        AdapterClass::E2DedupWrite
            | AdapterClass::E3ObservableWrite
            | AdapterClass::E4CompensatableWrite
            | AdapterClass::E5SharedAtomic
    );
    EffectSpec {
        tenant_namespace: "tenant-a".into(),
        intent_id: intent_id.into(),
        work_id: work_id.into(),
        operation_type: "external-write".into(),
        target_account: "account-a".into(),
        payload_digest: payload_digest.into(),
        adapter_class,
        idempotency_key: requires_key.then(|| format!("idem-{intent_id}")),
        idempotency_valid_until: requires_key.then_some(10_000),
        retry_budget: 3,
        expected_evidence_plan_ref: "evidence-plan-a".into(),
    }
}

fn create_authorized(
    store: &mut DurableWorkStore,
    work_id: &str,
    intent_id: &str,
    adapter: AdapterClass,
    now: u64,
) {
    store
        .create_work("tenant-a", work_id, "work-digest", now)
        .expect("create work");
    let spec = effect_spec(intent_id, work_id, "payload-a", adapter);
    store.create_effect(&spec, now).expect("create effect");
    store
        .prepare_effect("tenant-a", intent_id, now + 1)
        .expect("prepare");
    store
        .authorize_effect("tenant-a", intent_id, "snapshot-a", now + 2)
        .expect("authorize");
}

fn begin_dispatch(
    store: &mut DurableWorkStore,
    work_id: &str,
    intent_id: &str,
    adapter: AdapterClass,
    now: u64,
) -> noerith_storage::work::DispatchTicket {
    create_authorized(store, work_id, intent_id, adapter, now);
    let lease = store
        .acquire_dispatch_lease("tenant-a", "worker-a", now + 3, 100)
        .expect("lease");
    store
        .commit_ready("tenant-a", intent_id, &lease, now + 4)
        .expect("commit ready");
    store
        .claim_outbox("tenant-a", intent_id, &lease, now + 5)
        .expect("claim outbox");
    store
        .begin_dispatch("tenant-a", intent_id, &lease, now + 6)
        .expect("begin dispatch")
}

#[test]
fn s03_01_02_durable_work_queue_and_presend_claim_resume() {
    let (mut store, path) = open("queue-resume");
    store
        .create_work("tenant-a", "work-queue", "work-digest", 10)
        .expect("create work");
    let claim = store
        .claim_next_work("tenant-a", "worker-q", 11, 10)
        .expect("claim query")
        .expect("claim exists");
    assert_eq!(
        store.work_state("tenant-a", "work-queue").unwrap(),
        WorkState::Running
    );
    store.wait_work(&claim, 30, 12).expect("wait work");
    assert!(
        store
            .claim_next_work("tenant-a", "worker-q", 29, 10)
            .unwrap()
            .is_none()
    );
    let second = store
        .claim_next_work("tenant-a", "worker-q", 30, 5)
        .unwrap()
        .expect("second claim");
    drop(store);

    let mut reopened = DurableWorkStore::open(&path, "synthetic-s03-key").expect("reopen");
    assert_eq!(
        reopened
            .recover_expired_work_claims("tenant-a", 36)
            .unwrap(),
        1
    );
    let third = reopened
        .claim_next_work("tenant-a", "worker-r", 36, 10)
        .unwrap()
        .expect("recovered claim");
    assert!(third.fence > second.fence);

    create_authorized(
        &mut reopened,
        "work-presend",
        "intent-presend",
        AdapterClass::E2DedupWrite,
        100,
    );
    let lease = reopened
        .acquire_dispatch_lease("tenant-a", "dispatcher-a", 103, 50)
        .unwrap();
    reopened
        .commit_ready("tenant-a", "intent-presend", &lease, 104)
        .unwrap();
    reopened
        .claim_outbox("tenant-a", "intent-presend", &lease, 105)
        .unwrap();
    drop(reopened);

    let mut reopened = DurableWorkStore::open(&path, "synthetic-s03-key").expect("reopen 2");
    let same_lease = reopened
        .acquire_dispatch_lease("tenant-a", "dispatcher-a", 106, 50)
        .unwrap();
    assert_eq!(same_lease.fence, lease.fence);
    let ticket = reopened
        .begin_dispatch("tenant-a", "intent-presend", &same_lease, 107)
        .unwrap();
    assert_eq!(ticket.attempt, 1);
}

#[test]
fn s03_03_04_17_ambiguous_crash_is_durable_and_e1_never_blind_retries() {
    let (mut store, path) = open("opaque-crash");
    let _ticket = begin_dispatch(
        &mut store,
        "work-opaque",
        "intent-opaque",
        AdapterClass::E1OpaqueWrite,
        100,
    );
    drop(store);

    let mut recovered = DurableWorkStore::open(&path, "synthetic-s03-key").unwrap();
    assert_eq!(recovered.recover_inflight("tenant-a", 200).unwrap(), 1);
    assert_eq!(recovered.recover_inflight("tenant-a", 201).unwrap(), 0);
    assert_eq!(
        recovered
            .effect_view("tenant-a", "intent-opaque")
            .unwrap()
            .state,
        EffectState::AcceptanceUnknown
    );
    assert_eq!(
        recovered
            .retry_decision("tenant-a", "intent-opaque", 202)
            .unwrap(),
        RetryDecision::NoAutomaticRetry
    );
}

#[test]
fn s03_05_15_e2_retry_reuses_identity_and_is_bounded() {
    let (mut store, _) = open("dedup-retry");
    let ticket = begin_dispatch(
        &mut store,
        "work-dedup",
        "intent-dedup",
        AdapterClass::E2DedupWrite,
        100,
    );
    store
        .record_dispatch_ambiguous(&ticket, "network-timeout", 110)
        .unwrap();
    let decision = store
        .retry_decision("tenant-a", "intent-dedup", 111)
        .unwrap();
    let delay = match decision {
        RetryDecision::RetrySameIntent { after_ms } => after_ms,
        other => panic!("unexpected retry decision: {other:?}"),
    };
    assert!(delay <= 30_000);
    let before = store.effect_view("tenant-a", "intent-dedup").unwrap();
    let lease = store
        .acquire_dispatch_lease("tenant-a", "worker-a", 112, 100)
        .unwrap();
    store
        .prepare_same_intent_retry("tenant-a", "intent-dedup", &lease, "snapshot-fresh-b", 112)
        .unwrap();
    assert!(
        store
            .claim_outbox("tenant-a", "intent-dedup", &lease, 113)
            .is_err()
    );
    let retry_time = 112 + delay;
    assert!(matches!(
        store.claim_outbox("tenant-a", "intent-dedup", &lease, retry_time),
        Err(WorkError::StaleFence)
    ));
    let fresh_lease = store
        .acquire_dispatch_lease("tenant-a", "worker-a", retry_time, 100)
        .unwrap();
    assert!(fresh_lease.fence > lease.fence);
    store
        .claim_outbox("tenant-a", "intent-dedup", &fresh_lease, retry_time)
        .unwrap();
    let retry_ticket = store
        .begin_dispatch("tenant-a", "intent-dedup", &fresh_lease, retry_time + 1)
        .unwrap();
    assert_eq!(retry_ticket.attempt, 2);
    assert_eq!(retry_ticket.idempotency_key, before.idempotency_key);
    assert_eq!(retry_ticket.intent_id, ticket.intent_id);
}

#[test]
fn s03_06_e3_prefers_reconciliation_and_unresolved_stays_durable() {
    let (mut store, path) = open("observable-reconcile");
    let ticket = begin_dispatch(
        &mut store,
        "work-observable",
        "intent-observable",
        AdapterClass::E3ObservableWrite,
        100,
    );
    store
        .record_dispatch_ambiguous(&ticket, "lost-response", 110)
        .unwrap();
    assert_eq!(
        store
            .retry_decision("tenant-a", "intent-observable", 111)
            .unwrap(),
        RetryDecision::Reconcile
    );
    store
        .start_reconciliation("tenant-a", "intent-observable", 112)
        .unwrap();
    store
        .resolve_reconciliation(
            "tenant-a",
            "intent-observable",
            ReconcileOutcome::Unresolved {
                evidence_ref: "status-unavailable".into(),
            },
            113,
        )
        .unwrap();
    drop(store);
    let reopened = DurableWorkStore::open(&path, "synthetic-s03-key").unwrap();
    assert_eq!(
        reopened
            .effect_view("tenant-a", "intent-observable")
            .unwrap()
            .state,
        EffectState::Unresolved
    );
}

#[test]
fn s03_07_callbacks_are_deduplicated_and_conflicts_fail_closed() {
    let (mut store, _) = open("callbacks");
    let _ticket = begin_dispatch(
        &mut store,
        "work-callback",
        "intent-callback",
        AdapterClass::E3ObservableWrite,
        100,
    );
    let before = store.event_count("tenant-a", "intent-callback").unwrap();
    assert!(
        store
            .apply_callback(
                "tenant-a",
                "intent-callback",
                &CallbackInput {
                    callback_id: "callback-1".into(),
                    callback_digest: "callback-digest-a".into(),
                    accepted: true,
                    evidence_ref: "receipt-a".into(),
                },
                120,
            )
            .unwrap()
    );
    let once = store.event_count("tenant-a", "intent-callback").unwrap();
    assert_eq!(once, before + 1);
    assert!(
        !store
            .apply_callback(
                "tenant-a",
                "intent-callback",
                &CallbackInput {
                    callback_id: "callback-1".into(),
                    callback_digest: "callback-digest-a".into(),
                    accepted: true,
                    evidence_ref: "receipt-a".into(),
                },
                121,
            )
            .unwrap()
    );
    assert_eq!(
        store.event_count("tenant-a", "intent-callback").unwrap(),
        once
    );
    assert!(matches!(
        store.apply_callback(
            "tenant-a",
            "intent-callback",
            &CallbackInput {
                callback_id: "callback-1".into(),
                callback_digest: "callback-digest-b".into(),
                accepted: true,
                evidence_ref: "receipt-a".into(),
            },
            122,
        ),
        Err(WorkError::DuplicateIntentConflict)
    ));
}

#[test]
fn s03_08_stale_dispatcher_fence_cannot_cross_boundary() {
    let (mut store, _) = open("fence");
    create_authorized(
        &mut store,
        "work-fence",
        "intent-fence",
        AdapterClass::E2DedupWrite,
        10,
    );
    let old = store
        .acquire_dispatch_lease("tenant-a", "worker-old", 13, 5)
        .unwrap();
    store
        .commit_ready("tenant-a", "intent-fence", &old, 14)
        .unwrap();
    let new = store
        .acquire_dispatch_lease("tenant-a", "worker-new", 19, 20)
        .unwrap();
    assert!(new.fence > old.fence);
    assert!(matches!(
        store.claim_outbox("tenant-a", "intent-fence", &old, 19),
        Err(WorkError::StaleFence)
    ));
}

#[test]
fn s03_09_10_cancel_is_truthful_before_and_after_send_boundary() {
    let (mut store, _) = open("cancel");
    create_authorized(
        &mut store,
        "work-cancel-pre",
        "intent-cancel-pre",
        AdapterClass::E1OpaqueWrite,
        10,
    );
    assert_eq!(
        store
            .request_cancel("tenant-a", "intent-cancel-pre", 20)
            .unwrap(),
        CancelState::Confirmed
    );
    assert_eq!(
        store
            .effect_view("tenant-a", "intent-cancel-pre")
            .unwrap()
            .state,
        EffectState::CancelledPrecommit
    );

    let _ticket = begin_dispatch(
        &mut store,
        "work-cancel-post",
        "intent-cancel-post",
        AdapterClass::E3ObservableWrite,
        100,
    );
    assert_eq!(
        store
            .request_cancel("tenant-a", "intent-cancel-post", 110)
            .unwrap(),
        CancelState::Requested
    );
    assert_eq!(
        store
            .record_cancel_outcome(
                "tenant-a",
                "intent-cancel-post",
                CancelOutcome::Unknown,
                "provider-cancel-unknown",
                111,
            )
            .unwrap(),
        CancelState::Unknown
    );
}

#[test]
fn s03_11_12_acceptance_never_completes_work_without_observation() {
    let (mut store, _) = open("completion");
    let ticket = begin_dispatch(
        &mut store,
        "work-complete",
        "intent-complete",
        AdapterClass::E3ObservableWrite,
        100,
    );
    store
        .record_dispatch_accepted(&ticket, "receipt-accepted", 110)
        .unwrap();
    assert!(
        !store
            .try_complete_work("tenant-a", "work-complete", 111)
            .unwrap()
    );
    assert_ne!(
        store.work_state("tenant-a", "work-complete").unwrap(),
        WorkState::Completed
    );
    store
        .observe(
            "tenant-a",
            "intent-complete",
            ObservationOutcome::Succeeded {
                evidence_ref: "target-state-proof".into(),
            },
            112,
        )
        .unwrap();
    assert!(
        store
            .try_complete_work("tenant-a", "work-complete", 113)
            .unwrap()
    );
    assert_eq!(
        store.work_state("tenant-a", "work-complete").unwrap(),
        WorkState::Completed
    );
}

#[test]
fn s03_13_unhealthy_execution_blocks_dispatch_not_cancel_control() {
    let (mut store, _) = open("health");
    create_authorized(
        &mut store,
        "work-health",
        "intent-health",
        AdapterClass::E2DedupWrite,
        10,
    );
    let lease = store
        .acquire_dispatch_lease("tenant-a", "worker-a", 13, 100)
        .unwrap();
    store
        .set_health("tenant-a", HealthState::Quarantined, 14)
        .unwrap();
    assert!(matches!(
        store.commit_ready("tenant-a", "intent-health", &lease, 15),
        Err(WorkError::ExecutionUnhealthy)
    ));
    assert_eq!(
        store
            .request_cancel("tenant-a", "intent-health", 16)
            .unwrap(),
        CancelState::Confirmed
    );
}

#[test]
fn s03_14_compensation_is_a_new_linked_effect() {
    let (mut store, _) = open("compensation");
    let ticket = begin_dispatch(
        &mut store,
        "work-comp",
        "intent-original",
        AdapterClass::E4CompensatableWrite,
        100,
    );
    store
        .record_dispatch_accepted(&ticket, "receipt-original", 110)
        .unwrap();
    store
        .observe(
            "tenant-a",
            "intent-original",
            ObservationOutcome::Failed {
                evidence_ref: "partial-failure".into(),
            },
            111,
        )
        .unwrap();
    let compensation = effect_spec(
        "intent-compensation",
        "work-comp",
        "payload-compensation",
        AdapterClass::E3ObservableWrite,
    );
    store
        .create_compensation("tenant-a", "intent-original", &compensation, 112)
        .unwrap();
    let original = store.effect_view("tenant-a", "intent-original").unwrap();
    let compensating = store
        .effect_view("tenant-a", "intent-compensation")
        .unwrap();
    assert_eq!(original.state, EffectState::FailedAfterAccept);
    assert_eq!(
        compensating.parent_intent_id.as_deref(),
        Some("intent-original")
    );
    assert_eq!(compensating.state, EffectState::Proposed);
}

#[test]
fn s03_16_cancel_control_path_stays_fast_under_backlog() {
    let (mut store, _) = open("backlog");
    store
        .create_work("tenant-a", "work-backlog", "work-digest", 1)
        .unwrap();
    for index in 0..2_000_u32 {
        let intent = format!("intent-{index}");
        let spec = effect_spec(
            &intent,
            "work-backlog",
            "same-payload",
            AdapterClass::E1OpaqueWrite,
        );
        store.create_effect(&spec, 2 + u64::from(index)).unwrap();
    }
    let started = Instant::now();
    let result = store
        .request_cancel("tenant-a", "intent-1999", 10_000)
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(result, CancelState::Confirmed);
    assert!(
        elapsed <= Duration::from_millis(250),
        "cancel path took {elapsed:?} with 2000 queued effects"
    );
    println!("S03 cancel-control elapsed with 2000 effects: {elapsed:?}");
}

#[test]
fn s03_18_equal_payload_does_not_collapse_distinct_user_intents() {
    let (mut store, _) = open("distinct-intent");
    store
        .create_work("tenant-a", "work-distinct", "work-digest", 1)
        .unwrap();
    let first = effect_spec(
        "intent-first",
        "work-distinct",
        "equal-payload",
        AdapterClass::E2DedupWrite,
    );
    let second = effect_spec(
        "intent-second",
        "work-distinct",
        "equal-payload",
        AdapterClass::E2DedupWrite,
    );
    store.create_effect(&first, 2).unwrap();
    store.create_effect(&second, 3).unwrap();
    assert_ne!(first.intent_id, second.intent_id);
    assert_ne!(first.idempotency_key, second.idempotency_key);
    assert_eq!(
        store.effect_view("tenant-a", "intent-first").unwrap().state,
        EffectState::Proposed
    );
    assert_eq!(
        store
            .effect_view("tenant-a", "intent-second")
            .unwrap()
            .state,
        EffectState::Proposed
    );
}
