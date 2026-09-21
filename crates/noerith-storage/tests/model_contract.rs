use noerith_storage::model::{
    AllowedUseState, CopyPurgeState, DeleteJobState, InfluenceRole, PhysicalState, SourceIdentity,
};

#[test]
fn q03_model_contract_has_stable_lifecycle_names() {
    assert_eq!(AllowedUseState::Active.as_db(), "ACTIVE");
    assert_eq!(AllowedUseState::Quarantined.as_db(), "QUARANTINED");
    assert_eq!(AllowedUseState::Disputed.as_db(), "DISPUTED");
    assert_eq!(AllowedUseState::Superseded.as_db(), "SUPERSEDED");
    assert_eq!(AllowedUseState::Expired.as_db(), "EXPIRED");
    assert_eq!(AllowedUseState::Blocked.as_db(), "BLOCKED");
    assert_eq!(PhysicalState::Present.as_db(), "PRESENT");
    assert_eq!(PhysicalState::PurgePending.as_db(), "PURGE_PENDING");
    assert_eq!(CopyPurgeState::Unknown.as_db(), "UNKNOWN");
    assert_eq!(DeleteJobState::Complete.as_db(), "COMPLETE");
    assert_eq!(InfluenceRole::Correction.as_db(), "CORRECTION");
}

#[test]
fn q03_source_identity_round_trip_cannot_drop_tenant_or_version() {
    let source = SourceIdentity {
        tenant_namespace: "tenant-a".to_owned(),
        source_id: "source-shared".to_owned(),
        version: 9,
    };
    let encoded = serde_json::to_string(&source).expect("serialize");
    let decoded: SourceIdentity = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded, source);
}
