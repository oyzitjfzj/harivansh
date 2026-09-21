use crate::{
    engine::{Result, StorageError},
    model::SourceIdentity,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;

const FRONTIER_SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontierUseState {
    Active,
    Blocked,
}

impl FrontierUseState {
    fn as_db(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Blocked => "BLOCKED",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "ACTIVE" => Ok(Self::Active),
            "BLOCKED" => Ok(Self::Blocked),
            _ => Err(StorageError::IntegrityMismatch),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceFrontier {
    pub source: SourceIdentity,
    pub lifecycle_epoch: u64,
    pub use_state: FrontierUseState,
    pub authority_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingPublication {
    pub tenant_namespace: String,
    pub source_id: String,
    pub expected_previous_version: Option<u64>,
    pub target_version: u64,
    pub lifecycle_epoch: u64,
    pub authority_epoch: u64,
}

pub(crate) struct FrontierStore {
    connection: Connection,
}

impl FrontierStore {
    pub(crate) fn open(path: &Path, passphrase: &str) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", passphrase)?;
        let cipher_version: String =
            connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        if cipher_version.trim().is_empty() {
            return Err(StorageError::CipherInactive);
        }
        connection.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000_i64)?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StorageError::Sqlite(rusqlite::Error::InvalidQuery));
        }
        initialize_schema(&mut connection)?;
        Ok(Self { connection })
    }

    pub(crate) fn namespace_epoch(&self, tenant_namespace: &str) -> Result<u64> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT lifecycle_epoch FROM namespace_frontiers WHERE tenant_namespace=?1",
                [tenant_namespace],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) as u64)
    }

    pub(crate) fn authority_epoch(&self, tenant_namespace: &str) -> Result<u64> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT authority_epoch FROM namespace_frontiers WHERE tenant_namespace=?1",
                [tenant_namespace],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) as u64)
    }

    pub(crate) fn set_authority_epoch(
        &mut self,
        tenant_namespace: &str,
        authority_epoch: u64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_namespace_tx(&tx, tenant_namespace)?;
        let current: i64 = tx.query_row(
            "SELECT authority_epoch FROM namespace_frontiers WHERE tenant_namespace=?1",
            [tenant_namespace],
            |row| row.get(0),
        )?;
        if authority_epoch < current as u64 {
            return Err(StorageError::StaleLifecycle);
        }
        tx.execute(
            "UPDATE namespace_frontiers SET authority_epoch=?2 WHERE tenant_namespace=?1",
            params![tenant_namespace, authority_epoch as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn begin_publication(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        expected_previous_version: Option<u64>,
        target_version: u64,
        lifecycle_epoch: u64,
        authority_epoch: u64,
    ) -> Result<()> {
        if target_version == 0 {
            return Err(StorageError::StaleLifecycle);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_namespace_tx(&tx, tenant_namespace)?;
        let namespace_row: (i64, i64) = tx.query_row(
            "SELECT lifecycle_epoch,authority_epoch FROM namespace_frontiers WHERE tenant_namespace=?1",
            [tenant_namespace],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if lifecycle_epoch <= namespace_row.0 as u64 || authority_epoch < namespace_row.1 as u64 {
            return Err(StorageError::StaleLifecycle);
        }

        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT current_version,use_state FROM source_frontiers WHERE tenant_namespace=?1 AND source_id=?2",
                params![tenant_namespace, source_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match (expected_previous_version, existing) {
            (None, None) if target_version == 1 => {}
            (Some(expected), Some((current, state)))
                if current as u64 == expected
                    && state == FrontierUseState::Active.as_db()
                    && target_version == expected + 1 => {}
            _ => return Err(StorageError::StaleLifecycle),
        }

        let pending_exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM pending_publications WHERE tenant_namespace=?1 AND source_id=?2",
                params![tenant_namespace, source_id],
                |row| row.get(0),
            )
            .optional()?;
        if pending_exists.is_some() {
            return Err(StorageError::StaleLifecycle);
        }
        tx.execute(
            "INSERT INTO pending_publications(tenant_namespace,source_id,expected_previous_version,target_version,lifecycle_epoch,authority_epoch) \
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                tenant_namespace,
                source_id,
                expected_previous_version.map(|value| value as i64),
                target_version as i64,
                lifecycle_epoch as i64,
                authority_epoch as i64
            ],
        )?;
        tx.execute(
            "UPDATE namespace_frontiers SET lifecycle_epoch=?2 WHERE tenant_namespace=?1",
            params![tenant_namespace, lifecycle_epoch as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn commit_publication(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        target_version: u64,
        lifecycle_epoch: u64,
        authority_epoch: u64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<(i64, i64, i64)> = tx
            .query_row(
                "SELECT target_version,lifecycle_epoch,authority_epoch FROM pending_publications \
                 WHERE tenant_namespace=?1 AND source_id=?2",
                params![tenant_namespace, source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if pending
            != Some((
                target_version as i64,
                lifecycle_epoch as i64,
                authority_epoch as i64,
            ))
        {
            return Err(StorageError::StaleLifecycle);
        }
        tx.execute(
            "INSERT INTO source_frontiers(tenant_namespace,source_id,current_version,lifecycle_epoch,use_state,authority_epoch) \
             VALUES(?1,?2,?3,?4,'ACTIVE',?5) \
             ON CONFLICT(tenant_namespace,source_id) DO UPDATE SET \
                current_version=excluded.current_version,lifecycle_epoch=excluded.lifecycle_epoch,use_state='ACTIVE',authority_epoch=excluded.authority_epoch",
            params![
                tenant_namespace,
                source_id,
                target_version as i64,
                lifecycle_epoch as i64,
                authority_epoch as i64
            ],
        )?;
        tx.execute(
            "DELETE FROM pending_publications WHERE tenant_namespace=?1 AND source_id=?2",
            params![tenant_namespace, source_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn abort_publication(
        &mut self,
        tenant_namespace: &str,
        source_id: &str,
        target_version: u64,
    ) -> Result<()> {
        self.connection.execute(
            "DELETE FROM pending_publications WHERE tenant_namespace=?1 AND source_id=?2 AND target_version=?3",
            params![tenant_namespace, source_id, target_version as i64],
        )?;
        Ok(())
    }

    pub(crate) fn require_active(
        &self,
        source: &SourceIdentity,
        lifecycle_epoch: u64,
        source_authority_epoch: u64,
    ) -> Result<()> {
        let namespace_authority = self.authority_epoch(&source.tenant_namespace)?;
        let row: Option<(i64, i64, String, i64)> = self
            .connection
            .query_row(
                "SELECT current_version,lifecycle_epoch,use_state,authority_epoch FROM source_frontiers \
                 WHERE tenant_namespace=?1 AND source_id=?2",
                params![source.tenant_namespace, source.source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((version, epoch, state, authority_epoch)) = row else {
            return Err(StorageError::StaleLifecycle);
        };
        if FrontierUseState::parse(&state)? != FrontierUseState::Active
            || version as u64 != source.version
            || epoch as u64 != lifecycle_epoch
            || authority_epoch as u64 != source_authority_epoch
            || source_authority_epoch < namespace_authority
        {
            return Err(StorageError::StaleLifecycle);
        }
        Ok(())
    }

    pub(crate) fn require_current_identity(&self, source: &SourceIdentity) -> Result<()> {
        let row: Option<(i64, String)> = self
            .connection
            .query_row(
                "SELECT current_version,use_state FROM source_frontiers WHERE tenant_namespace=?1 AND source_id=?2",
                params![source.tenant_namespace, source.source_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((version, state))
                if version as u64 == source.version
                    && FrontierUseState::parse(&state)? == FrontierUseState::Active =>
            {
                Ok(())
            }
            _ => Err(StorageError::StaleLifecycle),
        }
    }

    pub(crate) fn block_sources(
        &mut self,
        tenant_namespace: &str,
        sources: &[SourceIdentity],
        lifecycle_epoch: u64,
    ) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_namespace_tx(&tx, tenant_namespace)?;
        let current_epoch: i64 = tx.query_row(
            "SELECT lifecycle_epoch FROM namespace_frontiers WHERE tenant_namespace=?1",
            [tenant_namespace],
            |row| row.get(0),
        )?;
        if lifecycle_epoch <= current_epoch as u64 {
            return Err(StorageError::StaleLifecycle);
        }
        for source in sources {
            let existing: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT current_version,authority_epoch FROM source_frontiers \
                     WHERE tenant_namespace=?1 AND source_id=?2",
                    params![tenant_namespace, source.source_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((version, authority_epoch)) = existing else {
                return Err(StorageError::StaleLifecycle);
            };
            if version as u64 != source.version {
                return Err(StorageError::StaleLifecycle);
            }
            tx.execute(
                "UPDATE source_frontiers SET lifecycle_epoch=?3,use_state='BLOCKED',authority_epoch=?4 \
                 WHERE tenant_namespace=?1 AND source_id=?2",
                params![
                    tenant_namespace,
                    source.source_id,
                    lifecycle_epoch as i64,
                    authority_epoch
                ],
            )?;
            tx.execute(
                "DELETE FROM pending_publications WHERE tenant_namespace=?1 AND source_id=?2",
                params![tenant_namespace, source.source_id],
            )?;
        }
        tx.execute(
            "UPDATE namespace_frontiers SET lifecycle_epoch=?2 WHERE tenant_namespace=?1",
            params![tenant_namespace, lifecycle_epoch as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn pending_publications(&self) -> Result<Vec<PendingPublication>> {
        let mut statement = self.connection.prepare(
            "SELECT tenant_namespace,source_id,expected_previous_version,target_version,lifecycle_epoch,authority_epoch \
             FROM pending_publications ORDER BY tenant_namespace,source_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(PendingPublication {
                tenant_namespace: row.get(0)?,
                source_id: row.get(1)?,
                expected_previous_version: row.get::<_, Option<i64>>(2)?.map(|value| value as u64),
                target_version: row.get::<_, i64>(3)? as u64,
                lifecycle_epoch: row.get::<_, i64>(4)? as u64,
                authority_epoch: row.get::<_, i64>(5)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub(crate) fn blocked_sources(&self) -> Result<Vec<SourceFrontier>> {
        let mut statement = self.connection.prepare(
            "SELECT tenant_namespace,source_id,current_version,lifecycle_epoch,use_state,authority_epoch \
             FROM source_frontiers WHERE use_state='BLOCKED' ORDER BY tenant_namespace,source_id",
        )?;
        let rows = statement.query_map([], |row| {
            let state: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                state,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            let (tenant_namespace, source_id, version, lifecycle_epoch, state, authority_epoch) =
                row?;
            result.push(SourceFrontier {
                source: SourceIdentity {
                    tenant_namespace,
                    source_id,
                    version: version as u64,
                },
                lifecycle_epoch: lifecycle_epoch as u64,
                use_state: FrontierUseState::parse(&state)?,
                authority_epoch: authority_epoch as u64,
            });
        }
        Ok(result)
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > FRONTIER_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS namespace_frontiers( \
            tenant_namespace TEXT PRIMARY KEY, \
            lifecycle_epoch INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_epoch>=0), \
            authority_epoch INTEGER NOT NULL DEFAULT 0 CHECK(authority_epoch>=0) \
         ); \
         CREATE TABLE IF NOT EXISTS source_frontiers( \
            tenant_namespace TEXT NOT NULL,source_id TEXT NOT NULL,current_version INTEGER NOT NULL CHECK(current_version>0), \
            lifecycle_epoch INTEGER NOT NULL CHECK(lifecycle_epoch>=0), \
            use_state TEXT NOT NULL CHECK(use_state IN ('ACTIVE','BLOCKED')), \
            authority_epoch INTEGER NOT NULL CHECK(authority_epoch>=0), \
            PRIMARY KEY(tenant_namespace,source_id), \
            FOREIGN KEY(tenant_namespace) REFERENCES namespace_frontiers(tenant_namespace) \
         ); \
         CREATE TABLE IF NOT EXISTS pending_publications( \
            tenant_namespace TEXT NOT NULL,source_id TEXT NOT NULL,expected_previous_version INTEGER,target_version INTEGER NOT NULL CHECK(target_version>0), \
            lifecycle_epoch INTEGER NOT NULL CHECK(lifecycle_epoch>=0),authority_epoch INTEGER NOT NULL CHECK(authority_epoch>=0), \
            PRIMARY KEY(tenant_namespace,source_id), \
            FOREIGN KEY(tenant_namespace) REFERENCES namespace_frontiers(tenant_namespace) \
         );",
    )?;
    connection.pragma_update(None, "user_version", FRONTIER_SCHEMA_VERSION)?;
    Ok(())
}

fn ensure_namespace_tx(tx: &rusqlite::Transaction<'_>, tenant_namespace: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO namespace_frontiers(tenant_namespace,lifecycle_epoch,authority_epoch) \
         VALUES(?1,0,0) ON CONFLICT DO NOTHING",
        [tenant_namespace],
    )?;
    Ok(())
}
