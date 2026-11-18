//! The stores of the pending reverts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_contracts::common::ActionId;
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::PendingRevert;
use crate::lock;

/// The value of the field `schema` in the file of a [`FileRevertStore`].
pub(crate) const FILE_SCHEMA: &str = "aegis.pending_reverts.v1";

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The durable storage of the pending reverts.
///
/// The dispatcher writes a pending revert before it calls the connector. The scheduler
/// reads the pending reverts when it starts and after each change.
///
/// An implementation must make each write durable before it returns. An implementation
/// must be safe to share between tasks.
#[async_trait]
pub trait RevertStore: Send + Sync {
    /// Writes one pending revert. A pending revert for the same action is replaced.
    async fn put(&self, revert: PendingRevert) -> Result<()>;

    /// Reads the pending revert of one action.
    async fn get(&self, action_id: ActionId) -> Result<Option<PendingRevert>>;

    /// Removes the pending revert of one action and returns it.
    async fn remove(&self, action_id: ActionId) -> Result<Option<PendingRevert>>;

    /// Lists all pending reverts. The pending revert with the earliest due time is first.
    async fn list(&self) -> Result<Vec<PendingRevert>>;
}

fn sorted(reverts: &BTreeMap<ActionId, PendingRevert>) -> Vec<PendingRevert> {
    let mut list: Vec<PendingRevert> = reverts.values().cloned().collect();
    list.sort_by_key(|revert| (revert.due_at, revert.action_id));
    list
}

/// A [`RevertStore`] that keeps the pending reverts in memory.
///
/// The data does not stay after a restart. Use this store in tests. Use
/// [`FileRevertStore`] in production.
#[derive(Default)]
pub struct MemoryRevertStore {
    reverts: Mutex<BTreeMap<ActionId, PendingRevert>>,
}

#[async_trait]
impl RevertStore for MemoryRevertStore {
    async fn put(&self, revert: PendingRevert) -> Result<()> {
        lock(&self.reverts).insert(revert.action_id, revert);
        Ok(())
    }

    async fn get(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        Ok(lock(&self.reverts).get(&action_id).cloned())
    }

    async fn remove(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        Ok(lock(&self.reverts).remove(&action_id))
    }

    async fn list(&self) -> Result<Vec<PendingRevert>> {
        Ok(sorted(&lock(&self.reverts)))
    }
}

/// The contents of the file of a [`FileRevertStore`].
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    reverts: Vec<PendingRevert>,
}

/// A [`RevertStore`] that keeps the pending reverts in one JSON file.
///
/// Each change writes the full data to a new file in the same directory, syncs it to the
/// disk, and then renames it over the store file. Thus the store file always holds the
/// data from before or from after a change, also if the process stops during the write.
///
/// The file names the targets of the pending reverts. On Unix, only the owner can read it.
/// Use one store file for one dispatcher.
pub struct FileRevertStore {
    path: PathBuf,
    reverts: tokio::sync::Mutex<BTreeMap<ActionId, PendingRevert>>,
    writes: AtomicU64,
}

impl FileRevertStore {
    /// Opens the store file and reads the pending reverts.
    ///
    /// The function makes the directory of the file if it does not exist. A file that does
    /// not exist gives an empty store.
    ///
    /// # Errors
    ///
    /// - [`Error::Integrity`]: the file is not a valid store file. The function does not
    ///   start with an empty store, because that loses the pending reverts. Examine the
    ///   file.
    /// - [`Error::Unavailable`]: the function cannot read the file or make the directory.
    pub async fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let unavailable = |operation: &str, error: std::io::Error| {
            Error::Unavailable(format!(
                "cannot {operation} the revert store {}: {error}",
                path.display()
            ))
        };
        if let Some(directory) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(directory)
                .await
                .map_err(|error| unavailable("make the directory of", error))?;
        }
        let reverts = match tokio::fs::metadata(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(unavailable("read", error)),
            Ok(metadata) => {
                if metadata.len() > MAX_FILE_BYTES {
                    return Err(Error::Integrity(format!(
                        "the revert store {} has {} bytes; the limit is {MAX_FILE_BYTES}",
                        path.display(),
                        metadata.len()
                    )));
                }
                let bytes = tokio::fs::read(&path)
                    .await
                    .map_err(|error| unavailable("read", error))?;
                Self::decode(&path, &bytes)?
            }
        };
        Ok(Self {
            path,
            reverts: tokio::sync::Mutex::new(reverts),
            writes: AtomicU64::new(0),
        })
    }

    /// Returns the path of the store file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn decode(path: &Path, bytes: &[u8]) -> Result<BTreeMap<ActionId, PendingRevert>> {
        let invalid = |reason: String| {
            Error::Integrity(format!(
                "the revert store {} is not valid: {reason}; examine the file, because it can hold pending reverts",
                path.display()
            ))
        };
        let document: Document =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        if document.schema != FILE_SCHEMA {
            return Err(invalid(format!(
                "the schema must be {FILE_SCHEMA}, not {:?}",
                document.schema
            )));
        }
        let mut reverts = BTreeMap::new();
        for revert in document.reverts {
            let action_id = revert.action_id;
            if reverts.insert(action_id, revert).is_some() {
                return Err(invalid(format!(
                    "the action {action_id} has two pending reverts"
                )));
            }
        }
        Ok(reverts)
    }

    /// Returns the contents of the store file for `reverts`.
    ///
    /// The function refuses data that is larger than the limit of [`open`](Self::open),
    /// so the store never writes a file that it cannot read again.
    fn encode(path: &Path, reverts: &BTreeMap<ActionId, PendingRevert>) -> Result<Vec<u8>> {
        let document = Document {
            schema: FILE_SCHEMA.to_owned(),
            reverts: sorted(reverts),
        };
        let mut bytes = serde_json::to_vec_pretty(&document)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(Error::Unavailable(format!(
                "the revert store {} is full: {} pending reverts need {} bytes, and the limit is {MAX_FILE_BYTES}",
                path.display(),
                reverts.len(),
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Writes the data to a new file and renames the new file over the store file.
    async fn persist(&self, reverts: &BTreeMap<ActionId, PendingRevert>) -> Result<()> {
        let bytes = Self::encode(&self.path, reverts)?;
        let mut name = self
            .path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            self.writes.fetch_add(1, Ordering::Relaxed)
        ));
        let temporary = self.path.with_file_name(name);
        let target = self.path.clone();
        let written = tokio::task::spawn_blocking(move || {
            let result = replace_file(&temporary, &target, &bytes);
            if result.is_err() {
                // The store file is not changed. Remove the partial file.
                if let Err(cleanup) = std::fs::remove_file(&temporary)
                    && cleanup.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        file = %temporary.display(),
                        error = %cleanup,
                        "could not remove the temporary file of the revert store"
                    );
                }
            }
            result
        })
        .await;
        let failure = match written {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => error.to_string(),
            Err(error) => format!("the write task stopped: {error}"),
        };
        Err(Error::Unavailable(format!(
            "cannot write the revert store {}: {failure}",
            self.path.display()
        )))
    }
}

/// Writes `bytes` to the file `temporary`, syncs it, and renames it to `target`.
fn replace_file(temporary: &Path, target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, target)?;
    // Sync the directory, so that the new name of the file is durable.
    #[cfg(unix)]
    if let Some(directory) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[async_trait]
impl RevertStore for FileRevertStore {
    async fn put(&self, revert: PendingRevert) -> Result<()> {
        let mut reverts = self.reverts.lock().await;
        let mut changed = reverts.clone();
        changed.insert(revert.action_id, revert);
        self.persist(&changed).await?;
        *reverts = changed;
        Ok(())
    }

    async fn get(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        Ok(self.reverts.lock().await.get(&action_id).cloned())
    }

    async fn remove(&self, action_id: ActionId) -> Result<Option<PendingRevert>> {
        let mut reverts = self.reverts.lock().await;
        if !reverts.contains_key(&action_id) {
            return Ok(None);
        }
        let mut changed = reverts.clone();
        let removed = changed.remove(&action_id);
        self.persist(&changed).await?;
        *reverts = changed;
        Ok(removed)
    }

    async fn list(&self) -> Result<Vec<PendingRevert>> {
        Ok(sorted(&*self.reverts.lock().await))
    }
}

#[cfg(test)]
mod tests {
    use aegis_contracts::action::ActionKind;
    use aegis_contracts::common::{EntityKind, EntityRef};
    use chrono::{DateTime, Utc};

    use super::super::{PendingState, add_seconds};
    use super::*;

    fn pending(due_in: u64) -> PendingRevert {
        let start = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).unwrap();
        PendingRevert {
            action_id: ActionId::new(),
            kind: ActionKind::DisableUser,
            target: EntityRef::new(EntityKind::User, "user-1"),
            incident_id: None,
            requested_by: "responder".to_owned(),
            revert_after_seconds: due_in,
            armed_at: start,
            due_at: add_seconds(start, due_in),
            state: PendingState::Waiting,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            approval_id: None,
            audit_sequence: Some(7),
        }
    }

    #[tokio::test]
    async fn the_memory_store_lists_by_due_time_and_removes_one() {
        let store = MemoryRevertStore::default();
        let late = pending(600);
        let early = pending(60);
        store.put(late.clone()).await.unwrap();
        store.put(early.clone()).await.unwrap();

        assert_eq!(store.list().await.unwrap(), [early.clone(), late.clone()]);
        assert_eq!(store.get(late.action_id).await.unwrap(), Some(late.clone()));
        assert_eq!(store.get(ActionId::new()).await.unwrap(), None);

        let mut changed = early.clone();
        changed.attempts = 2;
        store.put(changed.clone()).await.unwrap();
        assert_eq!(store.list().await.unwrap(), [changed.clone(), late.clone()]);

        assert_eq!(store.remove(early.action_id).await.unwrap(), Some(changed));
        assert_eq!(store.remove(early.action_id).await.unwrap(), None);
        assert_eq!(store.list().await.unwrap(), [late]);
    }

    #[test]
    fn encode_refuses_data_that_open_cannot_read_again() {
        let path = Path::new("reverts.json");
        let mut reverts = BTreeMap::new();
        let one = pending(60);
        reverts.insert(one.action_id, one.clone());
        let bytes = FileRevertStore::encode(path, &reverts).unwrap();
        assert_eq!(FileRevertStore::decode(path, &bytes).unwrap(), reverts);

        // Each pending revert needs more than 400 bytes, so this data is above the limit.
        for _ in 0..(MAX_FILE_BYTES / 400) {
            let more = pending(60);
            reverts.insert(more.action_id, more);
        }
        let error = FileRevertStore::encode(path, &reverts).unwrap_err();
        assert!(
            matches!(&error, Error::Unavailable(message)
                if message.starts_with("the revert store reverts.json is full: ")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn decode_rejects_a_file_with_a_different_schema_or_a_duplicate() {
        let path = Path::new("reverts.json");
        let one = pending(60);
        let other_schema = serde_json::to_vec(&Document {
            schema: "aegis.pending_reverts.v0".to_owned(),
            reverts: vec![one.clone()],
        })
        .unwrap();
        let error = FileRevertStore::decode(path, &other_schema).unwrap_err();
        assert!(
            matches!(&error, Error::Integrity(message) if message.contains("the schema must be aegis.pending_reverts.v1")),
            "{error:?}"
        );

        let duplicate = serde_json::to_vec(&Document {
            schema: FILE_SCHEMA.to_owned(),
            reverts: vec![one.clone(), one.clone()],
        })
        .unwrap();
        let error = FileRevertStore::decode(path, &duplicate).unwrap_err();
        assert!(
            matches!(&error, Error::Integrity(message) if message.contains("has two pending reverts")),
            "{error:?}"
        );

        let valid = serde_json::to_vec(&Document {
            schema: FILE_SCHEMA.to_owned(),
            reverts: vec![one.clone()],
        })
        .unwrap();
        assert_eq!(
            FileRevertStore::decode(path, &valid).unwrap(),
            BTreeMap::from([(one.action_id, one)])
        );
    }
}
