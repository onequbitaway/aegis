//! Stores for the cursor of each connector.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::check_connector_name;

/// A store that keeps the cursor of each connector between restarts.
///
/// The [`IngestRunner`](crate::IngestRunner) saves the cursor after it publishes a batch.
/// After a restart, the runner continues from the saved cursor.
#[async_trait]
pub trait CheckpointStore: Send + Sync {
    /// Returns the saved cursor of the connector `name`.
    ///
    /// Returns `None` if the store has no cursor for the connector.
    async fn load(&self, name: &str) -> Result<Option<String>>;

    /// Saves `cursor` as the cursor of the connector `name`.
    ///
    /// The new cursor replaces the old cursor completely or not at all.
    async fn save(&self, name: &str, cursor: &str) -> Result<()>;
}

/// A checkpoint store that keeps the cursors in memory.
///
/// The cursors do not survive a restart of the process. Use this store for tests and for
/// sources that must start again from the beginning.
#[derive(Debug, Default)]
pub struct MemoryCheckpointStore {
    cursors: Mutex<HashMap<String, String>>,
}

impl MemoryCheckpointStore {
    /// Makes an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CheckpointStore for MemoryCheckpointStore {
    async fn load(&self, name: &str) -> Result<Option<String>> {
        check_connector_name(name)?;
        let cursors = self.cursors.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(cursors.get(name).cloned())
    }

    async fn save(&self, name: &str, cursor: &str) -> Result<()> {
        check_connector_name(name)?;
        let mut cursors = self.cursors.lock().unwrap_or_else(PoisonError::into_inner);
        cursors.insert(name.to_owned(), cursor.to_owned());
        Ok(())
    }
}

/// The contents of one checkpoint file.
#[derive(Debug, Serialize, Deserialize)]
struct StoredCheckpoint {
    /// The cursor of the connector.
    cursor: String,
    /// The time at which the store saved the cursor.
    saved_at: DateTime<Utc>,
}

/// A checkpoint store that keeps one small JSON file for each connector in a directory.
///
/// The store writes a temporary file, syncs it, and renames it to the final name. Thus a
/// crash during a save leaves the old cursor in place.
#[derive(Debug, Clone)]
pub struct FileCheckpointStore {
    directory: PathBuf,
}

impl FileCheckpointStore {
    /// Makes a store that keeps its files in `directory`.
    ///
    /// The store creates the directory at the first save.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Returns the directory that holds the checkpoint files.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the path of the checkpoint file of the connector `name`.
    fn path(&self, name: &str) -> Result<PathBuf> {
        check_connector_name(name)?;
        Ok(self.directory.join(format!("{name}.checkpoint.json")))
    }

    /// Writes `payload` to `temporary` and then renames it to `target`.
    async fn replace(
        &self,
        temporary: &Path,
        target: &Path,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut file = fs::File::create(temporary).await?;
        file.write_all(payload).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(temporary, target).await?;
        // The rename is durable only after the directory entry is on the disk.
        #[cfg(unix)]
        fs::File::open(&self.directory).await?.sync_all().await?;
        Ok(())
    }
}

#[async_trait]
impl CheckpointStore for FileCheckpointStore {
    async fn load(&self, name: &str) -> Result<Option<String>> {
        let path = self.path(name)?;
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::other(
                    format!("read the checkpoint of connector {name}"),
                    error,
                ));
            }
        };
        let stored: StoredCheckpoint = serde_json::from_slice(&bytes).map_err(|error| {
            Error::Integrity(format!(
                "the checkpoint file of connector {name} is not valid: {error}"
            ))
        })?;
        Ok(Some(stored.cursor))
    }

    async fn save(&self, name: &str, cursor: &str) -> Result<()> {
        let target = self.path(name)?;
        let context = || format!("save the checkpoint of connector {name}");
        fs::create_dir_all(&self.directory)
            .await
            .map_err(|error| Error::other(context(), error))?;
        let payload = serde_json::to_vec(&StoredCheckpoint {
            cursor: cursor.to_owned(),
            saved_at: Utc::now(),
        })?;
        let temporary = self
            .directory
            .join(format!(".{name}.{}.tmp", Uuid::now_v7()));
        if let Err(error) = self.replace(&temporary, &target, &payload).await {
            if let Err(cleanup) = fs::remove_file(&temporary).await
                && cleanup.kind() != ErrorKind::NotFound
            {
                tracing::warn!(
                    connector = name,
                    error = %cleanup,
                    "could not remove the temporary checkpoint file"
                );
            }
            return Err(Error::other(context(), error));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn the_memory_store_returns_the_last_saved_cursor_of_each_connector() {
        let store = MemoryCheckpointStore::new();
        assert_eq!(store.load("entra").await.unwrap(), None);
        store.save("entra", "1").await.unwrap();
        store.save("file", "a").await.unwrap();
        store.save("entra", "2").await.unwrap();
        assert_eq!(store.load("entra").await.unwrap().as_deref(), Some("2"));
        assert_eq!(store.load("file").await.unwrap().as_deref(), Some("a"));
        assert_eq!(store.load("other").await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_file_store_keeps_the_cursor_for_a_new_store_on_the_same_directory() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("state").join("checkpoints");
        let store = FileCheckpointStore::new(&nested);
        assert_eq!(store.directory(), nested);
        assert_eq!(store.load("entra").await.unwrap(), None);

        store.save("entra", "cursor-1").await.unwrap();
        store.save("file", "17").await.unwrap();
        store.save("entra", "cursor-2").await.unwrap();

        let reopened = FileCheckpointStore::new(&nested);
        assert_eq!(
            reopened.load("entra").await.unwrap().as_deref(),
            Some("cursor-2")
        );
        assert_eq!(reopened.load("file").await.unwrap().as_deref(), Some("17"));
        assert_eq!(
            file_names(&nested),
            ["entra.checkpoint.json", "file.checkpoint.json"],
            "a save must leave no temporary file"
        );
    }

    #[tokio::test]
    async fn a_save_puts_a_new_file_in_place_and_does_not_write_into_the_old_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileCheckpointStore::new(directory.path().join("checkpoints"));
        store.save("entra", "cursor-1").await.unwrap();
        // A second name for the file of the first save. A write into that file changes the
        // bytes that this name shows. A rename of a new file over the first name does not.
        let old_file = directory.path().join("old-file.json");
        std::fs::hard_link(store.directory().join("entra.checkpoint.json"), &old_file).unwrap();
        let before = std::fs::read(&old_file).unwrap();

        store.save("entra", "cursor-2").await.unwrap();

        assert_eq!(
            store.load("entra").await.unwrap().as_deref(),
            Some("cursor-2")
        );
        assert_eq!(
            std::fs::read(&old_file).unwrap(),
            before,
            "a reader of the old file must not see a partial write"
        );
    }

    #[tokio::test]
    async fn the_file_store_keeps_a_cursor_with_quotes_and_new_lines() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileCheckpointStore::new(directory.path());
        let cursor = "{\"sign_ins\":\"2026-11-03T09:00:00Z\"}\nsecond line";
        store.save("entra", cursor).await.unwrap();
        assert_eq!(store.load("entra").await.unwrap().as_deref(), Some(cursor));
    }

    #[tokio::test]
    async fn a_damaged_checkpoint_file_is_an_integrity_error() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileCheckpointStore::new(directory.path());
        store.save("entra", "cursor-1").await.unwrap();
        std::fs::write(directory.path().join("entra.checkpoint.json"), b"{\"cur").unwrap();
        let error = store.load("entra").await.unwrap_err();
        assert!(
            matches!(&error, Error::Integrity(message) if message.contains("entra")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_failed_save_returns_the_error_and_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileCheckpointStore::new(directory.path());
        store.save("entra", "cursor-1").await.unwrap();
        // A directory with the name of the checkpoint file makes the rename fail.
        let blocked = FileCheckpointStore::new(directory.path());
        std::fs::remove_file(directory.path().join("entra.checkpoint.json")).unwrap();
        std::fs::create_dir(directory.path().join("entra.checkpoint.json")).unwrap();
        std::fs::write(
            directory.path().join("entra.checkpoint.json").join("keep"),
            b"",
        )
        .unwrap();

        let error = blocked.save("entra", "cursor-2").await.unwrap_err();
        assert!(
            matches!(&error, Error::Other { context, .. } if context == "save the checkpoint of connector entra"),
            "{error}"
        );
        assert_eq!(file_names(directory.path()), ["entra.checkpoint.json"]);
    }

    #[tokio::test]
    async fn a_name_that_leaves_the_directory_is_invalid_input() {
        let directory = tempfile::tempdir().unwrap();
        let file_store = FileCheckpointStore::new(directory.path().join("inner"));
        let memory_store = MemoryCheckpointStore::new();
        for name in ["../escape", "a/b", "", "."] {
            let error = file_store.save(name, "cursor").await.unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{name:?}");
            let error = file_store.load(name).await.unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{name:?}");
            let error = memory_store.save(name, "cursor").await.unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{name:?}");
        }
        assert_eq!(file_names(directory.path()), Vec::<String>::new());
    }
}
