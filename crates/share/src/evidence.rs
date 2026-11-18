//! Evidence items and the manifest that lets a receiver check them.
//!
//! An evidence item is one minimized log record, as one line of JSON. The line holds
//! only printable ASCII, so each transport keeps the bytes. The manifest holds the
//! SHA-256 of each line, and the SHA-256 of the file that has all lines.
//!
//! The manifest shows that an item did not change after the builder made it. It does not
//! show who made the package. To show the origin, sign the manifest, or send it on a
//! second channel.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::ShareError;
use crate::text::{json_compact, json_pretty};

/// The name of the file that holds the evidence items, one item in each line.
pub const EVIDENCE_FILE_NAME: &str = "evidence.jsonl";

/// The name of the hash algorithm of the manifest.
pub const HASH_ALGORITHM: &str = "sha256";

/// The type of an evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceItemKind {
    /// A minimized event from a log of the operator.
    Event,
    /// A reference to a sealed record in the audit log of the operator.
    AuditRecord,
}

/// One item of evidence in a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// The identifier of the item in its report, for example `E0001`.
    pub id: String,
    /// The type of the item.
    pub kind: EvidenceItemKind,
    /// The item: one line of JSON in printable ASCII, with no line break.
    pub content: String,
    /// The SHA-256 of the bytes of `content`, in lower-case hexadecimal.
    pub sha256: String,
}

/// Returns the SHA-256 of `bytes` in lower-case hexadecimal.
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn length(text: &str) -> u64 {
    u64::try_from(text.len()).unwrap_or(u64::MAX)
}

/// Returns the identifier of the item with the 1-based position `number`.
pub(crate) fn item_id(number: usize, total: usize) -> String {
    let width = total.to_string().len().max(4);
    format!("E{number:0width$}")
}

impl EvidenceItem {
    /// Makes an item from the fields of a record. The item identifier goes into the
    /// record as the field `item`, so that each line names itself.
    pub(crate) fn new(id: String, kind: EvidenceItemKind, mut fields: Map<String, Value>) -> Self {
        fields.insert("item".to_owned(), Value::String(id.clone()));
        let content = json_compact(&Value::Object(fields));
        let sha256 = sha256_hex(content.as_bytes());
        Self {
            id,
            kind,
            content,
            sha256,
        }
    }
}

/// Returns the evidence file: the content of each item, each followed by a line feed.
#[must_use]
pub fn evidence_jsonl(items: &[EvidenceItem]) -> String {
    let mut text = String::with_capacity(items.iter().map(|item| item.content.len() + 1).sum());
    for item in items {
        text.push_str(&item.content);
        text.push('\n');
    }
    text
}

/// The manifest entry of one evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// The identifier of the item.
    pub id: String,
    /// The type of the item.
    pub kind: EvidenceItemKind,
    /// The number of bytes of the item.
    pub bytes: u64,
    /// The SHA-256 of the item, in lower-case hexadecimal.
    pub sha256: String,
}

/// The hashes of the evidence items of one report.
///
/// A receiver uses [`verify_items`](Self::verify_items) or
/// [`verify_file`](Self::verify_file) to check that the evidence did not change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceManifest {
    /// The hash algorithm. The value is always [`HASH_ALGORITHM`].
    pub algorithm: String,
    /// The name of the evidence file. The value is always [`EVIDENCE_FILE_NAME`].
    pub file_name: String,
    /// The number of bytes of the evidence file.
    pub file_bytes: u64,
    /// The SHA-256 of the evidence file, in lower-case hexadecimal.
    pub file_sha256: String,
    /// One entry for each item, in the order of the lines of the evidence file.
    pub items: Vec<ManifestEntry>,
}

impl EvidenceManifest {
    /// Makes the manifest of `items`.
    #[must_use]
    pub fn for_items(items: &[EvidenceItem]) -> Self {
        let file = evidence_jsonl(items);
        Self {
            algorithm: HASH_ALGORITHM.to_owned(),
            file_name: EVIDENCE_FILE_NAME.to_owned(),
            file_bytes: length(&file),
            file_sha256: sha256_hex(file.as_bytes()),
            items: items
                .iter()
                .map(|item| ManifestEntry {
                    id: item.id.clone(),
                    kind: item.kind,
                    bytes: length(&item.content),
                    sha256: sha256_hex(item.content.as_bytes()),
                })
                .collect(),
        }
    }

    fn check_algorithm(&self) -> Result<(), ShareError> {
        if self.algorithm == HASH_ALGORITHM {
            Ok(())
        } else {
            Err(ShareError::manifest(
                "manifest",
                format!("the algorithm is not {HASH_ALGORITHM}"),
            ))
        }
    }

    fn check_line(entry: &ManifestEntry, content: &str) -> Result<(), ShareError> {
        if length(content) != entry.bytes {
            return Err(ShareError::manifest(
                &entry.id,
                format!(
                    "the item has {} bytes and the manifest gives {}",
                    content.len(),
                    entry.bytes
                ),
            ));
        }
        if sha256_hex(content.as_bytes()) != entry.sha256.to_ascii_lowercase() {
            return Err(ShareError::manifest(
                &entry.id,
                "the SHA-256 of the item is not the value in the manifest",
            ));
        }
        Ok(())
    }

    fn check_count(&self, found: usize) -> Result<(), ShareError> {
        if found == self.items.len() {
            Ok(())
        } else {
            Err(ShareError::manifest(
                &self.file_name,
                format!(
                    "the evidence has {found} items and the manifest has {}",
                    self.items.len()
                ),
            ))
        }
    }

    /// Checks evidence items against the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Manifest`] for the first item that does not agree: a
    /// different number of items, a different identifier, a different length, or a
    /// different hash.
    pub fn verify_items(&self, items: &[EvidenceItem]) -> Result<(), ShareError> {
        self.check_algorithm()?;
        self.check_count(items.len())?;
        for (entry, item) in self.items.iter().zip(items) {
            if entry.id != item.id {
                return Err(ShareError::manifest(
                    &entry.id,
                    "the item at this position has a different identifier",
                ));
            }
            Self::check_line(entry, &item.content)?;
        }
        Ok(())
    }

    /// Checks the text of the evidence file against the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Manifest`] for the first line that does not agree, or for
    /// the file if only the hash of the full file is different.
    pub fn verify_file(&self, text: &str) -> Result<(), ShareError> {
        self.check_algorithm()?;
        let lines: Vec<&str> = text.split_terminator('\n').collect();
        self.check_count(lines.len())?;
        for (entry, line) in self.items.iter().zip(lines) {
            Self::check_line(entry, line)?;
        }
        if length(text) != self.file_bytes
            || sha256_hex(text.as_bytes()) != self.file_sha256.to_ascii_lowercase()
        {
            return Err(ShareError::manifest(
                &self.file_name,
                "the SHA-256 of the file is not the value in the manifest",
            ));
        }
        Ok(())
    }

    /// Returns the manifest as JSON text in printable ASCII.
    ///
    /// # Errors
    ///
    /// Returns [`ShareError::Encode`] if the manifest cannot be encoded.
    pub fn to_json_string(&self) -> Result<String, ShareError> {
        let value =
            serde_json::to_value(self).map_err(|error| ShareError::encode("manifest", error))?;
        Ok(json_pretty(&value))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn item(number: usize, text: &str) -> EvidenceItem {
        let Value::Object(fields) = json!({"type": "event", "text": text}) else {
            panic!("not an object");
        };
        EvidenceItem::new(item_id(number, 2), EvidenceItemKind::Event, fields)
    }

    fn items() -> Vec<EvidenceItem> {
        vec![item(1, "first"), item(2, "second <b>")]
    }

    #[test]
    fn item_identifiers_have_four_digits_or_more() {
        assert_eq!(item_id(1, 3), "E0001");
        assert_eq!(item_id(600, 603), "E0600");
        assert_eq!(item_id(9999, 9999), "E9999");
        assert_eq!(item_id(7, 12_345), "E00007");
    }

    #[test]
    fn an_item_is_one_ascii_line_that_names_itself() {
        let items = items();
        assert_eq!(
            items[0].content,
            r#"{"item":"E0001","text":"first","type":"event"}"#
        );
        assert_eq!(
            items[1].content,
            r#"{"item":"E0002","text":"second \u003cb\u003e","type":"event"}"#
        );
        // The value comes from `printf '%s' '{"item":"E0001","text":"first","type":"event"}' | shasum -a 256`.
        assert_eq!(
            items[0].sha256,
            "4012570e3fb9753c23898b6b7d2d7aaf1d06c73ccf30ba09a81d39b291316f38"
        );
    }

    #[test]
    fn the_manifest_has_one_entry_for_each_item_and_the_hash_of_the_file() {
        let items = items();
        let manifest = EvidenceManifest::for_items(&items);
        assert_eq!(manifest.algorithm, "sha256");
        assert_eq!(manifest.file_name, "evidence.jsonl");
        assert_eq!(manifest.items.len(), 2);
        assert_eq!(manifest.items[0].id, "E0001");
        assert_eq!(manifest.items[0].bytes, 46);
        assert_eq!(manifest.items[0].sha256, items[0].sha256);
        assert_eq!(manifest.items[1].sha256, items[1].sha256);
        let file = evidence_jsonl(&items);
        assert_eq!(file.lines().count(), 2);
        assert_eq!(manifest.file_bytes, u64::try_from(file.len()).unwrap());
        assert_eq!(
            manifest.file_sha256,
            hex::encode(Sha256::digest(file.as_bytes()))
        );
        manifest.verify_items(&items).unwrap();
        manifest.verify_file(&file).unwrap();
    }

    #[test]
    fn a_changed_item_fails_the_check_and_the_error_names_it() {
        let items = items();
        let manifest = EvidenceManifest::for_items(&items);

        let mut changed = items.clone();
        changed[1].content = changed[1].content.replace("second", "sEcond");
        let error = manifest.verify_items(&changed).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "E0002" && reason.contains("SHA-256")),
            "{error}"
        );

        let mut longer = items.clone();
        longer[0].content.push(' ');
        let error = manifest.verify_items(&longer).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "E0001" && reason == "the item has 47 bytes and the manifest gives 46"),
            "{error}"
        );

        let error = manifest.verify_items(&items[..1]).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "evidence.jsonl"
                    && reason == "the evidence has 1 items and the manifest has 2"),
            "{error}"
        );

        let mut swapped = items.clone();
        swapped.swap(0, 1);
        let error = manifest.verify_items(&swapped).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "E0001" && reason.contains("different identifier")),
            "{error}"
        );
    }

    #[test]
    fn a_changed_file_fails_the_check() {
        let items = items();
        let manifest = EvidenceManifest::for_items(&items);
        let file = evidence_jsonl(&items);

        let error = manifest
            .verify_file(&file.replace("first", "fIrst"))
            .unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, .. } if item == "E0001"),
            "{error}"
        );

        let error = manifest.verify_file(&format!("{file}{{}}\n")).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "evidence.jsonl" && reason.contains("3 items")),
            "{error}"
        );

        // The lines are the same, but the last line feed is missing.
        let error = manifest.verify_file(file.trim_end()).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "evidence.jsonl" && reason.contains("SHA-256 of the file")),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_with_a_different_algorithm_fails_closed() {
        let items = items();
        let mut manifest = EvidenceManifest::for_items(&items);
        manifest.algorithm = "md5".to_owned();
        let error = manifest.verify_items(&items).unwrap_err();
        assert!(
            matches!(&error, ShareError::Manifest { item, reason }
                if item == "manifest" && reason == "the algorithm is not sha256"),
            "{error}"
        );
        let error = manifest.verify_file(&evidence_jsonl(&items)).unwrap_err();
        assert!(matches!(error, ShareError::Manifest { .. }), "{error}");
    }

    #[test]
    fn the_manifest_round_trips_through_its_json_text() {
        let items = items();
        let manifest = EvidenceManifest::for_items(&items);
        let text = manifest.to_json_string().unwrap();
        let decoded: EvidenceManifest = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, manifest);
        decoded.verify_items(&items).unwrap();
        // An upper-case hash from a different tool is the same hash.
        let mut upper = decoded;
        upper.items[0].sha256 = upper.items[0].sha256.to_ascii_uppercase();
        upper.verify_items(&items).unwrap();
    }
}
