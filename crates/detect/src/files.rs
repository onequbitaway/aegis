//! File reads with a size limit.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::DetectError;

/// Reads a text file of at most `limit` bytes.
///
/// `invalid` makes the error for a file that is too large, is not a regular file, or is not
/// UTF-8 text.
pub(crate) fn read_text(
    path: &Path,
    limit: u64,
    invalid: impl Fn(String) -> DetectError,
) -> Result<String, DetectError> {
    let file = fs::File::open(path).map_err(|error| DetectError::io(path, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| DetectError::io(path, error))?;
    if !metadata.is_file() {
        return Err(invalid("the path is not a regular file".to_owned()));
    }
    // The limit applies to the read and not only to the metadata, because a file can grow.
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| DetectError::io(path, error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(invalid(format!(
            "the file is larger than the limit of {limit} bytes"
        )));
    }
    String::from_utf8(bytes).map_err(|_| invalid("the file is not UTF-8 text".to_owned()))
}

/// Lists the files in `directory` that have one of the `extensions`, in order of name.
///
/// A directory that does not exist gives an empty list. The function does not go into
/// subdirectories.
pub(crate) fn list_files(
    directory: &Path,
    extensions: &[&str],
) -> Result<Vec<PathBuf>, DetectError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(DetectError::io(directory, error)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| DetectError::io(directory, error))?
            .path();
        let wanted = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                extensions
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(extension))
            });
        if wanted && path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid(reason: String) -> DetectError {
        DetectError::rule("probe", reason)
    }

    #[test]
    fn read_text_returns_the_text_of_a_file_at_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("a.yml");
        fs::write(&path, "12345").unwrap();
        assert_eq!(read_text(&path, 5, invalid).unwrap(), "12345");
    }

    #[test]
    fn read_text_rejects_a_file_above_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("a.yml");
        fs::write(&path, "123456").unwrap();
        let error = read_text(&path, 5, invalid).unwrap_err();
        assert_eq!(
            error.to_string(),
            "rule probe: the file is larger than the limit of 5 bytes"
        );
    }

    #[test]
    fn read_text_rejects_bytes_that_are_not_text_and_paths_that_are_not_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("a.yml");
        fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        let error = read_text(&path, 100, invalid).unwrap_err();
        assert_eq!(error.to_string(), "rule probe: the file is not UTF-8 text");

        let error = read_text(directory.path(), 100, invalid).unwrap_err();
        assert!(
            matches!(&error, DetectError::Rule { reason, .. } if reason == "the path is not a regular file")
                || matches!(&error, DetectError::Io { .. }),
            "{error}"
        );
    }

    #[test]
    fn read_text_reports_a_missing_file_as_a_read_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("none.yml");
        let error = read_text(&path, 100, invalid).unwrap_err();
        assert!(
            matches!(&error, DetectError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
            "{error}"
        );
    }

    #[test]
    fn list_files_filters_by_extension_and_sorts_by_name() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["b.yml", "a.YAML", "c.txt", "d.yml.bak", "noextension"] {
            fs::write(directory.path().join(name), "x").unwrap();
        }
        fs::create_dir(directory.path().join("nested.yml")).unwrap();
        let names: Vec<String> = list_files(directory.path(), &["yml", "yaml"])
            .unwrap()
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.YAML", "b.yml"]);
    }

    #[test]
    fn list_files_gives_an_empty_list_for_a_directory_that_does_not_exist() {
        let directory = tempfile::tempdir().unwrap();
        let files = list_files(&directory.path().join("none"), &["yml"]).unwrap();
        assert_eq!(files, Vec::<PathBuf>::new());
    }
}
