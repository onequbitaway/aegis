//! Embeds the starter files of the repository in the crate.
//!
//! The script writes `embedded.rs` to the output directory. That file holds the detection
//! pack, the policies, the sample playbooks, and the recorded attack log. A binary that
//! links this crate can thus start with no checkout of the repository.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The directories of the repository that the starter directory gets.
const DIRECTORIES: [&str; 3] = ["detections", "policies", "playbooks"];

/// The recorded attack log, relative to the root of the repository.
const ATTACK_LOG: &str = "fixtures/artex_style_attack.jsonl";

/// Collects the files below `directory`, in path order. Hidden files are not collected.
fn collect(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let hidden = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| name.starts_with('.'));
        if hidden {
            continue;
        }
        if entry.file_type()?.is_dir() {
            collect(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_directory = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let root = manifest_directory.join("../..").canonicalize()?;
    let mut code = String::from(
        "/// The starter files: the path below the starter directory, and the contents.\n\
         pub(crate) static STARTER_FILES: &[(&str, &[u8])] = &[\n",
    );
    for directory in DIRECTORIES {
        let directory = root.join(directory);
        println!("cargo:rerun-if-changed={}", directory.display());
        let mut files = Vec::new();
        collect(&directory, &mut files)?;
        for file in files {
            println!("cargo:rerun-if-changed={}", file.display());
            let relative = file.strip_prefix(&root)?;
            let name = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            writeln!(
                code,
                "    ({name:?}, include_bytes!({:?})),",
                file.display().to_string()
            )?;
        }
    }
    code.push_str("];\n\n");
    let attack_log = root.join(ATTACK_LOG);
    println!("cargo:rerun-if-changed={}", attack_log.display());
    writeln!(
        code,
        "/// The recorded attack log, as JSON Lines.\n\
         pub(crate) static ATTACK_LOG: &str = include_str!({:?});",
        attack_log.display().to_string()
    )?;
    let output = PathBuf::from(std::env::var("OUT_DIR")?).join("embedded.rs");
    fs::write(output, code)?;
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
