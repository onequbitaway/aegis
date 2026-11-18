//! Helpers that the integration tests share.
//!
//! The tests run real guest plugins. This module builds them with `cargo` from the
//! `plugins` directory, one time for each test program. `cargo` does no work when the
//! guests are up to date.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Each test program uses a different part of this module.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use aegis_plugin::{PluginKind, PluginManifest};
use chrono::{DateTime, Utc};

/// The Rust target of a WebAssembly component.
const TARGET: &str = "wasm32-wasip2";

/// Returns the path of the component file of the guest crate `name`.
///
/// # Panics
///
/// Panics with the output of `cargo` if the guest plugins do not build.
pub fn component(name: &str) -> PathBuf {
    static BUILD: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    match BUILD.get_or_init(build_guests) {
        Ok(directory) => directory.join(format!("{}.wasm", name.replace('-', "_"))),
        Err(message) => panic!("{message}"),
    }
}

/// Builds all guest plugins and returns the directory of the component files.
fn build_guests() -> Result<PathBuf, String> {
    let plugins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let target_dir = plugins.join("target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .current_dir(&plugins)
        .args(["build", "--release", "--locked", "--target", TARGET])
        .arg("--target-dir")
        .arg(&target_dir)
        // Flags for the host build, for example coverage flags, do not apply to a guest.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .map_err(|error| {
            format!(
                "Cannot run {} to build the guest plugins in {}: {error}",
                Path::new(&cargo).display(),
                plugins.display()
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "The guest plugins in {} did not build ({}). \
             Make sure that the Rust target is installed: `rustup target add {TARGET}`.\n\
             --- cargo output ---\n{}",
            plugins.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(target_dir.join(TARGET).join("release"))
}

/// Makes a manifest for the guest crate `guest` with no hash and no permitted hosts.
pub fn manifest(name: &str, kind: PluginKind, guest: &str) -> PluginManifest {
    PluginManifest::new(name, kind, component(guest))
}

/// Parses an RFC 3339 time.
pub fn time(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}
