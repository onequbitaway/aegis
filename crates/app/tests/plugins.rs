//! The connector plugins of the `[plugins]` section go to the source registry and to the
//! action registry.
#![cfg(feature = "plugins")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use aegis_app::App;
use aegis_contracts::Error;
use aegis_contracts::action::ActionKind;

use support::Starter;

/// The Rust target of a WebAssembly component.
const TARGET: &str = "wasm32-wasip2";

/// Builds the example plugins of the repository and returns the directory of the
/// component files. `cargo` does no work when the plugins are up to date.
fn build_example_plugins() -> PathBuf {
    let plugins = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let target_dir = plugins.join("target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(&cargo)
        .current_dir(&plugins)
        .args(["build", "--release", "--locked", "--target", TARGET])
        .arg("--target-dir")
        .arg(&target_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the example plugins did not build. Install the target with `rustup target add \
         {TARGET}`.\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    target_dir.join(TARGET).join("release")
}

/// Puts the two example plugins and their manifests in `directory`.
fn install_example_plugins(directory: &Path) {
    let components = build_example_plugins();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    std::fs::create_dir_all(directory).unwrap();
    for (crate_name, file) in [
        ("example-source", "example_source"),
        ("example-action", "example_action"),
    ] {
        std::fs::copy(
            components.join(format!("{file}.wasm")),
            directory.join(format!("{file}.wasm")),
        )
        .unwrap();
        std::fs::copy(
            repository
                .join(crate_name)
                .join(format!("{crate_name}.toml")),
            directory.join(format!("{crate_name}.toml")),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn a_source_plugin_and_an_action_plugin_go_to_their_registries() {
    let starter = Starter::new();
    install_example_plugins(&starter.path().join("plugins"));
    let config = starter.config_with(|text| text + "\n[plugins]\ndir = \"plugins\"\n");

    let app = starter.build(&config, |builder| builder).await;

    assert_eq!(app.sources().names(), ["example-source"]);
    let source = app.sources().get("example-source").unwrap();
    assert_eq!(source.info().name, "example-source");
    source.check().await.unwrap();

    // The plugin comes before the built-in connectors, so it does the `notify` action.
    assert_eq!(
        app.action_registry().names(),
        ["webhook-notify", "honeytokens", "simulation"]
    );
    let notify = app.action_registry().select(&ActionKind::Notify).unwrap();
    assert_eq!(notify.info().name, "webhook-notify");
    let block = app.action_registry().select(&ActionKind::BlockIp).unwrap();
    assert_eq!(block.info().name, "simulation");
}

#[tokio::test]
async fn a_plugin_that_fails_its_integrity_check_stops_the_build() {
    let starter = Starter::new();
    let directory = starter.path().join("plugins");
    install_example_plugins(&directory);
    let manifest = directory.join("example-source.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(
        &manifest,
        format!("sha256 = \"{}\"\n{text}", "0".repeat(64)),
    )
    .unwrap();
    let config = starter.config_with(|text| text + "\n[plugins]\ndir = \"plugins\"\n");

    let error = match App::builder(&config).base_dir(starter.path()).build().await {
        Ok(_) => panic!("the plugin must not load"),
        Err(error) => error,
    };

    assert!(
        matches!(&error, Error::Integrity(message) if message.starts_with("[plugins] plugin example-source")),
        "{error:?}"
    );

    // A limit of the configuration applies: with `require_sha256`, a manifest with no
    // hash does not load.
    std::fs::write(&manifest, text).unwrap();
    let strict = starter.config_with(|text| {
        text + "\n[plugins]\ndir = \"plugins\"\n\n[plugins.limits]\nrequire_sha256 = true\n"
    });
    let error = match App::builder(&strict).base_dir(starter.path()).build().await {
        Ok(_) => panic!("the plugin must not load"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, Error::Integrity(message)
            if message.starts_with("[plugins] plugin ")
                && message.ends_with("the manifest has no sha256 value and this host requires one")),
        "{error:?}"
    );
}
