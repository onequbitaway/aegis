//! Tests for how the host finds, checks, and loads plugin files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use aegis_contracts::action::{ActionKind, ActionRequest, ActionStatus};
use aegis_contracts::{EntityKind, EntityRef, Error};
use aegis_plugin::{HostLimits, PluginHost, PluginKind, PluginManifest};
use sha2::{Digest, Sha256};

fn host() -> PluginHost {
    PluginHost::new(HostLimits::default()).unwrap()
}

fn sha256_of(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

/// Copies the component of the guest crate `guest` to `directory` and returns its hash.
fn install(directory: &Path, guest: &str, file_name: &str) -> String {
    let source = common::component(guest);
    std::fs::copy(&source, directory.join(file_name)).unwrap();
    sha256_of(&source)
}

/// Returns the error of a load that must fail.
fn load_error<T>(result: Result<T, Error>) -> Error {
    result.err().expect("the plugin loaded")
}

#[tokio::test]
async fn a_component_with_the_hash_of_the_manifest_loads() {
    let mut manifest = common::manifest("pinned", PluginKind::Source, "example-source");
    let sha256 = sha256_of(&manifest.component);

    manifest.sha256 = Some(sha256.clone());
    let source = host().load_source(&manifest).await.unwrap();
    assert_eq!(source.info().name, "pinned");

    // The case of the hexadecimal digits has no effect.
    manifest.sha256 = Some(sha256.to_uppercase());
    host().load_source(&manifest).await.unwrap();
}

#[tokio::test]
async fn a_manifest_hash_mismatch_is_an_integrity_error() {
    let mut manifest = common::manifest("pinned", PluginKind::Source, "example-source");
    let actual = sha256_of(&manifest.component);
    // This is the hash of a different file.
    let expected = sha256_of(&common::component("example-action"));
    assert_ne!(actual, expected);
    manifest.sha256 = Some(expected.clone());

    let error = load_error(host().load_source(&manifest).await);

    assert!(
        matches!(&error, Error::Integrity(message)
        if *message == format!(
            "plugin pinned: the SHA-256 of the component file is {actual}, but the manifest expects {expected}"
        )),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_changed_component_file_does_not_load_with_the_old_hash() {
    let directory = tempfile::tempdir().unwrap();
    let sha256 = install(directory.path(), "example-source", "source.wasm");
    let path = directory.path().join("source.wasm");
    let mut manifest = PluginManifest::new("pinned", PluginKind::Source, &path);
    manifest.sha256 = Some(sha256);
    let host = host();
    host.load_source(&manifest).await.unwrap();

    // One more byte at the end of the file changes the hash.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0);
    std::fs::write(&path, bytes).unwrap();

    let error = load_error(host.load_source(&manifest).await);
    assert!(matches!(error, Error::Integrity(_)), "{error:?}");
}

#[tokio::test]
async fn a_host_that_requires_a_hash_refuses_a_manifest_without_one() {
    let host = PluginHost::new(HostLimits {
        require_sha256: true,
        ..HostLimits::default()
    })
    .unwrap();
    let mut manifest = common::manifest("unpinned", PluginKind::Source, "example-source");

    let error = load_error(host.load_source(&manifest).await);
    assert!(
        matches!(&error, Error::Integrity(message)
            if message == "plugin unpinned: the manifest has no sha256 value and this host requires one"),
        "{error:?}"
    );

    manifest.sha256 = Some(sha256_of(&manifest.component));
    host.load_source(&manifest).await.unwrap();
}

#[tokio::test]
async fn the_kind_of_the_manifest_must_match_the_load_function_and_the_component() {
    let host = host();

    // The manifest says `action`, and the caller asks for a source.
    let action_manifest = common::manifest("notify", PluginKind::Action, "example-action");
    let error = load_error(host.load_source(&action_manifest).await);
    assert!(
        matches!(&error, Error::Config(message)
            if message == "plugin notify has the kind `action`, but this function loads the kind `source`"),
        "{error:?}"
    );
    let source_manifest = common::manifest("events", PluginKind::Source, "example-source");
    let error = load_error(host.load_action(&source_manifest).await);
    assert!(
        matches!(&error, Error::Config(message)
            if message == "plugin events has the kind `source`, but this function loads the kind `action`"),
        "{error:?}"
    );

    // The manifest says `source`, but the component is an action connector.
    let wrong_component = common::manifest("events", PluginKind::Source, "example-action");
    let error = load_error(host.load_source(&wrong_component).await);
    assert!(
        matches!(&error, Error::Config(message)
        if message.starts_with(
            "plugin events: the component does not implement the source-connector world"
        )),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_component_that_needs_an_import_that_the_sandbox_does_not_give_does_not_load() {
    // This guest implements the source world, and it also imports `test:greedy/vault`.
    let manifest = common::manifest("greedy", PluginKind::Source, "greedy-source");

    let error = load_error(host().load_source(&manifest).await);

    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with(
                "plugin greedy: the component needs an import that the sandbox does not give: "
            ) && message.contains("test:greedy/vault")),
        "{error:?}"
    );
}

/// A component that holds one core module. The module declares one function type that
/// is open for subtypes, `(type (sub (func)))`, and nothing more. It has no code.
const COMPONENT_WITH_A_FUNCTION_SUBTYPE: [u8; 26] = [
    // The component header.
    0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00, // A core module section of 16 bytes.
    0x01, 0x10, // The module header.
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    // A type section with one type: `sub`, no supertypes, `func`, no parameters, no results.
    0x01, 0x06, 0x01, 0x50, 0x00, 0x60, 0x00, 0x00,
];

#[tokio::test]
async fn a_component_that_declares_a_function_subtype_does_not_load() {
    // The engine of this crate has no support for the GC proposal at run time. A module
    // that uses a function subtype must not get to the point where it runs.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("subtype.wasm");
    std::fs::write(&path, COMPONENT_WITH_A_FUNCTION_SUBTYPE).unwrap();
    let manifest = PluginManifest::new("subtype", PluginKind::Source, &path);

    let error = load_error(host().load_source(&manifest).await);

    // The engine refuses the file when it checks it, and the cause is the subtype. With
    // the GC proposal on, the file is a correct component, and the load fails later for
    // a different reason.
    assert!(
        matches!(&error, Error::Config(message)
        if message.starts_with("plugin subtype: the file ")
            && message.ends_with(
                "is not a valid WebAssembly component: failed to parse WebAssembly \
                 module: gc proposal must be enabled to use subtypes (at offset 0x15)"
            )),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_file_that_is_not_a_component_is_a_configuration_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("not-wasm.wasm");
    std::fs::write(&path, b"This file is not WebAssembly.").unwrap();
    let manifest = PluginManifest::new("broken", PluginKind::Source, &path);

    let error = load_error(host().load_source(&manifest).await);

    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with("plugin broken: the file ")
                && message.contains("is not a valid WebAssembly component")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_missing_component_file_is_not_found() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = PluginManifest::new(
        "missing",
        PluginKind::Action,
        directory.path().join("missing.wasm"),
    );

    let error = load_error(host().load_action(&manifest).await);

    assert!(
        matches!(&error, Error::NotFound(message) if message.contains("missing.wasm")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_component_file_over_the_size_limit_does_not_load() {
    let manifest = common::manifest("large", PluginKind::Source, "example-source");
    let size = std::fs::metadata(&manifest.component).unwrap().len();
    let too_small = PluginHost::new(HostLimits {
        max_component_bytes: size - 1,
        ..HostLimits::default()
    })
    .unwrap();

    let error = load_error(too_small.load_source(&manifest).await);
    assert!(
        matches!(&error, Error::Config(message)
        if *message == format!(
            "plugin large: the component file is larger than the limit of {} bytes",
            size - 1
        )),
        "{error:?}"
    );

    let exact = PluginHost::new(HostLimits {
        max_component_bytes: size,
        ..HostLimits::default()
    })
    .unwrap();
    exact.load_source(&manifest).await.unwrap();
}

#[tokio::test]
async fn a_manifest_that_is_not_valid_does_not_load() {
    let mut manifest = common::manifest("bad name", PluginKind::Source, "example-source");
    let error = load_error(host().load_source(&manifest).await);
    assert!(
        matches!(&error, Error::Config(message) if message.contains("plugin name")),
        "{error:?}"
    );

    manifest.name = "events".to_owned();
    manifest.allowed_hosts = vec!["*.example.com".to_owned()];
    let error = load_error(host().load_source(&manifest).await);
    assert!(
        matches!(&error, Error::Config(message)
            if message.starts_with("plugin events: the allowed_hosts entry \"*.example.com\"")),
        "{error:?}"
    );
}

#[tokio::test]
async fn zero_limits_do_not_make_a_host() {
    let error = PluginHost::new(HostLimits {
        max_memory_bytes: 0,
        ..HostLimits::default()
    })
    .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.contains("max_memory_bytes")),
        "{error:?}"
    );
}

#[tokio::test]
async fn load_dir_loads_each_manifest_of_the_directory() {
    let directory = tempfile::tempdir().unwrap();
    let source_hash = install(directory.path(), "example-source", "example_source.wasm");
    install(directory.path(), "example-action", "example_action.wasm");
    std::fs::write(
        directory.path().join("20-events.toml"),
        format!(
            "name = \"events-b\"\nkind = \"source\"\ncomponent = \"example_source.wasm\"\nsha256 = \"{source_hash}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("10-events.toml"),
        "name = \"events-a\"\nkind = \"source\"\ncomponent = \"example_source.wasm\"\n\n[config]\npage_size = \"5\"\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("notify.toml"),
        "name = \"notify\"\nkind = \"action\"\ncomponent = \"example_action.wasm\"\nallowed_hosts = [\"hooks.example.com\"]\n\n[config]\nwebhook_url = \"https://hooks.example.com/hook\"\n",
    )
    .unwrap();
    // The host reads only `.toml` files of the directory itself.
    std::fs::write(directory.path().join("README.md"), "Not a manifest.").unwrap();
    std::fs::create_dir(directory.path().join("disabled")).unwrap();
    std::fs::write(
        directory.path().join("disabled/broken.toml"),
        "This file is not a manifest.",
    )
    .unwrap();

    let host = host();
    let plugins = host.load_dir(directory.path()).await.unwrap();

    let sources: Vec<String> = plugins
        .sources
        .iter()
        .map(|source| source.info().name)
        .collect();
    assert_eq!(sources, ["events-a", "events-b"]);
    assert_eq!(plugins.actions.len(), 1);
    assert_eq!(plugins.actions[0].info().name, "notify");
    assert_eq!(plugins.actions[0].supported_actions(), [ActionKind::Notify]);
    assert_eq!(
        format!("{plugins:?}"),
        "LoadedPlugins { sources: [\"events-a\", \"events-b\"], actions: [\"notify\"] }"
    );

    // Each plugin has the configuration of its own manifest.
    let range = aegis_contracts::TimeRange {
        start: common::time("2000-01-01T00:00:00Z"),
        end: common::time("2100-01-01T00:00:00Z"),
    };
    let page_a = plugins.sources[0].fetch(range, None).await.unwrap();
    let page_b = plugins.sources[1].fetch(range, None).await.unwrap();
    assert_eq!(page_a.events.len(), 5);
    assert_eq!(page_b.events.len(), 2);
    assert_eq!(page_a.events[0].source.connector, "events-a");
    assert_eq!(page_b.events[0].source.connector, "events-b");
}

#[tokio::test]
async fn the_example_manifests_load_the_example_plugins() {
    // An operator installs a plugin as the authoring guide says: the component file and
    // the manifest file go to the plugin directory.
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let directory = tempfile::tempdir().unwrap();
    install(directory.path(), "example-source", "example_source.wasm");
    install(directory.path(), "example-action", "example_action.wasm");
    for (example, manifest) in [
        ("example-source", "example-source.toml"),
        ("example-action", "example-action.toml"),
    ] {
        std::fs::copy(
            examples.join(example).join(manifest),
            directory.path().join(manifest),
        )
        .unwrap();
    }

    let plugins = host().load_dir(directory.path()).await.unwrap();

    assert_eq!(
        format!("{plugins:?}"),
        "LoadedPlugins { sources: [\"example-source\"], actions: [\"webhook-notify\"] }"
    );
    // The configuration of each example manifest is the configuration that its plugin
    // reads: the source accepts its page size, and the action finds its webhook URL.
    plugins.sources[0].check().await.unwrap();
    let mut request = ActionRequest::new(
        ActionKind::Notify,
        EntityRef::new(EntityKind::User, "bob@example.com"),
        "responder",
        "Test.",
    );
    request.dry_run = true;
    let outcome = plugins.actions[0].execute(&request).await.unwrap();
    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert_eq!(outcome.connector, "webhook-notify");
}

#[tokio::test]
async fn load_dir_fails_when_one_plugin_does_not_load() {
    let directory = tempfile::tempdir().unwrap();
    install(directory.path(), "example-source", "example_source.wasm");
    std::fs::write(
        directory.path().join("good.toml"),
        "name = \"good\"\nkind = \"source\"\ncomponent = \"example_source.wasm\"\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("tampered.toml"),
        format!(
            "name = \"tampered\"\nkind = \"source\"\ncomponent = \"example_source.wasm\"\nsha256 = \"{}\"\n",
            "0".repeat(64)
        ),
    )
    .unwrap();

    let error = host().load_dir(directory.path()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Integrity(message) if message.starts_with("plugin tampered: ")),
        "{error:?}"
    );
}

#[tokio::test]
async fn load_dir_refuses_two_manifests_with_the_same_kind_and_name() {
    let directory = tempfile::tempdir().unwrap();
    install(directory.path(), "example-source", "example_source.wasm");
    for file in ["a.toml", "b.toml"] {
        std::fs::write(
            directory.path().join(file),
            "name = \"events\"\nkind = \"source\"\ncomponent = \"example_source.wasm\"\n",
        )
        .unwrap();
    }

    let error = host().load_dir(directory.path()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(message)
            if message == "more than one source plugin manifest has the name events"),
        "{error:?}"
    );
}

#[tokio::test]
async fn load_dir_names_the_manifest_file_that_is_not_valid() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("broken.toml"), "name = \"x\"\n").unwrap();

    let error = host().load_dir(directory.path()).await.unwrap_err();

    assert!(
        matches!(&error, Error::Config(message)
            if message.contains("broken.toml") && message.contains("kind")),
        "{error:?}"
    );
}

#[tokio::test]
async fn load_dir_of_an_empty_directory_loads_nothing_and_a_missing_directory_is_not_found() {
    let directory = tempfile::tempdir().unwrap();
    let plugins = host().load_dir(directory.path()).await.unwrap();
    assert_eq!(plugins.sources.len(), 0);
    assert_eq!(plugins.actions.len(), 0);

    let missing = directory.path().join("missing");
    let error = host().load_dir(&missing).await.unwrap_err();
    assert!(
        matches!(&error, Error::NotFound(message) if message.contains("missing")),
        "{error:?}"
    );
}

#[test]
fn a_load_outside_a_tokio_runtime_is_an_error_and_not_a_panic() {
    let host = host();
    let manifest = common::manifest("events", PluginKind::Source, "example-source");

    let error = load_error(futures::executor::block_on(host.load_source(&manifest)));

    assert!(
        matches!(&error, Error::Config(message) if message.contains("Tokio runtime")),
        "{error:?}"
    );
}
