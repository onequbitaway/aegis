//! The plugin host: it loads components and gives them to AEGIS as connectors.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use aegis_contracts::action::ActionConnector;
use aegis_contracts::source::SourceConnector;
use aegis_contracts::{Error, Result};
use sha2::{Digest, Sha256};
use wasmtime::Engine;
use wasmtime::component::{Component, Linker};

use crate::action::PluginAction;
use crate::bindings::{ActionConnectorPre, SourceConnectorPre};
use crate::http::{HttpClients, HttpPolicy};
use crate::limits::HostLimits;
use crate::manifest::{PluginKind, PluginManifest, read_error};
use crate::sandbox::{self, HostState, PluginContext, Sandbox};
use crate::source::PluginSource;
use crate::text::clean;

/// The compiled components of one host. The key is the SHA-256 of the component file.
type ComponentCache = Arc<Mutex<HashMap<String, Component>>>;
/// A component with its imports connected to the sandbox.
type InstancePre = wasmtime::component::InstancePre<HostState>;

/// Loads connector plugins and runs them in a sandbox.
///
/// A plugin is a WebAssembly component with a manifest. The host compiles the component
/// one time. Then each call into the plugin runs in a new instance with the limits of the
/// host. Refer to the crate documentation for the sandbox rules.
///
/// Make one host for a process and load all plugins with it. The methods that load a
/// plugin and all connector methods must run in a Tokio runtime.
pub struct PluginHost {
    engine: Engine,
    linker: Linker<HostState>,
    clients: HttpClients,
    limits: HostLimits,
    components: ComponentCache,
}

/// The connectors that [`PluginHost::load_dir`] loaded.
#[derive(Default)]
pub struct LoadedPlugins {
    /// The source connectors, in the order of the manifest file names.
    pub sources: Vec<Arc<dyn SourceConnector>>,
    /// The action connectors, in the order of the manifest file names.
    pub actions: Vec<Arc<dyn ActionConnector>>,
}

impl fmt::Debug for LoadedPlugins {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sources: Vec<String> = self
            .sources
            .iter()
            .map(|source| source.info().name)
            .collect();
        let actions: Vec<String> = self
            .actions
            .iter()
            .map(|action| action.info().name)
            .collect();
        formatter
            .debug_struct("LoadedPlugins")
            .field("sources", &sources)
            .field("actions", &actions)
            .finish()
    }
}

impl fmt::Debug for PluginHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginHost")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl PluginHost {
    /// Makes a host that applies `limits` to each plugin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a limit is zero, and [`Error::Other`] if the
    /// WebAssembly engine or the HTTP client does not start.
    pub fn new(limits: HostLimits) -> Result<Self> {
        limits.validate()?;
        let engine = sandbox::engine()?;
        let linker = sandbox::linker(&engine)?;
        let clients = HttpClients::new(&limits)
            .map_err(|error| Error::other("make the HTTP clients of the plugin host", error))?;
        Ok(Self {
            engine,
            linker,
            clients,
            limits,
            components: ComponentCache::default(),
        })
    }

    /// Returns the limits of this host.
    #[must_use]
    pub fn limits(&self) -> &HostLimits {
        &self.limits
    }

    /// Loads a source connector plugin.
    ///
    /// The host checks the manifest and the hash, compiles the component, and calls
    /// `info` of the plugin one time. The name of the connector is the name in the
    /// manifest.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`]: the manifest is not valid, the kind is not `source`, or the
    ///   file is not a component that implements the `source-connector` world.
    /// - [`Error::NotFound`]: the component file does not exist.
    /// - [`Error::Integrity`]: the hash of the file is not the hash in the manifest, or
    ///   the host requires a hash and the manifest has none.
    /// - [`Error::Serialization`]: `info` did not return the JSON form of `ConnectorInfo`.
    /// - The sandbox errors of a call, if `info` fails.
    pub async fn load_source(&self, manifest: &PluginManifest) -> Result<Arc<dyn SourceConnector>> {
        let (component, sandbox) = self.prepare(manifest, PluginKind::Source).await?;
        let component = self.link(manifest, &component)?;
        let component =
            SourceConnectorPre::new(component).map_err(|error| wrong_world(manifest, &error))?;
        let source = PluginSource::load(sandbox, component, manifest.poll_interval).await?;
        Ok(Arc::new(source))
    }

    /// Loads an action connector plugin.
    ///
    /// The host checks the manifest and the hash, compiles the component, and calls
    /// `info` and `supported-actions` of the plugin one time. The name of the connector
    /// is the name in the manifest.
    ///
    /// # Errors
    ///
    /// The errors are the same as for [`load_source`](Self::load_source), with the kind
    /// `action` and the `action-connector` world.
    pub async fn load_action(&self, manifest: &PluginManifest) -> Result<Arc<dyn ActionConnector>> {
        let (component, sandbox) = self.prepare(manifest, PluginKind::Action).await?;
        let component = self.link(manifest, &component)?;
        let component =
            ActionConnectorPre::new(component).map_err(|error| wrong_world(manifest, &error))?;
        let action = PluginAction::load(sandbox, component).await?;
        Ok(Arc::new(action))
    }

    /// Loads each plugin that has a manifest in `directory`.
    ///
    /// A manifest is a file with the extension `.toml`. The host does not look in
    /// subdirectories. The host loads the manifests in the order of their file names.
    ///
    /// # Errors
    ///
    /// The first plugin that does not load stops the operation, and its error is the
    /// result. Thus a plugin that fails an integrity check cannot go unnoticed. Two
    /// manifests of the same kind with the same name are [`Error::Config`].
    pub async fn load_dir(&self, directory: impl AsRef<Path>) -> Result<LoadedPlugins> {
        let directory = directory.as_ref().to_owned();
        let manifests = blocking(move || read_manifests(&directory)).await?;
        let mut plugins = LoadedPlugins::default();
        let mut names = BTreeSet::new();
        for manifest in &manifests {
            if !names.insert((manifest.kind.to_string(), manifest.name.clone())) {
                return Err(Error::Config(format!(
                    "more than one {} plugin manifest has the name {}",
                    manifest.kind, manifest.name
                )));
            }
            match manifest.kind {
                PluginKind::Source => plugins.sources.push(self.load_source(manifest).await?),
                PluginKind::Action => plugins.actions.push(self.load_action(manifest).await?),
            }
        }
        Ok(plugins)
    }

    /// Connects the imports of the component to the functions that the sandbox gives.
    ///
    /// A component that needs a different import does not load. Thus a plugin cannot get
    /// a capability that this crate does not define.
    fn link(&self, manifest: &PluginManifest, component: &Component) -> Result<InstancePre> {
        self.linker.instantiate_pre(component).map_err(|error| {
            Error::Config(format!(
                "plugin {}: the component needs an import that the sandbox does not give: {}",
                manifest.name,
                clean(&format!("{error:#}"))
            ))
        })
    }

    /// Checks the manifest, loads the component, and makes the sandbox of the plugin.
    async fn prepare(
        &self,
        manifest: &PluginManifest,
        kind: PluginKind,
    ) -> Result<(Component, Sandbox)> {
        manifest.validate()?;
        let name = manifest.name.clone();
        if manifest.kind != kind {
            return Err(Error::Config(format!(
                "plugin {name} has the kind `{}`, but this function loads the kind `{kind}`",
                manifest.kind
            )));
        }
        // Fail closed: with `require_sha256`, a component that nobody pinned does not load.
        if manifest.sha256.is_none() && self.limits.require_sha256 {
            return Err(Error::Integrity(format!(
                "plugin {name}: the manifest has no sha256 value and this host requires one"
            )));
        }
        let policy = HttpPolicy::parse(&manifest.allowed_hosts)
            .map_err(|reason| Error::Config(format!("plugin {name}: {reason}")))?;

        let engine = self.engine.clone();
        let cache = Arc::clone(&self.components);
        let path = manifest.component.clone();
        let expected = manifest.sha256.clone();
        let max_bytes = self.limits.max_component_bytes;
        let plugin = name.clone();
        let component = blocking(move || {
            load_component(
                &engine,
                &cache,
                &plugin,
                &path,
                expected.as_deref(),
                max_bytes,
            )
        })
        .await?;

        let context = PluginContext {
            name,
            config: manifest.config.clone(),
        };
        let sandbox = Sandbox::new(
            self.engine.clone(),
            context,
            policy,
            self.clients.clone(),
            self.limits.clone(),
        );
        Ok((component, sandbox))
    }
}

/// Reads the component file, checks its size and its hash, and compiles it.
///
/// The function hashes the same bytes that it compiles. Thus a change of the file after
/// the check has no effect.
fn load_component(
    engine: &Engine,
    cache: &ComponentCache,
    plugin: &str,
    path: &Path,
    expected_sha256: Option<&str>,
    max_bytes: u64,
) -> Result<Component> {
    let file = File::open(path).map_err(|error| read_error(path, error))?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| read_error(path, error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > max_bytes) {
        return Err(Error::Config(format!(
            "plugin {plugin}: the component file is larger than the limit of {max_bytes} bytes"
        )));
    }

    let sha256 = hex::encode(Sha256::digest(&bytes));
    if let Some(expected) = expected_sha256
        && !expected.eq_ignore_ascii_case(&sha256)
    {
        return Err(Error::Integrity(format!(
            "plugin {plugin}: the SHA-256 of the component file is {sha256}, but the manifest expects {}",
            expected.to_ascii_lowercase()
        )));
    }

    let cached = lock(cache).get(&sha256).cloned();
    if let Some(component) = cached {
        return Ok(component);
    }
    let component = Component::from_binary(engine, &bytes).map_err(|error| {
        Error::Config(format!(
            "plugin {plugin}: the file {} is not a valid WebAssembly component: {}",
            path.display(),
            clean(&format!("{error:#}"))
        ))
    })?;
    lock(cache).insert(sha256, component.clone());
    Ok(component)
}

/// Reads all manifest files of a plugin directory, in the order of their names.
fn read_manifests(directory: &Path) -> Result<Vec<PluginManifest>> {
    let entries = std::fs::read_dir(directory).map_err(|error| read_error(directory, error))?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry.map_err(|error| read_error(directory, error))?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "toml")
            && path.is_file()
        {
            paths.push(path);
        }
    }
    paths.sort();
    paths.iter().map(PluginManifest::from_file).collect()
}

/// Runs file and compiler work on the blocking threads of the Tokio runtime.
async fn blocking<T, F>(task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        Error::Config("the plugin host must load plugins in a Tokio runtime".to_owned())
    })?;
    runtime
        .spawn_blocking(task)
        .await
        .map_err(|error| Error::other("run a blocking task of the plugin host", error))?
}

fn wrong_world(manifest: &PluginManifest, error: &wasmtime::Error) -> Error {
    Error::Config(format!(
        "plugin {}: the component does not implement the {}-connector world of aegis:plugin: {}",
        manifest.name,
        manifest.kind,
        clean(&format!("{error:#}"))
    ))
}

/// Locks the cache. A panic in a different thread does not make the cache unavailable.
fn lock(cache: &ComponentCache) -> std::sync::MutexGuard<'_, HashMap<String, Component>> {
    cache.lock().unwrap_or_else(PoisonError::into_inner)
}
