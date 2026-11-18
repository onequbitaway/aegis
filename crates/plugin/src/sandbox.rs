//! The sandbox that runs plugin code.
//!
//! The sandbox is deny by default. A plugin gets the WASI interfaces that a component
//! needs to start, but with an empty context: no directories, no environment variables, no
//! arguments, no standard input, and no sockets. The only path to the outside is the
//! `host` interface of the WIT package, which this module implements.
//!
//! Each call into a plugin runs in a new instance with its own memory. Thus a fault in
//! one call cannot change a later call, and calls can run at the same time.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::source::ConnectorInfo;
use aegis_contracts::{Error, Result};
use futures::future::BoxFuture;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use wasmtime::component::{HasSelf, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::bindings::GuestError;
use crate::bindings::host::{self, LogLevel, Request, Response};
use crate::http::{HttpClients, HttpError, HttpGate, HttpPolicy};
use crate::limits::HostLimits;
use crate::text::clean;

/// The time between two deadline checks.
///
/// A plugin that computes without pause gives control back to the async runtime after
/// each tick.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// The largest number of core instances in one plugin instance.
const MAX_INSTANCES: usize = 64;
/// The largest number of linear memories in one plugin instance.
const MAX_MEMORIES: usize = 16;
/// The largest number of tables in one plugin instance.
const MAX_TABLES: usize = 64;
/// The largest number of elements in one table.
const MAX_TABLE_ELEMENTS: usize = 100_000;
/// The largest number of host resources that one plugin instance can hold.
///
/// A host resource is, for example, a WASI stream or a WASI timer. Each one uses memory
/// of the host, which the memory limit of the plugin does not count.
const MAX_HOST_RESOURCES: usize = 1024;
/// The largest plugin result that the host decodes on the task of the caller, in bytes.
const INLINE_DECODE_BYTES: usize = 64 * 1024;
/// The largest number of random bytes that a plugin can get in one WASI call.
///
/// The host allocates these bytes outside the memory of the plugin.
const MAX_RANDOM_BYTES: u64 = 1024 * 1024;

/// Makes the engine that compiles and runs all plugins of one host.
///
/// The function also starts the thread that moves the deadline clock of the engine. The
/// thread stops when the last copy of the engine is gone.
pub(crate) fn engine() -> Result<Engine> {
    let mut config = Config::new();
    config.epoch_interruption(true);
    // This crate builds the engine without its `gc` feature. In such a build of engine
    // version 48.0.8, a module that declares a function subtype can make the engine
    // abort the process (advisory GHSA-rc4p-x33f-vpr2). Without the GC proposal, the
    // engine refuses such a module when it loads. Connector plugins do not need the
    // proposal.
    config.wasm_gc(false);
    let engine =
        Engine::new(&config).map_err(|error| Error::other("make the plugin engine", error))?;

    let weak = engine.weak();
    std::thread::Builder::new()
        .name("aegis-plugin-clock".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(EPOCH_TICK);
                match weak.upgrade() {
                    Some(engine) => engine.increment_epoch(),
                    None => break,
                }
            }
        })
        .map_err(|error| Error::other("start the plugin clock thread", error))?;
    Ok(engine)
}

/// Makes the linker that gives a plugin its imports: empty WASI and the `host` interface.
pub(crate) fn linker(engine: &Engine) -> Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)
        .and_then(|()| {
            host::add_to_linker::<HostState, HasSelf<HostState>>(&mut linker, |state| state)
        })
        .map_err(|error| Error::other("make the plugin linker", error))?;
    Ok(linker)
}

/// The data of one plugin that all its calls share.
pub(crate) struct PluginContext {
    /// The name from the manifest.
    pub(crate) name: String,
    /// The `[config]` table from the manifest.
    pub(crate) config: BTreeMap<String, String>,
}

/// The data of one plugin instance. The store of the instance owns it.
pub(crate) struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
    limiter: MemoryLimiter,
    plugin: Arc<PluginContext>,
    http: HttpGate,
    /// The largest number of log messages that the host writes for this call.
    log_limit: u32,
    /// The number of log messages that the host can still write for this call.
    log_budget: u32,
    /// `true` after the host wrote that the plugin used all its log messages.
    log_limit_logged: bool,
    /// `true` after the host wrote that the plugin used all its HTTP requests.
    http_limit_logged: bool,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl host::Host for HostState {
    fn config_get(&mut self, key: String) -> Option<String> {
        self.plugin.config.get(&key).cloned()
    }

    fn log(&mut self, level: LogLevel, message: String) {
        let plugin = self.plugin.name.as_str();
        // A plugin cannot fill the log: the host drops the messages after the budget. It
        // tells the operator one time. With a limit of zero, the operator wants no line.
        let Some(budget) = self.log_budget.checked_sub(1) else {
            if self.log_limit > 0 && !std::mem::replace(&mut self.log_limit_logged, true) {
                tracing::warn!(
                    plugin,
                    "The plugin wrote more than {} log messages in one call. The host drops the remainder.",
                    self.log_limit
                );
            }
            return;
        };
        self.log_budget = budget;
        let message = clean(&message);
        match level {
            LogLevel::Trace => tracing::trace!(plugin, "{message}"),
            LogLevel::Debug => tracing::debug!(plugin, "{message}"),
            LogLevel::Info => tracing::info!(plugin, "{message}"),
            LogLevel::Warn => tracing::warn!(plugin, "{message}"),
            LogLevel::Error => tracing::error!(plugin, "{message}"),
        }
    }

    async fn http_request(&mut self, request: Request) -> Result<Response, GuestError> {
        self.http.send(request).await.map_err(|error| {
            // The gate limits the requests of one call, thus it also limits these log
            // lines. The refusal after the limit can repeat without end. The host writes
            // it one time.
            let repeated = matches!(error, HttpError::TooManyRequests(_))
                && std::mem::replace(&mut self.http_limit_logged, true);
            // The error can name a host or a header of the request. The plugin controls
            // their length.
            let message = clean(&error.to_string());
            if !repeated {
                tracing::warn!(
                    plugin = self.plugin.name.as_str(),
                    "The host did not complete an HTTP request of the plugin: {message}."
                );
            }
            match error {
                HttpError::InvalidUrl
                | HttpError::Credentials
                | HttpError::Method(_)
                | HttpError::ForbiddenHeader(_)
                | HttpError::InvalidHeader(_) => GuestError::InvalidInput(message),
                HttpError::Scheme(_) | HttpError::PlainHttp(_) | HttpError::NotAllowed(_) => {
                    GuestError::Unauthorized(message)
                }
                HttpError::Timeout(_) => GuestError::Timeout(message),
                HttpError::Transport(_) => GuestError::Unavailable(message),
                HttpError::TooManyRequests(_) | HttpError::ResponseTooLarge(_) => {
                    GuestError::Other(message)
                }
            }
        })
    }
}

/// Limits the memory and the tables of one plugin instance.
struct MemoryLimiter {
    max_bytes: usize,
    /// The total size of all linear memories of the instance.
    used_bytes: usize,
    /// `true` after the limiter refused a request for more memory.
    exceeded: bool,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let total = self
            .used_bytes
            .checked_add(desired.saturating_sub(current))
            .filter(|total| *total <= self.max_bytes);
        match total {
            Some(total) => {
                self.used_bytes = total;
                Ok(true)
            }
            None => {
                self.exceeded = true;
                Ok(false)
            }
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }

    fn instances(&self) -> usize {
        MAX_INSTANCES
    }

    fn tables(&self) -> usize {
        MAX_TABLES
    }

    fn memories(&self) -> usize {
        MAX_MEMORIES
    }
}

/// Runs the calls of one plugin, each in a new instance with the limits of the host.
pub(crate) struct Sandbox {
    engine: Engine,
    plugin: Arc<PluginContext>,
    policy: Arc<HttpPolicy>,
    clients: HttpClients,
    limits: HostLimits,
    slots: Semaphore,
}

impl Sandbox {
    /// Makes the sandbox of one plugin.
    pub(crate) fn new(
        engine: Engine,
        plugin: PluginContext,
        policy: HttpPolicy,
        clients: HttpClients,
        limits: HostLimits,
    ) -> Self {
        Self {
            engine,
            plugin: Arc::new(plugin),
            policy: Arc::new(policy),
            clients,
            slots: Semaphore::new(limits.max_concurrent_calls),
            limits,
        }
    }

    /// Returns the name of the plugin.
    pub(crate) fn name(&self) -> &str {
        &self.plugin.name
    }

    /// Runs one call in a new store and applies the time limit and the memory limit.
    ///
    /// `call` makes the instance and calls one export. The time limit includes the wait
    /// for a free call position. When the caller drops the returned future, the plugin
    /// code stops.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the call is not complete at the deadline,
    /// [`Error::BudgetExceeded`] if the plugin needs more memory than the limit, and
    /// [`Error::Other`] for a trap or a different sandbox failure.
    pub(crate) async fn call<T, F>(&self, operation: &'static str, call: F) -> Result<T>
    where
        F: for<'a> FnOnce(&'a mut Store<HostState>) -> BoxFuture<'a, wasmtime::Result<T>>,
    {
        let name = self.name();
        // The timers below need a Tokio runtime. Without one they panic.
        tokio::runtime::Handle::try_current().map_err(|_| {
            Error::Config(format!(
                "plugin {name}: a call to `{operation}` must run in a Tokio runtime"
            ))
        })?;
        let timeout = self.limits.call_timeout;
        let deadline = Instant::now() + timeout;
        let timed_out = || {
            Error::Timeout(format!(
                "plugin {name}: `{operation}` did not complete in {timeout:?}"
            ))
        };

        let _slot = tokio::time::timeout_at(deadline, self.slots.acquire())
            .await
            .map_err(|_| {
                Error::Timeout(format!(
                    "plugin {name}: `{operation}` did not start in {timeout:?}, because {} other calls are in progress",
                    self.limits.max_concurrent_calls
                ))
            })?
            .map_err(|error| Error::other(format!("plugin {name}: get a call position"), error))?;

        let mut store = self.store();
        let result = tokio::time::timeout_at(deadline, call(&mut store)).await;
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                // The full error has a stack trace with names from the plugin file. It
                // goes to the debug log only, and the host cleans it first.
                tracing::debug!(
                    plugin = name,
                    operation,
                    "The sandbox stopped a plugin call: {}",
                    clean(&format!("{error:#}"))
                );
                if store.data().limiter.exceeded {
                    Err(Error::BudgetExceeded(format!(
                        "plugin {name}: `{operation}` needs more memory than the limit of {} bytes",
                        self.limits.max_memory_bytes
                    )))
                } else {
                    Err(Error::other(
                        format!("plugin {name}: `{operation}` failed in the sandbox"),
                        failure(&error),
                    ))
                }
            }
            Err(_) => Err(timed_out()),
        }
    }

    /// Makes the store of one call, with an empty WASI context and the resource limits.
    fn store(&self) -> Store<HostState> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .max_random_size(MAX_RANDOM_BYTES);
        let mut table = ResourceTable::new();
        table.set_max_capacity(MAX_HOST_RESOURCES);
        let state = HostState {
            wasi: wasi.build(),
            table,
            limiter: MemoryLimiter {
                max_bytes: self.limits.max_memory_bytes,
                used_bytes: 0,
                exceeded: false,
            },
            plugin: Arc::clone(&self.plugin),
            http: HttpGate::new(self.clients.clone(), Arc::clone(&self.policy), &self.limits),
            log_limit: self.limits.max_log_messages_per_call,
            log_budget: self.limits.max_log_messages_per_call,
            log_limit_logged: false,
            http_limit_logged: false,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limiter);
        // The memory limit counts only the memory of the plugin. This limit bounds the
        // memory that the host allocates when it copies data out of the plugin.
        store.set_hostcall_fuel(self.limits.max_transfer_bytes);
        // The plugin code gives control back to the async runtime at each tick. Then the
        // timeout in `call` can stop a plugin that computes without end.
        store.set_epoch_deadline(1);
        store.epoch_deadline_async_yield_and_update(1);
        store
    }

    /// Maps an error that a plugin returned to the contract error of the same kind.
    ///
    /// The message of a plugin is not trusted. The host cleans it and adds the plugin
    /// name.
    pub(crate) fn guest_error(&self, error: GuestError) -> Error {
        let name = self.name();
        let text = |message: String| format!("plugin {name}: {}", clean(&message));
        match error {
            GuestError::InvalidInput(message) => Error::InvalidInput(text(message)),
            GuestError::NotFound(message) => Error::NotFound(text(message)),
            GuestError::Unauthorized(message) => Error::Unauthorized(text(message)),
            GuestError::Unsupported(message) => Error::Unsupported(text(message)),
            GuestError::Unavailable(message) => Error::Unavailable(text(message)),
            GuestError::RateLimited(message) => Error::RateLimited(text(message)),
            GuestError::Timeout(message) => Error::Timeout(text(message)),
            GuestError::Other(message) => Error::other(format!("plugin {name}"), clean(&message)),
        }
    }

    /// Decodes the result of `info` and makes the host the authority for the identity.
    ///
    /// The operator names the connector instance, thus the name is the name of the
    /// manifest. The other values are short labels. The host cleans them and limits
    /// their length, because each `info` call of the connector copies them.
    pub(crate) async fn connector_info(&self, text: String) -> Result<ConnectorInfo> {
        let info: ConnectorInfo = self.decode("info", "ConnectorInfo", text).await?;
        Ok(ConnectorInfo {
            name: self.name().to_owned(),
            vendor: clean(&info.vendor),
            product: clean(&info.product),
            version: clean(&info.version),
        })
    }

    /// Decodes JSON text from a plugin to a contract type.
    ///
    /// The decoder is CPU work whose time increases with the size of the text. For a
    /// large text, the work runs on a blocking thread and not on the async runtime.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] with the plugin name if the text is not the JSON
    /// form of `T`.
    pub(crate) async fn decode<T>(&self, operation: &str, expected: &str, text: String) -> Result<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let name = self.name();
        let decoded = if text.len() <= INLINE_DECODE_BYTES {
            serde_json::from_str(&text)
        } else {
            tokio::task::spawn_blocking(move || serde_json::from_str(&text))
                .await
                .map_err(|error| {
                    Error::other(
                        format!("plugin {name}: decode the result of `{operation}`"),
                        error,
                    )
                })?
        };
        decoded.map_err(|error| {
            Error::Serialization(format!(
                "plugin {name}: `{operation}` did not return the JSON form of {expected}: {}",
                clean(&error.to_string())
            ))
        })
    }
}

/// Describes why the sandbox stopped a call, in text that the plugin does not control.
///
/// The cause at the root of an engine error is text of the engine, for example the type
/// of a trap. The levels above it can hold function names from the plugin file.
fn failure(error: &wasmtime::Error) -> String {
    clean(&error.root_cause().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 64 * 1024;

    fn limiter(max_bytes: usize) -> MemoryLimiter {
        MemoryLimiter {
            max_bytes,
            used_bytes: 0,
            exceeded: false,
        }
    }

    #[test]
    fn the_limiter_permits_growth_up_to_the_limit() {
        let mut limiter = limiter(4 * PAGE);
        assert!(limiter.memory_growing(0, 2 * PAGE, None).unwrap());
        assert!(limiter.memory_growing(2 * PAGE, 4 * PAGE, None).unwrap());
        assert_eq!(limiter.used_bytes, 4 * PAGE);
        assert!(!limiter.exceeded);
    }

    #[test]
    fn the_limiter_refuses_growth_past_the_limit_and_records_it() {
        let mut limiter = limiter(4 * PAGE);
        assert!(limiter.memory_growing(0, 4 * PAGE, None).unwrap());
        assert!(!limiter.memory_growing(4 * PAGE, 5 * PAGE, None).unwrap());
        assert!(limiter.exceeded);
        assert_eq!(limiter.used_bytes, 4 * PAGE);
    }

    #[test]
    fn the_limiter_counts_all_memories_of_the_instance_together() {
        let mut limiter = limiter(4 * PAGE);
        assert!(limiter.memory_growing(0, 3 * PAGE, None).unwrap());
        // A second memory starts at zero. It cannot use a new budget.
        assert!(!limiter.memory_growing(0, 2 * PAGE, None).unwrap());
        assert!(limiter.exceeded);
        assert!(limiter.memory_growing(0, PAGE, None).unwrap());
    }

    #[test]
    fn the_limiter_refuses_a_request_that_overflows() {
        let mut limiter = limiter(usize::MAX);
        assert!(limiter.memory_growing(0, PAGE, None).unwrap());
        assert!(!limiter.memory_growing(0, usize::MAX, None).unwrap());
        assert!(limiter.exceeded);
    }

    #[test]
    fn the_limiter_limits_the_elements_of_a_table() {
        let mut limiter = limiter(PAGE);
        assert!(limiter.table_growing(0, 100_000, None).unwrap());
        assert!(!limiter.table_growing(0, 100_001, None).unwrap());
        assert!(!limiter.table_growing(99_999, usize::MAX, None).unwrap());
    }
}
