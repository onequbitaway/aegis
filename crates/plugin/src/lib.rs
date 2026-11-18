//! A WebAssembly plugin host for AEGIS connectors.
//!
//! People write connectors out of tree, in a language that compiles to a WebAssembly
//! component. This crate loads such a component at run time. The result is an ordinary
//! [`SourceConnector`](aegis_contracts::SourceConnector) or
//! [`ActionConnector`](aegis_contracts::ActionConnector) value.
//!
//! # How it works
//!
//! - The WIT package `aegis:plugin` in the `wit` directory defines the interface. A
//!   plugin implements the `source-connector` world or the `action-connector` world.
//! - The plugin and the host exchange the contract types as JSON text.
//! - A [`PluginManifest`] names the component file and gives the plugin its
//!   configuration and its permitted network destinations.
//! - A [`PluginHost`] compiles the component and makes the connector.
//!
//! ```no_run
//! use aegis_plugin::{HostLimits, PluginHost};
//!
//! # async fn example() -> aegis_contracts::Result<()> {
//! let host = PluginHost::new(HostLimits::default())?;
//! let plugins = host.load_dir("/etc/aegis/plugins").await?;
//! for source in &plugins.sources {
//!     source.check().await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # The sandbox
//!
//! A plugin is not trusted. The sandbox is deny by default:
//!
//! - **No ambient access.** A plugin has no filesystem, no environment variables, no
//!   arguments, no standard input, and no sockets. Its standard output goes nowhere. It
//!   can read the clock and get random numbers.
//! - **No other imports.** A component can import WASI and the `host` interface of the
//!   WIT package. A component that needs a different import does not load. A component
//!   that uses the WebAssembly GC proposal does not load.
//! - **Network through the host only.** The host sends each HTTP request for the plugin.
//!   The destination must be in `allowed_hosts` of the manifest, with an exact match of
//!   the host and the port. The scheme must be `https`, or `http` to a loopback address.
//!   The host does not follow a redirect. A request to a loopback address does not use a
//!   proxy. [`HostLimits`] limits the number of requests in one call and the size of a
//!   response.
//! - **Memory limits.** [`HostLimits::max_memory_bytes`] limits the memory of one call. A
//!   call that needs more fails with [`Error::BudgetExceeded`](aegis_contracts::Error).
//!   [`HostLimits::max_transfer_bytes`] limits the data that the host copies out of the
//!   plugin in one transfer. The host also limits the WASI resources of one call.
//! - **Time limit.** [`HostLimits::call_timeout`] limits the time of one call. A call
//!   that is not complete at the deadline fails with
//!   [`Error::Timeout`](aegis_contracts::Error). This includes a plugin that computes
//!   without end and a plugin that sleeps.
//! - **Faults stay inside.** A trap in a plugin is an error of that one call.
//! - **Output is not trusted.** JSON from a plugin that is not the contract type is
//!   [`Error::Serialization`](aegis_contracts::Error). The host sets the connector name
//!   in each event and in each action outcome, thus a plugin cannot speak for a
//!   different connector. An action outcome that contradicts `dry_run` is an error. The
//!   host cleans plugin text before it goes to a log or an error.
//! - **Integrity.** When the manifest has a `sha256` value, the host loads the component
//!   only if the hash matches. A mismatch is
//!   [`Error::Integrity`](aegis_contracts::Error).
//!   [`HostLimits::require_sha256`] makes the hash mandatory.
//!
//! # Concurrency
//!
//! The host makes a new instance for each call. Thus a connector is safe to share
//! between tasks, calls run at the same time, and a plugin keeps no state between calls.
//! A plugin keeps its position in the cursor. [`HostLimits::max_concurrent_calls`]
//! limits the calls that run in one plugin at the same time.
//!
//! Plugin code runs on the task of the caller. It gives control back to the async
//! runtime at least every 10 ms, thus a plugin that computes for a long time does not
//! block the runtime. The host compiles a component and decodes a large result on a
//! blocking thread. When the caller drops the future of a call, the plugin code stops.
//!
//! # Errors
//!
//! | Condition | Error |
//! | --- | --- |
//! | The manifest or a limit is not valid, or the file is not a correct component. | `Config` |
//! | The manifest file or the component file does not exist. | `NotFound` |
//! | The hash of the component is not the hash in the manifest. | `Integrity` |
//! | The plugin returns an error. | The variant with the same name. The case `other` is `Other`. |
//! | The plugin returns JSON that is not the contract type. | `Serialization` |
//! | The call is not complete at the deadline. | `Timeout` |
//! | The plugin needs more memory than the limit. | `BudgetExceeded` |
//! | The plugin traps, or the sandbox stops it for a different reason. | `Other` |
//! | The action type is not in the list that the plugin declared. | `Unsupported` |

mod action;
mod bindings;
mod host;
mod http;
mod limits;
mod manifest;
mod sandbox;
mod source;
mod text;

pub use host::{LoadedPlugins, PluginHost};
pub use limits::HostLimits;
pub use manifest::{PluginKind, PluginManifest};
