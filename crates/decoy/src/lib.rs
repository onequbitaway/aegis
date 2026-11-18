//! Decoy network services for AEGIS.
//!
//! A decoy is a service that the operator runs on an address of its own. No legitimate
//! client uses the address, so each contact is a signal. The decoy wastes the time and the
//! model tokens of an automated attacker, and it records what the client does.
//!
//! This crate is defensive only. A decoy only answers a client that connects to it. It
//! slows and misleads this client. It never damages the client: it sends no compressed
//! data, no malformed message, and no content made to crash a client. It never connects
//! to a different system.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`DecoyService`] | The service. It implements [`SourceConnector`](aegis_contracts::SourceConnector). |
//! | [`BoundDecoy`] | A service with a bound listener. [`BoundDecoy::serve`] runs it. |
//! | [`DecoyConfig`] | The serde configuration. An unknown key is an error. |
//! | [`PersonaKind`] | The personas: `tarpit`, `maze`, and `model_api`. |
//! | [`DecoyStats`] | A snapshot of the counters of a service. |
//! | [`client_fingerprint`] | The heuristic fingerprint of a client. |
//! | [`CANARY_INSTRUCTION_PREFIX`] | The fixed text of the canary instruction. |
//! | [`action`], [`attr`], [`result`] | The event names that only the decoy uses. |
//!
//! # Personas
//!
//! - **Tarpit.** Each request gets a valid page that arrives a few bytes at a time.
//! - **Maze.** An endless set of generated pages and an endless JSON API. The content
//!   comes from the path and a secret seed. It holds no real data.
//! - **Model API.** An OpenAI-compatible API that accepts only planted decoy keys. It
//!   records the prompt and streams a slow filler answer. It never calls a real model.
//!
//! An answer can carry one canary instruction for automated agents. The instruction asks
//! only for a fetch of one URL on this decoy.
//!
//! # Limits
//!
//! The decoy has hard limits, so nobody can use it against the operator:
//!
//! - The number of connections, for all clients and for one client address.
//! - The size of a request, and the time in which a client must send it.
//! - The time of one write, the time of one connection, and the bytes that the decoy sends.
//! - The count and the size of the event queue.
//!
//! Refer to [`LimitsConfig`] and [`EventsConfig`].
//!
//! # Events
//!
//! The service emits `decoy.contact`, `decoy.canary_hit`, and `honeytoken.trip` events.
//! Text from a client is untrusted data. The decoy limits it, removes control characters,
//! and puts it below [`UNTRUSTED_CLIENT_DATA`] in [`Event::raw`](aegis_contracts::Event).
//!
//! # Example
//!
//! This example runs a maze, sends one request to it, and reads the contact event.
//!
//! ```
//! use aegis_contracts::SourceConnector;
//! use aegis_decoy::{DecoyConfig, DecoyService, PersonaKind};
//! use futures::StreamExt;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio_util::sync::CancellationToken;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut config = DecoyConfig::new(
//!     "decoy-lab",
//!     "127.0.0.1:0".parse()?,
//!     [PersonaKind::Maze],
//!     "AEGIS_DECOY_SEED",
//! );
//! config.maze.delay = std::time::Duration::ZERO;
//! let bound = DecoyService::bind_with_env(config, |name| {
//!     (name == "AEGIS_DECOY_SEED").then(|| "0123456789abcdef0123456789abcdef".to_owned())
//! })
//! .await?;
//! let address = bound.local_addr();
//! let service = bound.service();
//! let cancel = CancellationToken::new();
//! let server = tokio::spawn(bound.serve(cancel.clone()));
//!
//! let mut client = tokio::net::TcpStream::connect(address).await?;
//! client.write_all(b"GET /docs HTTP/1.1\r\nHost: decoy\r\n\r\n").await?;
//! let mut answer = String::new();
//! client.read_to_string(&mut answer).await?;
//! assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
//!
//! let mut events = service.stream(None).await?;
//! let batch = events.next().await.ok_or("the stream ended")??;
//! assert_eq!(batch.events[0].action, "decoy.contact");
//! assert_eq!(batch.events[0].attribute_str("decoy_kind"), Some("maze"));
//!
//! cancel.cancel();
//! server.await?;
//! # Ok(())
//! # }
//! ```

mod canary;
mod config;
mod connection;
mod events;
mod fingerprint;
mod gate;
mod http;
mod names;
mod persona;
mod seed;
mod service;
mod text;

pub use canary::CANARY_INSTRUCTION_PREFIX;
pub use config::{
    CanaryConfig, DecoyConfig, DecoyKeyConfig, EventsConfig, LimitsConfig, MODEL_API_ROOT,
    MazeConfig, ModelApiConfig, PersonaKind, TarpitConfig,
};
pub use fingerprint::client_fingerprint;
pub use names::{LISTENER_KIND, UNTRUSTED_CLIENT_DATA, action, attr, result};
pub use service::{BoundDecoy, DecoyService, DecoyStats};

/// Compiles the examples in `README.md` as documentation tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;
