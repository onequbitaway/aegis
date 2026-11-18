//! The decoy service of the application.
//!
//! The `[decoy]` section starts one [`DecoyService`] of `aegis-decoy` as a part of
//! [`App::run_with`](crate::App::run_with), if the module `ingest` is in the module set.
//! The module is in the crate only with the Cargo feature `decoy`.
//!
//! A decoy is a network service on an address of the operator that no legitimate client
//! uses. It only answers a client that connects to it. It slows and misleads that client,
//! and it records what the client does. It does not damage the client, and it opens no
//! connection.
//!
//! # The connections
//!
//! - **Events.** The decoy is a source connector. One ingestion runner publishes its
//!   events on `aegis.events.{id}`, so the detection engine examines each contact.
//! - **Honeytokens.** Each decoy key of the model API is a honeytoken in the registry of
//!   the application, with the identifier of the key. Thus the honeytoken detector makes a
//!   detection when a client uses a decoy key. The registry never gets the key.
//! - **Shutdown.** The decoy stops with the service. It closes each connection, records
//!   each of these contacts, and ends its event stream. The runner publishes the events
//!   that remain and then completes.
//!
//! # Fail closed
//!
//! - The seed and each decoy key come from environment variables. A variable that is not
//!   set stops the start. The decoy has no default seed.
//! - The decoy address must not be the address of the operator API. The settings refuse
//!   such a configuration.
//! - A local session, for example `aegis monitor`, never starts the decoy.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::{Error, Result};
use aegis_decoy::{BoundDecoy, DecoyConfig, DecoyService, PersonaKind};
use aegis_respond::{HoneytokenKind, HoneytokenRegistry, HoneytokenRequest};
use serde_json::json;

use crate::app::APP_ACTOR;

/// A function that returns the value of an environment variable.
pub(crate) type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Returns the function that reads the environment of the process.
pub(crate) fn process_env() -> EnvLookup {
    Arc::new(|name| std::env::var(name).ok())
}

/// Returns the placement of the honeytoken for one decoy key.
///
/// The placement names the decoy and the key. It is not an entity of the environment of
/// the operator, so no event has it as its actor or as its target.
#[must_use]
pub fn key_placement(decoy_id: &str, key_id: &str) -> EntityRef {
    EntityRef::new(
        EntityKind::Other,
        format!("decoy:{decoy_id}:model-api-key:{key_id}"),
    )
    .with_name(format!("Decoy model API key {key_id}"))
}

/// Makes one honeytoken for each decoy key of the model API.
///
/// The honeytoken has the identifier of the key. The decoy emits a `honeytoken.trip`
/// event with this identifier, and the honeytoken detector then makes a detection. The
/// registry gets no key: a honeytoken of the registry has a random value of its own.
///
/// # Errors
///
/// Returns [`Error::Config`] if the registry refuses a key, for example because two
/// honeytokens would have one identifier.
pub(crate) async fn register_keys(
    registry: &HoneytokenRegistry,
    config: &DecoyConfig,
) -> Result<usize> {
    if !config.has_persona(PersonaKind::ModelApi) {
        return Ok(0);
    }
    for key in &config.model_api.keys {
        let request = HoneytokenRequest::new(
            HoneytokenKind::Credential,
            key_placement(&config.id, &key.id),
            format!(
                "The decoy key {} of the model API of the decoy {}. A client that uses it \
                 found the place where the operator planted the key.",
                key.id, config.id
            ),
        )
        .with_id(key.id.clone())
        .issued_by(APP_ACTOR);
        registry.issue(request).await.map_err(|error| {
            Error::Config(format!(
                "the decoy key {} cannot be a honeytoken: {error}",
                key.id
            ))
        })?;
    }
    Ok(config.model_api.keys.len())
}

/// The decoy of one application: the secrets, and the service while it runs.
pub(crate) struct DecoyRuntime {
    env: EnvLookup,
    running: Mutex<Option<Running>>,
}

struct Running {
    service: DecoyService,
    address: SocketAddr,
}

impl DecoyRuntime {
    pub(crate) fn new(env: EnvLookup) -> Self {
        Self {
            env,
            running: Mutex::new(None),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks the configuration with its secrets. Opens no socket.
    pub(crate) fn check(&self, config: &DecoyConfig) -> Result<()> {
        let env = self.env.clone();
        DecoyService::with_env(config.clone(), move |name| env(name)).map(|_| ())
    }

    /// Reads the secrets and opens the listener.
    pub(crate) async fn bind(&self, config: &DecoyConfig) -> Result<BoundDecoy> {
        let env = self.env.clone();
        let bound = DecoyService::bind_with_env(config.clone(), move |name| env(name)).await?;
        *self.lock() = Some(Running {
            service: bound.service(),
            address: bound.local_addr(),
        });
        Ok(bound)
    }

    /// Records that the decoy stopped.
    pub(crate) fn stopped(&self) {
        *self.lock() = None;
    }

    /// Returns the address of the listener, while the decoy runs.
    pub(crate) fn address(&self) -> Option<SocketAddr> {
        self.lock().as_ref().map(|running| running.address)
    }

    /// Returns the field of the status document: the address and the counters.
    pub(crate) fn status(&self, config: &DecoyConfig) -> serde_json::Value {
        match self.lock().as_ref() {
            Some(running) => json!({
                "id": config.id,
                "running": true,
                "address": running.address,
                "personas": config.personas,
                "stats": running.service.stats(),
                "memory_bound_bytes": running.service.memory_bound(),
            }),
            None => json!({
                "id": config.id,
                "running": false,
                "personas": config.personas,
            }),
        }
    }
}
