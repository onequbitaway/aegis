//! Deception: honeytokens and canaries.
//!
//! A honeytoken is a passive decoy. The operator plants it in a place that no legitimate
//! process reads, for example a decoy secret in a vault or a decoy application. A read or a
//! use of the decoy has no legitimate cause, so it is a reliable sign of an attacker.
//!
//! This module only makes and records decoys, and finds events that touch them. A decoy
//! value is random text. It is not a credential and it gives no access to any system. Do
//! not register a decoy value as a real credential.
//!
//! | Item | Function |
//! | --- | --- |
//! | [`HoneytokenRegistry`] | Issues, lists, and retires honeytokens. |
//! | [`HoneytokenStore`] | The storage contract. [`MemoryHoneytokenStore`] keeps the data in memory. |
//! | [`HoneytokenTripDetector`] | A tier 1 detector for events that touch a honeytoken. |
//! | [`HoneytokenConnector`] | An action connector for `deploy_honeytoken`. |

mod connector;
mod detector;

use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

use aegis_contracts::common::{ActionId, EntityKind, EntityRef};
use aegis_contracts::event::{Event, attr};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::TryRng;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use connector::{HoneytokenConnector, parameter};
pub use detector::{HONEYTOKEN_DETECTOR_ID, HoneytokenTripDetector};

use crate::lock;
use crate::names::entity_label;

const ID_PREFIX: &str = "ht-";
const ID_RANDOM_BYTES: usize = 16;
const DECOY_LENGTH: usize = 40;
const DECOY_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const MAX_ID_LENGTH: usize = 128;
const MAX_DESCRIPTION_LENGTH: usize = 500;

/// The random text of a decoy. The `Debug` output does not show the text.
///
/// The text is not a credential. It gives no access to any system.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DecoyValue(String);

impl DecoyValue {
    /// Returns the text. Use it only to plant the decoy.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DecoyValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecoyValue([REDACTED])")
    }
}

/// The type of a decoy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneytokenKind {
    /// A decoy secret in a vault.
    Secret,
    /// A decoy key or password in a file, a repository, or a configuration.
    Credential,
    /// A decoy application registration or service principal.
    Application,
    /// A decoy user account.
    User,
    /// A decoy that has no more specific variant.
    Other,
}

impl HoneytokenKind {
    /// Returns the usual decoy type for a placement of the type `kind`.
    #[must_use]
    pub fn for_placement(kind: EntityKind) -> Self {
        match kind {
            EntityKind::Secret => Self::Secret,
            EntityKind::Application | EntityKind::ServicePrincipal => Self::Application,
            EntityKind::User => Self::User,
            _ => Self::Other,
        }
    }
}

/// One honeytoken.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Honeytoken {
    /// The identifier of the honeytoken.
    pub id: String,
    /// The type of the decoy.
    pub kind: HoneytokenKind,
    /// The random text of the decoy.
    pub decoy_value: DecoyValue,
    /// The place where the operator planted the decoy, for example a secret name.
    pub placement: EntityRef,
    /// A description of the decoy and its placement.
    pub description: String,
    /// The component or the person that issued the honeytoken.
    pub issued_by: String,
    /// The time at which the registry issued the honeytoken.
    pub issued_at: DateTime<Utc>,
    /// The action request that issued the honeytoken, if a connector issued it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// The time at which the operator retired the honeytoken. A retired token does not trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
}

impl Honeytoken {
    /// Returns `true` if the honeytoken is not retired.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.retired_at.is_none()
    }
}

/// The data for a new honeytoken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneytokenRequest {
    /// The type of the decoy.
    pub kind: HoneytokenKind,
    /// The place where the operator plants the decoy.
    pub placement: EntityRef,
    /// A description of the decoy and its placement.
    pub description: String,
    /// The component or the person that issues the honeytoken.
    pub issued_by: String,
    /// The identifier to use. With `None`, the registry makes a random identifier.
    pub id: Option<String>,
    /// The action request that issues the honeytoken.
    pub action_id: Option<ActionId>,
}

impl HoneytokenRequest {
    /// Makes a request with a random identifier and the issuer `operator`.
    pub fn new(kind: HoneytokenKind, placement: EntityRef, description: impl Into<String>) -> Self {
        Self {
            kind,
            placement,
            description: description.into(),
            issued_by: "operator".to_owned(),
            id: None,
            action_id: None,
        }
    }

    /// Sets the identifier. Use this for a decoy that a different canary system tracks.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the issuer.
    #[must_use]
    pub fn issued_by(mut self, issuer: impl Into<String>) -> Self {
        self.issued_by = issuer.into();
        self
    }
}

/// Storage for honeytokens.
#[async_trait]
pub trait HoneytokenStore: Send + Sync {
    /// Writes a honeytoken. A honeytoken with the same identifier is replaced.
    async fn put(&self, token: &Honeytoken) -> Result<()>;

    /// Reads one honeytoken.
    async fn get(&self, id: &str) -> Result<Option<Honeytoken>>;

    /// Lists all honeytokens, oldest first. The list includes retired honeytokens.
    async fn list(&self) -> Result<Vec<Honeytoken>>;
}

/// A [`HoneytokenStore`] that keeps all honeytokens in memory.
#[derive(Default)]
pub struct MemoryHoneytokenStore {
    tokens: Mutex<Vec<Honeytoken>>,
}

#[async_trait]
impl HoneytokenStore for MemoryHoneytokenStore {
    async fn put(&self, token: &Honeytoken) -> Result<()> {
        let mut tokens = lock(&self.tokens);
        match tokens.iter_mut().find(|known| known.id == token.id) {
            Some(known) => *known = token.clone(),
            None => tokens.push(token.clone()),
        }
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Honeytoken>> {
        Ok(lock(&self.tokens)
            .iter()
            .find(|token| token.id == id)
            .cloned())
    }

    async fn list(&self) -> Result<Vec<Honeytoken>> {
        Ok(lock(&self.tokens).clone())
    }
}

/// Fills a buffer from the random generator of the operating system.
fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    SysRng.try_fill_bytes(&mut bytes).map_err(|error| {
        Error::Unavailable(format!(
            "the random generator of the operating system failed: {error}"
        ))
    })?;
    Ok(bytes)
}

fn random_id() -> Result<String> {
    Ok(format!(
        "{ID_PREFIX}{}",
        hex::encode(random_bytes::<ID_RANDOM_BYTES>()?)
    ))
}

/// Makes random text from letters and digits. Each character has the same probability.
fn random_decoy() -> Result<DecoyValue> {
    let mut text = String::with_capacity(DECOY_LENGTH);
    while text.len() < DECOY_LENGTH {
        for byte in random_bytes::<64>()? {
            // Six bits give 0 to 63. Values 62 and 63 are rejected to keep the choice uniform.
            let Some(character) = DECOY_ALPHABET.get(usize::from(byte & 0x3f)) else {
                continue;
            };
            if text.len() < DECOY_LENGTH {
                text.push(char::from(*character));
            }
        }
    }
    Ok(DecoyValue(text))
}

/// How an event touched a honeytoken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripMatch {
    /// An attribute of the event holds the decoy value.
    DecoyValue,
    /// The attribute `honeytoken_id` of the event names the honeytoken.
    HoneytokenId,
    /// The target of the event is the honeytoken or its placement.
    Target,
    /// The actor of the event is the placement, for example a decoy application signs in.
    Actor,
}

/// One honeytoken that an event touched.
#[derive(Debug, Clone, PartialEq)]
pub struct Trip {
    /// The honeytoken.
    pub token: Honeytoken,
    /// How the event touched the honeytoken.
    pub matched: TripMatch,
}

fn same_entity(placement: &EntityRef, kind: EntityKind, id: &str, tenant: Option<&str>) -> bool {
    placement.kind == kind
        && placement.id == id
        && match (placement.tenant.as_deref(), tenant) {
            (Some(own), Some(other)) => own == other,
            _ => true,
        }
}

fn contains_text(value: &Value, text: &str) -> bool {
    match value {
        Value::String(found) => found.contains(text),
        Value::Array(items) => items.iter().any(|item| contains_text(item, text)),
        Value::Object(fields) => fields.values().any(|field| contains_text(field, text)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Returns how `event` touches `token`, or `None`.
fn trip_match(token: &Honeytoken, event: &Event) -> Option<TripMatch> {
    let decoy = token.decoy_value.expose();
    if !decoy.is_empty()
        && event
            .attributes
            .values()
            .any(|value| contains_text(value, decoy))
    {
        return Some(TripMatch::DecoyValue);
    }
    if event.attribute_str(attr::HONEYTOKEN_ID) == Some(token.id.as_str()) {
        return Some(TripMatch::HoneytokenId);
    }
    if let Some(target) = &event.target
        && (target.id == token.id
            || same_entity(
                &token.placement,
                target.kind,
                &target.id,
                target.tenant.as_deref(),
            ))
    {
        return Some(TripMatch::Target);
    }
    let actor = &event.actor;
    if same_entity(
        &token.placement,
        actor.kind,
        &actor.id,
        actor.tenant.as_deref(),
    ) {
        return Some(TripMatch::Actor);
    }
    None
}

/// Issues, lists, and retires honeytokens.
///
/// The registry keeps the active honeytokens in memory, so the detector reads no storage
/// for an event. If a different process changes the store, call [`refresh`](Self::refresh).
pub struct HoneytokenRegistry {
    store: Arc<dyn HoneytokenStore>,
    active: RwLock<Vec<Honeytoken>>,
    changes: tokio::sync::Mutex<()>,
}

impl HoneytokenRegistry {
    /// Opens a registry and reads the active honeytokens from the store.
    pub async fn open(store: Arc<dyn HoneytokenStore>) -> Result<Self> {
        let registry = Self {
            store,
            active: RwLock::default(),
            changes: tokio::sync::Mutex::new(()),
        };
        registry.refresh().await?;
        Ok(registry)
    }

    fn set_active(&self, tokens: Vec<Honeytoken>) {
        let mut active = self
            .active
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = tokens;
    }

    /// Reads the active honeytokens from the store again. Returns their number.
    pub async fn refresh(&self) -> Result<usize> {
        let _guard = self.changes.lock().await;
        let tokens: Vec<Honeytoken> = self
            .store
            .list()
            .await?
            .into_iter()
            .filter(Honeytoken::is_active)
            .collect();
        let count = tokens.len();
        self.set_active(tokens);
        Ok(count)
    }

    /// Returns the active honeytokens, oldest first.
    #[must_use]
    pub fn active(&self) -> Vec<Honeytoken> {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Issues a honeytoken with a random decoy value and writes it to the store.
    ///
    /// The identifier and the decoy value come from the random generator of the operating
    /// system. The caller plants the decoy value at the placement.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`]: a field is empty or too long, the identifier is in use, or
    ///   an active honeytoken has the same placement.
    /// - [`Error::Unavailable`]: the random generator failed.
    pub async fn issue(&self, request: HoneytokenRequest) -> Result<Honeytoken> {
        let placement_id = request.placement.id.trim();
        if placement_id.is_empty() {
            return Err(Error::InvalidInput(
                "the placement of a honeytoken must have an identifier".to_owned(),
            ));
        }
        let description = request.description.trim();
        if description.is_empty() || description.chars().count() > MAX_DESCRIPTION_LENGTH {
            return Err(Error::InvalidInput(format!(
                "the description of a honeytoken must have 1 to {MAX_DESCRIPTION_LENGTH} characters"
            )));
        }
        let _guard = self.changes.lock().await;
        let id = match request.id.as_deref().map(str::trim) {
            Some(id) => {
                let valid = !id.is_empty()
                    && id.chars().count() <= MAX_ID_LENGTH
                    && !id.chars().any(char::is_control);
                if !valid {
                    return Err(Error::InvalidInput(format!(
                        "the identifier of a honeytoken must have 1 to {MAX_ID_LENGTH} characters and no control characters"
                    )));
                }
                if self.store.get(id).await?.is_some() {
                    return Err(Error::InvalidInput(format!(
                        "a honeytoken with the identifier {id} already exists"
                    )));
                }
                id.to_owned()
            }
            None => random_id()?,
        };
        let mut placement = request.placement.clone();
        placement.id = placement_id.to_owned();
        let taken = self.active().iter().any(|token| {
            same_entity(
                &token.placement,
                placement.kind,
                &placement.id,
                placement.tenant.as_deref(),
            )
        });
        if taken {
            return Err(Error::InvalidInput(format!(
                "an active honeytoken already has the placement {}",
                entity_label(&placement)
            )));
        }
        let token = Honeytoken {
            id,
            kind: request.kind,
            decoy_value: random_decoy()?,
            placement,
            description: description.to_owned(),
            issued_by: request.issued_by,
            issued_at: Utc::now(),
            action_id: request.action_id,
            retired_at: None,
        };
        self.store.put(&token).await?;
        let mut active = self.active();
        active.push(token.clone());
        self.set_active(active);
        Ok(token)
    }

    /// Lists all honeytokens in the store, oldest first. The list includes retired tokens.
    pub async fn list(&self) -> Result<Vec<Honeytoken>> {
        self.store.list().await
    }

    /// Reads one honeytoken from the store.
    pub async fn get(&self, id: &str) -> Result<Option<Honeytoken>> {
        self.store.get(id).await
    }

    /// Retires a honeytoken. A retired honeytoken does not trip.
    ///
    /// A second call for the same honeytoken changes nothing and returns the honeytoken.
    /// Returns [`Error::NotFound`] if the store has no honeytoken with this identifier.
    pub async fn retire(&self, id: &str) -> Result<Honeytoken> {
        let _guard = self.changes.lock().await;
        let mut token = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("honeytoken {id}")))?;
        if token.is_active() {
            token.retired_at = Some(Utc::now());
            self.store.put(&token).await?;
        }
        let mut active = self.active();
        active.retain(|known| known.id != id);
        self.set_active(active);
        Ok(token)
    }

    /// Returns each active honeytoken that the event touches.
    ///
    /// An event touches a honeytoken in one of these ways, in this order:
    ///
    /// 1. An attribute holds the decoy value.
    /// 2. The attribute `honeytoken_id` names the honeytoken.
    /// 3. The target is the honeytoken or its placement.
    /// 4. The actor is the placement.
    #[must_use]
    pub fn trips(&self, event: &Event) -> Vec<Trip> {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(|token| {
                trip_match(token, event).map(|matched| Trip {
                    token: token.clone(),
                    matched,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoy_value_is_random_letters_and_digits() {
        let first = random_decoy().unwrap();
        let second = random_decoy().unwrap();
        assert_eq!(first.expose().len(), DECOY_LENGTH);
        assert!(
            first
                .expose()
                .chars()
                .all(|character| character.is_ascii_alphanumeric())
        );
        assert_ne!(first, second);
        assert_eq!(format!("{first:?}"), "DecoyValue([REDACTED])");
    }

    #[test]
    fn a_random_identifier_has_the_prefix_and_128_random_bits() {
        let first = random_id().unwrap();
        let second = random_id().unwrap();
        assert_eq!(first.len(), ID_PREFIX.len() + 2 * ID_RANDOM_BYTES);
        assert!(first.starts_with(ID_PREFIX), "{first}");
        assert!(
            first[ID_PREFIX.len()..]
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
        assert_ne!(first, second);
    }

    #[test]
    fn the_decoy_alphabet_has_62_different_characters() {
        let mut characters = DECOY_ALPHABET.to_vec();
        characters.sort_unstable();
        characters.dedup();
        assert_eq!(characters.len(), 62);
    }

    #[test]
    fn the_usual_decoy_type_follows_the_placement() {
        assert_eq!(
            HoneytokenKind::for_placement(EntityKind::Secret),
            HoneytokenKind::Secret
        );
        assert_eq!(
            HoneytokenKind::for_placement(EntityKind::ServicePrincipal),
            HoneytokenKind::Application
        );
        assert_eq!(
            HoneytokenKind::for_placement(EntityKind::User),
            HoneytokenKind::User
        );
        assert_eq!(
            HoneytokenKind::for_placement(EntityKind::Host),
            HoneytokenKind::Other
        );
    }

    #[test]
    fn entities_with_different_tenants_are_different() {
        let placement = EntityRef::new(EntityKind::Secret, "kv/decoy").with_tenant("tenant-a");
        assert!(same_entity(
            &placement,
            EntityKind::Secret,
            "kv/decoy",
            Some("tenant-a")
        ));
        assert!(same_entity(
            &placement,
            EntityKind::Secret,
            "kv/decoy",
            None
        ));
        assert!(!same_entity(
            &placement,
            EntityKind::Secret,
            "kv/decoy",
            Some("tenant-b")
        ));
        assert!(!same_entity(
            &placement,
            EntityKind::Secret,
            "kv/other",
            Some("tenant-a")
        ));
        assert!(!same_entity(
            &placement,
            EntityKind::Application,
            "kv/decoy",
            Some("tenant-a")
        ));
    }
}
