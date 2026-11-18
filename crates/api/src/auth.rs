//! Authentication with bearer tokens.
//!
//! Each principal in the configuration names the environment variable that holds its
//! token. The server keeps only the SHA-256 digest of each token. It compares digests in
//! constant time.
//!
//! Authentication fails closed. A request with no token, a token that no principal has, or
//! more than one `Authorization` header is refused. With no principals, each request is
//! refused.

use std::collections::BTreeMap;

use aegis_contracts::policy::Principal;
use aegis_contracts::{Error, Result};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::PrincipalConfig;
use crate::state::EnvLookup;

/// The minimum length of a bearer token, in characters.
pub const MIN_TOKEN_CHARACTERS: usize = 32;

/// The maximum length of a bearer token that the server examines, in bytes.
const MAX_TOKEN_BYTES: usize = 4096;

const BEARER: &str = "bearer";

type TokenDigest = [u8; 32];

fn digest(token: &[u8]) -> TokenDigest {
    Sha256::digest(token).into()
}

struct TokenEntry {
    digest: TokenDigest,
    principal: Principal,
}

/// The principals of the configuration and the digests of their tokens.
pub(crate) struct Authenticator {
    tokens: Vec<TokenEntry>,
    principals: BTreeMap<String, Principal>,
}

impl Authenticator {
    /// Reads the token of each principal through `env`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a token variable is not set, a token is shorter than
    /// [`MIN_TOKEN_CHARACTERS`], or two principals have the same token. The message names
    /// the variable. It never shows a token.
    pub(crate) fn from_config(principals: &[PrincipalConfig], env: &EnvLookup) -> Result<Self> {
        let mut tokens: Vec<TokenEntry> = Vec::new();
        let mut known = BTreeMap::new();
        for config in principals {
            let principal = Principal {
                id: config.id.clone(),
                kind: config.kind,
                roles: config.roles.clone(),
            };
            known.insert(config.id.clone(), principal.clone());
            let Some(variable) = &config.token_env else {
                continue;
            };
            let token = env(variable)
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::Config(format!(
                        "principal {}: the environment variable {variable} is not set",
                        config.id
                    ))
                })?;
            if token.chars().count() < MIN_TOKEN_CHARACTERS {
                return Err(Error::Config(format!(
                    "principal {}: the token in {variable} must have {MIN_TOKEN_CHARACTERS} \
                     characters or more",
                    config.id
                )));
            }
            if token.len() > MAX_TOKEN_BYTES || !token.chars().all(is_token_character) {
                return Err(Error::Config(format!(
                    "principal {}: the token in {variable} must have only visible ASCII \
                     characters and at most {MAX_TOKEN_BYTES} of them",
                    config.id
                )));
            }
            let digest = digest(token.as_bytes());
            if tokens.iter().any(|entry| entry.digest == digest) {
                return Err(Error::Config(format!(
                    "principal {}: the token in {variable} is also the token of a different \
                     principal",
                    config.id
                )));
            }
            tokens.push(TokenEntry { digest, principal });
        }
        Ok(Self {
            tokens,
            principals: known,
        })
    }

    /// Returns the principal with this identifier, with or without a token.
    pub(crate) fn principal(&self, id: &str) -> Option<&Principal> {
        self.principals.get(id)
    }

    /// Returns the principal that the bearer token in `headers` identifies.
    ///
    /// `None` means that the request has no valid credential.
    pub(crate) fn authenticate(&self, headers: &HeaderMap) -> Option<Principal> {
        let token = bearer_token(headers)?;
        self.find(token.as_bytes())
    }

    /// Compares the digest of `token` with each stored digest. The loop has no early exit,
    /// so the time does not show how many principals the server examined.
    fn find(&self, token: &[u8]) -> Option<Principal> {
        let presented = digest(token);
        let mut found: Option<&Principal> = None;
        for entry in &self.tokens {
            if bool::from(entry.digest.ct_eq(&presented)) {
                found = Some(&entry.principal);
            }
        }
        found.cloned()
    }
}

/// Returns `true` for a character that a bearer token can have: visible ASCII.
fn is_token_character(character: char) -> bool {
    character.is_ascii_graphic()
}

/// Returns the token of the single `Authorization: Bearer` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case(BEARER) {
        return None;
    }
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aegis_contracts::policy::PrincipalKind;
    use axum::http::HeaderValue;

    use super::*;

    const ALICE_TOKEN: &str = "alice-token-0123456789abcdef0123456789";
    const BOB_TOKEN: &str = "bob-token-0123456789abcdef0123456789ab";

    fn env() -> EnvLookup {
        Arc::new(|name: &str| match name {
            "ALICE_TOKEN" => Some(format!(" {ALICE_TOKEN}\n")),
            "BOB_TOKEN" => Some(BOB_TOKEN.to_owned()),
            "SHORT_TOKEN" => Some("short".to_owned()),
            "EMPTY_TOKEN" => Some("  ".to_owned()),
            "SPACE_TOKEN" => Some("token with spaces 0123456789abcdef0123456789".to_owned()),
            _ => None,
        })
    }

    fn principals() -> Vec<PrincipalConfig> {
        vec![
            PrincipalConfig::human("alice", &["approver"], "ALICE_TOKEN"),
            PrincipalConfig {
                id: "bob".to_owned(),
                kind: PrincipalKind::System,
                roles: vec!["viewer".to_owned()],
                token_env: Some("BOB_TOKEN".to_owned()),
            },
            PrincipalConfig {
                id: "carol".to_owned(),
                kind: PrincipalKind::Human,
                roles: vec!["approver".to_owned()],
                token_env: None,
            },
        ]
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn config_error(principals: &[PrincipalConfig]) -> String {
        match Authenticator::from_config(principals, &env()) {
            Err(Error::Config(message)) => message,
            Err(other) => panic!("expected a configuration error, found {other:?}"),
            Ok(_) => panic!("expected a configuration error"),
        }
    }

    #[test]
    fn a_valid_token_gives_its_principal() {
        let auth = Authenticator::from_config(&principals(), &env()).unwrap();
        let alice = auth
            .authenticate(&headers(&[&format!("Bearer {ALICE_TOKEN}")]))
            .unwrap();
        assert_eq!(
            alice,
            Principal::new("alice", PrincipalKind::Human, &["approver"])
        );
        let bob = auth
            .authenticate(&headers(&[&format!("bearer   {BOB_TOKEN}")]))
            .unwrap();
        assert_eq!(
            bob,
            Principal::new("bob", PrincipalKind::System, &["viewer"])
        );
    }

    #[test]
    fn a_request_without_a_valid_token_has_no_principal() {
        let auth = Authenticator::from_config(&principals(), &env()).unwrap();
        let wrong_scheme = format!("Basic {ALICE_TOKEN}");
        let prefix = format!("Bearer {}", &ALICE_TOKEN[..ALICE_TOKEN.len() - 1]);
        let longer = format!("Bearer {ALICE_TOKEN}x");
        let cases: [&[&str]; 8] = [
            &[],
            &["Bearer"],
            &["Bearer "],
            &["Bearer not-a-token-of-any-principal-000000"],
            &[&wrong_scheme],
            &[&prefix],
            &[&longer],
            &[ALICE_TOKEN],
        ];
        for case in cases {
            assert_eq!(auth.authenticate(&headers(case)), None, "{case:?}");
        }
        let valid = format!("Bearer {ALICE_TOKEN}");
        assert_eq!(auth.authenticate(&headers(&[&valid, &valid])), None);
    }

    #[test]
    fn no_principals_means_that_no_token_is_valid() {
        let auth = Authenticator::from_config(&[], &env()).unwrap();
        assert_eq!(
            auth.authenticate(&headers(&[&format!("Bearer {ALICE_TOKEN}")])),
            None
        );
        assert_eq!(auth.authenticate(&headers(&["Bearer "])), None);
    }

    #[test]
    fn a_principal_without_a_token_is_known_but_cannot_authenticate() {
        let auth = Authenticator::from_config(&principals(), &env()).unwrap();
        assert_eq!(
            auth.principal("carol"),
            Some(&Principal::new(
                "carol",
                PrincipalKind::Human,
                &["approver"]
            ))
        );
        assert_eq!(auth.principal("dave"), None);
        assert_eq!(auth.tokens.len(), 2);
    }

    #[test]
    fn a_token_that_is_not_usable_is_a_configuration_error() {
        let with_variable = |variable: &str| vec![PrincipalConfig::human("alice", &[], variable)];
        assert_eq!(
            config_error(&with_variable("MISSING_TOKEN")),
            "principal alice: the environment variable MISSING_TOKEN is not set"
        );
        assert_eq!(
            config_error(&with_variable("EMPTY_TOKEN")),
            "principal alice: the environment variable EMPTY_TOKEN is not set"
        );
        assert_eq!(
            config_error(&with_variable("SHORT_TOKEN")),
            "principal alice: the token in SHORT_TOKEN must have 32 characters or more"
        );
        assert_eq!(
            config_error(&with_variable("SPACE_TOKEN")),
            "principal alice: the token in SPACE_TOKEN must have only visible ASCII characters \
             and at most 4096 of them"
        );
    }

    #[test]
    fn two_principals_cannot_share_a_token() {
        let shared = vec![
            PrincipalConfig::human("alice", &[], "ALICE_TOKEN"),
            PrincipalConfig::human("mallory", &[], "ALICE_TOKEN"),
        ];
        let message = config_error(&shared);
        assert_eq!(
            message,
            "principal mallory: the token in ALICE_TOKEN is also the token of a different \
             principal"
        );
        assert!(!message.contains(ALICE_TOKEN));
    }
}
