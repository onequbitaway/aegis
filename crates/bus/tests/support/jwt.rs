//! NATS operator, account, and user tokens for the test of the credentials file.
//!
//! Each test run makes new keys. No key is in the repository.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nkeys::KeyPair;
use serde_json::{Value, json};

/// An operator with a system account and one account for users. JetStream is enabled for
/// the account for users.
pub struct Operator {
    operator: KeyPair,
    system_account: KeyPair,
    account: KeyPair,
}

impl Operator {
    /// Makes an operator and its accounts with new keys.
    pub fn new() -> Self {
        Self {
            operator: KeyPair::new_operator(),
            system_account: KeyPair::new_account(),
            account: KeyPair::new_account(),
        }
    }

    /// The text of a NATS server configuration that trusts this operator and knows the
    /// accounts.
    pub fn server_config(&self) -> String {
        let operator = self.operator.public_key();
        let system_account = self.system_account.public_key();
        let account = self.account.public_key();
        let limits = |jetstream: i64| {
            json!({
                "subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1,
                "wildcards": true, "conn": -1, "leaf": -1,
                "mem_storage": jetstream, "disk_storage": jetstream,
                "streams": jetstream, "consumer": jetstream,
            })
        };
        let operator_token = token(
            &self.operator,
            &operator,
            "aegis-test-operator",
            json!({ "type": "operator", "version": 2 }),
        );
        let system_token = token(
            &self.operator,
            &system_account,
            "aegis-test-system",
            json!({ "type": "account", "version": 2, "limits": limits(0) }),
        );
        let account_token = token(
            &self.operator,
            &account,
            "aegis-test-account",
            json!({ "type": "account", "version": 2, "limits": limits(-1) }),
        );
        format!(
            "operator: \"{operator_token}\"\nsystem_account: {system_account}\nresolver: \
             MEMORY\nresolver_preload: {{\n  {system_account}: \"{system_token}\"\n  \
             {account}: \"{account_token}\"\n}}\n"
        )
    }

    /// The content of a credentials file for a new user of the account.
    pub fn user_credentials(&self, name: &str) -> String {
        let user = KeyPair::new_user();
        let user_token = token(
            &self.account,
            &user.public_key(),
            name,
            json!({ "type": "user", "version": 2, "pub": {}, "sub": {}, "subs": -1, "data": -1, "payload": -1 }),
        );
        credentials_file(&user_token, &user.seed().expect("the seed of the user"))
    }
}

/// Makes the text of a credentials file from a user token and a user seed.
pub fn credentials_file(user_token: &str, seed: &str) -> String {
    format!(
        "-----BEGIN NATS USER JWT-----\n{user_token}\n------END NATS USER JWT------\n\n\
         -----BEGIN USER NKEY SEED-----\n{seed}\n------END USER NKEY SEED------\n"
    )
}

/// Makes a signed token. The issuer signs the claims of the subject.
fn token(issuer: &KeyPair, subject: &str, name: &str, nats: Value) -> String {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    let claims = json!({
        "jti": format!("{name}-{issued_at}"),
        "iat": issued_at,
        "iss": issuer.public_key(),
        "name": name,
        "sub": subject,
        "nats": nats,
    });
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ed25519-nkey"}"#);
    let body = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signed = format!("{header}.{body}");
    let signature = issuer.sign(signed.as_bytes()).expect("a signature");
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}
