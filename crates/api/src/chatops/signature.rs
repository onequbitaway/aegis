//! The signature checks of the ChatOps requests.
//!
//! The server checks the signature of each request before it reads the request. A check
//! fails closed: a missing header, a header in a different form, an old timestamp, and a
//! signature that does not match are all refusals.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The maximum difference between the time of a request and the present time, in seconds.
pub const MAX_SKEW_SECONDS: i64 = 5 * 60;

const SLACK_VERSION: &str = "v0";
const TEAMS_SCHEME: &str = "HMAC";
const MAC_BYTES: usize = 32;

/// Why a signature check refused a request. The text goes to the log, not to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The request has no signature header or no timestamp header.
    #[error("a signature header is missing")]
    MissingHeader,
    /// A header does not have the necessary form.
    #[error("a signature header does not have the necessary form")]
    Malformed,
    /// The time of the request is too far from the present time.
    #[error("the request time is more than five minutes from the present time")]
    Stale,
    /// The signature is not the signature of this request with the shared secret.
    #[error("the signature does not match")]
    Mismatch,
}

fn mac(secret: &[u8], parts: &[&[u8]]) -> Result<[u8; MAC_BYTES], SignatureError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| SignatureError::Malformed)?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn compare(expected: &[u8; MAC_BYTES], presented: &[u8]) -> Result<(), SignatureError> {
    // `ct_eq` on slices gives "not equal" for a different length.
    if bool::from(expected.as_slice().ct_eq(presented)) {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

/// Returns the value of the `X-Slack-Signature` header for a request.
///
/// The value is `v0=` and the HMAC-SHA256 of `v0:{timestamp}:{body}` with the signing
/// secret, in lower-case hexadecimal.
///
/// # Errors
///
/// Returns [`SignatureError::Malformed`] if the secret cannot be an HMAC key.
pub fn slack_signature(
    signing_secret: &[u8],
    timestamp: &str,
    body: &[u8],
) -> Result<String, SignatureError> {
    let digest = mac(
        signing_secret,
        &[
            SLACK_VERSION.as_bytes(),
            b":",
            timestamp.as_bytes(),
            b":",
            body,
        ],
    )?;
    Ok(format!("{SLACK_VERSION}={}", hex::encode(digest)))
}

/// Checks the signature of a Slack request.
///
/// `timestamp` is the `X-Slack-Request-Timestamp` header. `signature` is the
/// `X-Slack-Signature` header. `now` is the present time in seconds since the Unix epoch.
///
/// # Errors
///
/// Returns the reason for the refusal.
pub fn verify_slack(
    signing_secret: &[u8],
    timestamp: Option<&str>,
    signature: Option<&str>,
    body: &[u8],
    now: i64,
) -> Result<(), SignatureError> {
    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return Err(SignatureError::MissingHeader);
    };
    // A timestamp must have digits only, so that the signed text has one form.
    if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SignatureError::Malformed);
    }
    let seconds: i64 = timestamp.parse().map_err(|_| SignatureError::Malformed)?;
    if now.abs_diff(seconds) > MAX_SKEW_SECONDS.unsigned_abs() {
        return Err(SignatureError::Stale);
    }
    let presented = signature
        .strip_prefix(SLACK_VERSION)
        .and_then(|rest| rest.strip_prefix('='))
        .and_then(|digest| hex::decode(digest).ok())
        .ok_or(SignatureError::Malformed)?;
    let expected = mac(
        signing_secret,
        &[
            SLACK_VERSION.as_bytes(),
            b":",
            timestamp.as_bytes(),
            b":",
            body,
        ],
    )?;
    compare(&expected, &presented)
}

/// Returns the value of the `Authorization` header of a Teams outgoing webhook request.
///
/// The value is `HMAC ` and the HMAC-SHA256 of the body with the shared secret, in base64.
///
/// # Errors
///
/// Returns [`SignatureError::Malformed`] if the secret cannot be an HMAC key.
pub fn teams_authorization(secret: &[u8], body: &[u8]) -> Result<String, SignatureError> {
    let digest = mac(secret, &[body])?;
    Ok(format!("{TEAMS_SCHEME} {}", STANDARD.encode(digest)))
}

/// Checks the `Authorization: HMAC <base64>` header of a Teams outgoing webhook request.
///
/// `secret` is the security token of the webhook after base64 decoding.
///
/// # Errors
///
/// Returns the reason for the refusal.
pub fn verify_teams(
    secret: &[u8],
    authorization: Option<&str>,
    body: &[u8],
) -> Result<(), SignatureError> {
    let authorization = authorization.ok_or(SignatureError::MissingHeader)?;
    let (scheme, digest) = authorization
        .split_once(' ')
        .ok_or(SignatureError::Malformed)?;
    if !scheme.eq_ignore_ascii_case(TEAMS_SCHEME) {
        return Err(SignatureError::Malformed);
    }
    let presented = STANDARD
        .decode(digest.trim())
        .map_err(|_| SignatureError::Malformed)?;
    let expected = mac(secret, &[body])?;
    compare(&expected, &presented)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The example of the Slack documentation for request signatures.
    const SLACK_SECRET: &[u8] = b"8f742231b10e8888abcd99yyyzzz85a5";
    const SLACK_TIMESTAMP: &str = "1531420618";
    const SLACK_BODY: &[u8] = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SLACK_SIGNATURE: &str =
        "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    const SLACK_NOW: i64 = 1_531_420_618;

    #[test]
    fn the_slack_signature_is_the_documented_value() {
        assert_eq!(
            slack_signature(SLACK_SECRET, SLACK_TIMESTAMP, SLACK_BODY).unwrap(),
            SLACK_SIGNATURE
        );
    }

    fn slack(
        timestamp: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
        now: i64,
    ) -> Result<(), SignatureError> {
        verify_slack(SLACK_SECRET, timestamp, signature, body, now)
    }

    #[test]
    fn a_correct_slack_signature_is_accepted_inside_the_time_window() {
        for now in [SLACK_NOW, SLACK_NOW + 300, SLACK_NOW - 300] {
            assert_eq!(
                slack(
                    Some(SLACK_TIMESTAMP),
                    Some(SLACK_SIGNATURE),
                    SLACK_BODY,
                    now
                ),
                Ok(()),
                "{now}"
            );
        }
    }

    #[test]
    fn a_slack_request_outside_the_time_window_is_stale() {
        for now in [SLACK_NOW + 301, SLACK_NOW - 301, 0, i64::MAX, i64::MIN] {
            assert_eq!(
                slack(
                    Some(SLACK_TIMESTAMP),
                    Some(SLACK_SIGNATURE),
                    SLACK_BODY,
                    now
                ),
                Err(SignatureError::Stale),
                "{now}"
            );
        }
    }

    #[test]
    fn a_changed_slack_request_does_not_match() {
        let mut body = SLACK_BODY.to_vec();
        body[0] ^= 1;
        assert_eq!(
            slack(
                Some(SLACK_TIMESTAMP),
                Some(SLACK_SIGNATURE),
                &body,
                SLACK_NOW
            ),
            Err(SignatureError::Mismatch)
        );
        // A different timestamp in the window changes the signed text.
        assert_eq!(
            slack(
                Some("1531420619"),
                Some(SLACK_SIGNATURE),
                SLACK_BODY,
                SLACK_NOW
            ),
            Err(SignatureError::Mismatch)
        );
        let other_secret = slack_signature(
            b"a-different-signing-secret-0000",
            SLACK_TIMESTAMP,
            SLACK_BODY,
        )
        .unwrap();
        assert_eq!(
            slack(
                Some(SLACK_TIMESTAMP),
                Some(&other_secret),
                SLACK_BODY,
                SLACK_NOW
            ),
            Err(SignatureError::Mismatch)
        );
        // A signature with fewer bytes, and a signature with no bytes.
        let short = &SLACK_SIGNATURE[..SLACK_SIGNATURE.len() - 2];
        for signature in [short, "v0="] {
            assert_eq!(
                slack(
                    Some(SLACK_TIMESTAMP),
                    Some(signature),
                    SLACK_BODY,
                    SLACK_NOW
                ),
                Err(SignatureError::Mismatch),
                "{signature:?}"
            );
        }
    }

    #[test]
    fn slack_headers_must_be_present_and_have_the_necessary_form() {
        assert_eq!(
            slack(None, Some(SLACK_SIGNATURE), SLACK_BODY, SLACK_NOW),
            Err(SignatureError::MissingHeader)
        );
        assert_eq!(
            slack(Some(SLACK_TIMESTAMP), None, SLACK_BODY, SLACK_NOW),
            Err(SignatureError::MissingHeader)
        );
        let v1 = SLACK_SIGNATURE.replacen("v0", "v1", 1);
        let bare = SLACK_SIGNATURE.trim_start_matches("v0=");
        for signature in [v1.as_str(), bare, "v0=zz", "v0=abc", "v0", ""] {
            assert_eq!(
                slack(
                    Some(SLACK_TIMESTAMP),
                    Some(signature),
                    SLACK_BODY,
                    SLACK_NOW
                ),
                Err(SignatureError::Malformed),
                "{signature:?}"
            );
        }
        for timestamp in [
            "",
            "+1531420618",
            " 1531420618",
            "1531420618.0",
            "now",
            "99999999999999999999",
        ] {
            assert_eq!(
                slack(
                    Some(timestamp),
                    Some(SLACK_SIGNATURE),
                    SLACK_BODY,
                    SLACK_NOW
                ),
                Err(SignatureError::Malformed),
                "{timestamp:?}"
            );
        }
    }

    // printf '{"type":"message","text":"approvals"}' \
    //   | openssl dgst -sha256 -mac HMAC -macopt hexkey:000102...1f -binary | base64
    const TEAMS_SECRET: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const TEAMS_BODY: &[u8] = br#"{"type":"message","text":"approvals"}"#;
    const TEAMS_AUTHORIZATION: &str = "HMAC rf7j990yPlopaCIt0twoH+oxzSprBgwN/gLF9c4mB5w=";

    #[test]
    fn the_teams_authorization_is_the_known_value() {
        assert_eq!(
            teams_authorization(&TEAMS_SECRET, TEAMS_BODY).unwrap(),
            TEAMS_AUTHORIZATION
        );
    }

    #[test]
    fn a_correct_teams_authorization_is_accepted() {
        assert_eq!(
            verify_teams(&TEAMS_SECRET, Some(TEAMS_AUTHORIZATION), TEAMS_BODY),
            Ok(())
        );
        let lower = TEAMS_AUTHORIZATION.replacen("HMAC", "hmac", 1);
        assert_eq!(
            verify_teams(&TEAMS_SECRET, Some(&lower), TEAMS_BODY),
            Ok(())
        );
    }

    #[test]
    fn a_teams_request_that_is_not_authentic_is_refused() {
        let mut body = TEAMS_BODY.to_vec();
        body.push(b' ');
        assert_eq!(
            verify_teams(&TEAMS_SECRET, Some(TEAMS_AUTHORIZATION), &body),
            Err(SignatureError::Mismatch)
        );
        let mut other = TEAMS_SECRET;
        other[31] ^= 1;
        assert_eq!(
            verify_teams(&other, Some(TEAMS_AUTHORIZATION), TEAMS_BODY),
            Err(SignatureError::Mismatch)
        );
        // A valid base64 value with a different length.
        assert_eq!(
            verify_teams(&TEAMS_SECRET, Some("HMAC AAAA"), TEAMS_BODY),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_teams(&TEAMS_SECRET, None, TEAMS_BODY),
            Err(SignatureError::MissingHeader)
        );
        let bearer = TEAMS_AUTHORIZATION.replacen("HMAC", "Bearer", 1);
        for authorization in [bearer.as_str(), "HMAC", "HMAC not base64!", ""] {
            assert_eq!(
                verify_teams(&TEAMS_SECRET, Some(authorization), TEAMS_BODY),
                Err(SignatureError::Malformed),
                "{authorization:?}"
            );
        }
    }
}
