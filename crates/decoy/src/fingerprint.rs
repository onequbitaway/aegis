//! The fingerprint of a client.

use sha2::{Digest, Sha256};

/// The text that separates this hash from other hashes of the same input.
const DOMAIN: &[u8] = b"aegis-decoy-client-fingerprint-v1";
/// The largest number of header names in the fingerprint.
const MAX_HEADER_NAMES: usize = 64;
/// The largest number of bytes of one value in the fingerprint.
const MAX_VALUE_BYTES: usize = 512;
/// The number of hexadecimal digits in a fingerprint.
pub(crate) const FINGERPRINT_LENGTH: usize = 32;

/// Returns a stable fingerprint of a client from the shape of one request.
///
/// The fingerprint is a hash of these values:
///
/// - The HTTP version, for example `HTTP/1.1`.
/// - The names of the request headers, as the client wrote them and in the same order.
/// - The user agent.
/// - The accepted content encodings, in lower case and with no white space.
///
/// The header values, the path, and the body are not in the hash. Thus the fingerprint
/// holds no secret, and one client program usually has one fingerprint.
///
/// The fingerprint is a heuristic. Two different clients can have the same fingerprint.
/// One client can change its headers and get a different fingerprint. Use the
/// fingerprint to group contacts. Do not use it as proof of an identity.
///
/// The result has 32 lower-case hexadecimal digits.
#[must_use]
pub fn client_fingerprint(
    http_version: &str,
    header_names: &[&str],
    user_agent: &str,
    accept_encoding: &str,
) -> String {
    let mut digest = Sha256::new();
    update_with_length(&mut digest, DOMAIN);
    update_with_length(&mut digest, http_version.as_bytes());
    let names = header_names.get(..MAX_HEADER_NAMES).unwrap_or(header_names);
    update_with_length(&mut digest, &names.len().to_be_bytes());
    for name in names {
        update_with_length(&mut digest, limited(name.as_bytes()));
    }
    update_with_length(&mut digest, limited(user_agent.as_bytes()));
    let encodings: String = accept_encoding
        .chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    update_with_length(&mut digest, limited(encodings.as_bytes()));
    let mut text = hex::encode(digest.finalize());
    text.truncate(FINGERPRINT_LENGTH);
    text
}

fn limited(bytes: &[u8]) -> &[u8] {
    bytes.get(..MAX_VALUE_BYTES).unwrap_or(bytes)
}

fn update_with_length(digest: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    digest.update(length.to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: &[&str] = &["Host", "User-Agent", "Accept", "Accept-Encoding"];

    fn base() -> String {
        client_fingerprint("HTTP/1.1", NAMES, "agent/1.0", "gzip, br")
    }

    #[test]
    fn the_fingerprint_is_stable_and_has_32_hexadecimal_digits() {
        let fingerprint = base();
        assert_eq!(fingerprint, base());
        assert_eq!(fingerprint.len(), FINGERPRINT_LENGTH);
        assert!(
            fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
    }

    #[test]
    fn each_input_changes_the_fingerprint() {
        let base = base();
        assert_ne!(
            base,
            client_fingerprint("HTTP/1.0", NAMES, "agent/1.0", "gzip, br")
        );
        assert_ne!(
            base,
            client_fingerprint("HTTP/1.1", NAMES, "agent/2.0", "gzip, br")
        );
        assert_ne!(
            base,
            client_fingerprint("HTTP/1.1", NAMES, "agent/1.0", "gzip")
        );
        let fewer = &NAMES[..3];
        assert_ne!(
            base,
            client_fingerprint("HTTP/1.1", fewer, "agent/1.0", "gzip, br")
        );
    }

    #[test]
    fn the_order_and_the_case_of_the_header_names_change_the_fingerprint() {
        let swapped = ["User-Agent", "Host", "Accept", "Accept-Encoding"];
        assert_ne!(
            base(),
            client_fingerprint("HTTP/1.1", &swapped, "agent/1.0", "gzip, br")
        );
        let lower = ["host", "user-agent", "accept", "accept-encoding"];
        assert_ne!(
            base(),
            client_fingerprint("HTTP/1.1", &lower, "agent/1.0", "gzip, br")
        );
    }

    #[test]
    fn the_case_and_the_spaces_of_the_encodings_do_not_change_the_fingerprint() {
        assert_eq!(
            base(),
            client_fingerprint("HTTP/1.1", NAMES, "agent/1.0", " GZIP,BR ")
        );
    }

    #[test]
    fn a_border_between_two_values_cannot_move() {
        assert_ne!(
            client_fingerprint("HTTP/1.1", &["ab", "c"], "", ""),
            client_fingerprint("HTTP/1.1", &["a", "bc"], "", "")
        );
        assert_ne!(
            client_fingerprint("HTTP/1.1", &[], "ab", ""),
            client_fingerprint("HTTP/1.1", &[], "a", "b")
        );
    }

    #[test]
    fn only_the_first_64_header_names_count() {
        let many: Vec<String> = (0..80).map(|index| format!("X-{index}")).collect();
        let all: Vec<&str> = many.iter().map(String::as_str).collect();
        let first = &all[..MAX_HEADER_NAMES];
        assert_eq!(
            client_fingerprint("HTTP/1.1", &all, "", ""),
            client_fingerprint("HTTP/1.1", first, "", "")
        );
        assert_ne!(
            client_fingerprint("HTTP/1.1", &all[..63], "", ""),
            client_fingerprint("HTTP/1.1", first, "", "")
        );
    }
}
