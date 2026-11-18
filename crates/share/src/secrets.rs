//! Removal of secrets and of addresses from free text.
//!
//! The allow list is the first control: by default, a document keeps only a small set of
//! event attributes. This module is the second control. It examines the text that stays
//! and replaces each part that looks like a secret.
//!
//! The check uses shapes and key names. It cannot find each possible secret. Read a
//! document before you send it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The text that replaces a secret.
pub(crate) const SECRET_MARK: &str = "[secret removed]";

/// The text that replaces an address that the document must not name.
pub(crate) const ADDRESS_MARK: &str = "[address removed]";

/// The text that replaces the query of a path.
pub(crate) const QUERY_MARK: &str = "[query removed]";

/// The text that replaces the fragment of a path.
pub(crate) const FRAGMENT_MARK: &str = "[fragment removed]";

/// Key names that hold a secret when the name contains one of these words.
const KEY_CONTAINS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "authorization",
    "credential",
    "signature",
    "sessionid",
    "cookie",
    "bearer",
];

/// Key names that hold a secret when the last word of the name is one of these words.
const KEY_LAST_WORD: &[&str] = &[
    "key", "sig", "pass", "pw", "pwd", "pin", "otp", "sas", "jwt", "sid", "auth",
];

/// Key names that hold a secret when the full name is one of these words.
const KEY_WHOLE: &[&str] = &["code"];

/// The names of HTTP authentication schemes. A credential follows the name.
const SCHEMES: &[&str] = &["bearer", "basic", "digest", "negotiate", "ntlm"];

/// Known prefixes of access tokens, each with the smallest length of a token.
const TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("AKIA", 20),
    ("ASIA", 20),
    ("ghp_", 20),
    ("gho_", 20),
    ("ghu_", 20),
    ("ghs_", 20),
    ("ghr_", 20),
    ("github_pat_", 20),
    ("glpat-", 20),
    ("xoxb-", 15),
    ("xoxp-", 15),
    ("xoxa-", 15),
    ("xoxr-", 15),
    ("xoxs-", 15),
    ("sk-", 20),
    ("sk_live_", 16),
    ("rk_live_", 16),
    ("AIza", 35),
    ("ya29.", 20),
    ("hf_", 30),
    ("npm_", 30),
    ("pypi-", 30),
    ("SG.", 30),
    ("dop_v1_", 30),
    ("shpat_", 20),
];

/// The smallest length of a run of letters and digits that the scrubber treats as a key.
const MIN_OPAQUE_CHARS: usize = 32;

/// The smallest length of a base64 run that the scrubber treats as a secret.
const MIN_BASE64_CHARS: usize = 24;

fn is_delimiter(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '&' | ';'
                | ','
                | '"'
                | '\''
                | '<'
                | '>'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '|'
                | '`'
        )
}

/// Splits text into tokens and delimiters. The flag is `true` for a token.
fn pieces(text: &str) -> Vec<(&str, bool)> {
    let mut found = Vec::new();
    let mut token_start: Option<usize> = None;
    for (index, character) in text.char_indices() {
        if is_delimiter(character) {
            if let Some(start) = token_start.take() {
                found.push((text.get(start..index).unwrap_or_default(), true));
            }
            let end = index + character.len_utf8();
            found.push((text.get(index..end).unwrap_or_default(), false));
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        found.push((text.get(start..).unwrap_or_default(), true));
    }
    found
}

fn is_secret_key(key: &str) -> bool {
    let words: Vec<String> = key
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let joined = words.concat();
    if joined.is_empty() {
        return false;
    }
    KEY_CONTAINS.iter().any(|word| joined.contains(word))
        || KEY_WHOLE.contains(&joined.as_str())
        || words
            .last()
            .is_some_and(|last| KEY_LAST_WORD.contains(&last.as_str()))
}

fn is_scheme(word: &str) -> bool {
    SCHEMES
        .iter()
        .any(|scheme| word.eq_ignore_ascii_case(scheme))
}

/// Returns `true` if `text` has the shape of a credential after a scheme name.
fn looks_like_credential(text: &str) -> bool {
    let token_chars = text.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(character, '+' | '/' | '=' | '.' | '_' | '~' | '-' | ':')
    });
    let has_digit = text.chars().any(|character| character.is_ascii_digit());
    let has_upper = text.chars().any(|character| character.is_ascii_uppercase());
    let has_lower = text.chars().any(|character| character.is_ascii_lowercase());
    token_chars && text.len() >= 8 && (has_digit || (has_upper && has_lower) || text.contains('='))
}

fn is_atom_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '~' | '+' | '%')
}

fn is_secret_atom(atom: &str) -> bool {
    let has_digit = atom.chars().any(|character| character.is_ascii_digit());
    let has_letter = atom
        .chars()
        .any(|character| character.is_ascii_alphabetic());
    if atom.starts_with("eyJ") && atom.len() >= 20 && atom.matches('.').count() >= 2 {
        return true;
    }
    for (prefix, min_length) in TOKEN_PREFIXES {
        if let Some(rest) = atom.strip_prefix(prefix) {
            let mixed = rest
                .chars()
                .any(|character| character.is_ascii_digit() || character.is_ascii_uppercase());
            if atom.len() >= *min_length && mixed {
                return true;
            }
        }
    }
    !atom.contains('.') && atom.len() >= MIN_OPAQUE_CHARS && has_digit && has_letter
}

/// Replaces each atom that has the shape of a token or a key.
fn scrub_atoms(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut atom = String::new();
    let flush = |atom: &mut String, output: &mut String| {
        if atom.is_empty() {
            return;
        }
        if is_secret_atom(atom) {
            output.push_str(SECRET_MARK);
        } else {
            output.push_str(atom);
        }
        atom.clear();
    };
    for character in text.chars() {
        if is_atom_char(character) {
            atom.push(character);
        } else {
            flush(&mut atom, &mut output);
            output.push(character);
        }
    }
    flush(&mut atom, &mut output);
    output
}

/// Replaces each long base64 run that has padding or a `+`.
fn scrub_base64(text: &str) -> String {
    let is_body =
        |character: char| character.is_ascii_alphanumeric() || matches!(character, '+' | '/');
    let mut output = String::with_capacity(text.len());
    let characters: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let start = index;
        while characters.get(index).copied().is_some_and(is_body) {
            index += 1;
        }
        let body_end = index;
        while index - body_end < 2 && characters.get(index) == Some(&'=') {
            index += 1;
        }
        let run: String = characters
            .get(start..index)
            .unwrap_or_default()
            .iter()
            .collect();
        if run.is_empty() {
            if let Some(character) = characters.get(index) {
                output.push(*character);
            }
            index += 1;
            continue;
        }
        let body_length = body_end - start;
        let has_upper = run.chars().any(|character| character.is_ascii_uppercase());
        let has_lower = run.chars().any(|character| character.is_ascii_lowercase());
        let marked = run.contains('+') || index > body_end;
        if body_length >= MIN_BASE64_CHARS && has_upper && has_lower && marked {
            output.push_str(SECRET_MARK);
        } else {
            output.push_str(&run);
        }
    }
    output
}

/// Replaces the user and the password in the authority of a URL.
fn scrub_userinfo(token: &str) -> String {
    let Some((scheme, rest)) = token.split_once("://") else {
        return token.to_owned();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://{SECRET_MARK}@{host}{tail}"),
        None => token.to_owned(),
    }
}

/// What the scrubber does with the next token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    /// Examine the token in the usual way.
    None,
    /// The token before was a key name. A `:` or a `=` can follow.
    Key,
    /// The token is the value of a secret key. Replace it.
    Value,
    /// The token follows a scheme name. Replace it if it has the shape of a credential.
    Credential,
}

/// Replaces the value in each `key=value` or `key:value` part that has a secret key.
///
/// The second value says what to do with the token after this one.
fn scrub_pairs(token: &str) -> (String, Pending) {
    let mut output = String::with_capacity(token.len());
    let mut rest = token;
    loop {
        let split = rest.find(['?', '#']);
        let part = split.map_or(rest, |index| rest.get(..index).unwrap_or_default());
        let pending = scrub_pair(part, &mut output);
        match split {
            Some(index) => {
                output.push_str(rest.get(index..=index).unwrap_or_default());
                rest = rest.get(index + 1..).unwrap_or_default();
            }
            None => return (output, pending),
        }
    }
}

/// Writes one part of a token to `output`, with the value of a secret key replaced.
fn scrub_pair(part: &str, output: &mut String) -> Pending {
    let separator = part.find('=').or_else(|| {
        part.find(':')
            .filter(|index| !part.get(index + 1..).unwrap_or_default().starts_with("//"))
    });
    let Some(index) = separator else {
        output.push_str(part);
        return if is_scheme(part) {
            Pending::Credential
        } else if is_secret_key(part) {
            Pending::Key
        } else {
            Pending::None
        };
    };
    let key = part.get(..index).unwrap_or_default();
    let mark = part.get(index..=index).unwrap_or_default();
    let value = part.get(index + 1..).unwrap_or_default();
    if !is_secret_key(key) {
        output.push_str(part);
        Pending::None
    } else if value.is_empty() {
        output.push_str(part);
        Pending::Value
    } else if is_scheme(value) {
        output.push_str(part);
        Pending::Credential
    } else {
        output.push_str(key);
        output.push_str(mark);
        output.push_str(SECRET_MARK);
        Pending::None
    }
}

/// Removes each PEM block, for example a private key.
fn scrub_pem(text: &str) -> String {
    const BEGIN: &str = "-----BEGIN";
    const END: &str = "-----END";
    const DASHES: &str = "-----";
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        output.push_str(rest.get(..start).unwrap_or_default());
        output.push_str(SECRET_MARK);
        let after_begin = rest.get(start + BEGIN.len()..).unwrap_or_default();
        rest = match after_begin.find(END) {
            Some(end) => {
                let after_end = after_begin.get(end + END.len()..).unwrap_or_default();
                match after_end.find(DASHES) {
                    Some(close) => after_end.get(close + DASHES.len()..).unwrap_or_default(),
                    None => "",
                }
            }
            None => "",
        };
    }
    output.push_str(rest);
    output
}

/// Returns `text` with each part that looks like a secret replaced by [`SECRET_MARK`].
///
/// The function finds:
///
/// - the value of a key with a secret name, as `key=value`, `key: value`, or JSON;
/// - the credential after an HTTP authentication scheme, for example `Bearer`;
/// - the user and the password in a URL;
/// - JSON Web Tokens and tokens with a known prefix;
/// - long runs of letters and digits, and long base64 runs;
/// - PEM blocks.
pub(crate) fn scrub_secrets(text: &str) -> String {
    let text = scrub_pem(text);
    let mut output = String::with_capacity(text.len());
    let mut pending = Pending::None;
    for (piece, is_token) in pieces(&text) {
        if !is_token {
            output.push_str(piece);
            continue;
        }
        match pending {
            Pending::Value => {
                if is_scheme(piece) {
                    output.push_str(piece);
                    pending = Pending::Credential;
                } else {
                    output.push_str(SECRET_MARK);
                    pending = Pending::None;
                }
                continue;
            }
            Pending::Key if piece == ":" || piece == "=" => {
                output.push_str(piece);
                pending = Pending::Value;
                continue;
            }
            Pending::Credential if looks_like_credential(piece) => {
                output.push_str(SECRET_MARK);
                pending = Pending::None;
                continue;
            }
            Pending::None | Pending::Key | Pending::Credential => {}
        }
        let (pairs, next) = scrub_pairs(&scrub_userinfo(piece));
        output.push_str(&scrub_atoms(&scrub_base64(&pairs)));
        pending = next;
    }
    output
}

/// Returns a path without its query and its fragment.
///
/// The contract says that `http_path` has no query. A connector can break that rule, and
/// a query often holds a key. The function puts [`QUERY_MARK`] or [`FRAGMENT_MARK`] in
/// the place of the part that it removes.
pub(crate) fn strip_query(path: &str) -> String {
    let Some(index) = path.find(['?', '#']) else {
        return path.to_owned();
    };
    let head = path.get(..index).unwrap_or_default();
    if path.get(index..).unwrap_or_default().starts_with('?') {
        format!("{head}?{QUERY_MARK}")
    } else {
        format!("{head}#{FRAGMENT_MARK}")
    }
}

fn kept(address: IpAddr, keep: &[IpAddr]) -> bool {
    keep.contains(&address.to_canonical())
}

/// Replaces each IPv4 address in `text` that is not in `keep`.
fn scrub_v4(text: &str, keep: &[IpAddr]) -> String {
    let characters: Vec<char> = text.chars().collect();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < characters.len() {
        let start = index;
        while characters
            .get(index)
            .is_some_and(|character| character.is_ascii_digit() || *character == '.')
        {
            index += 1;
        }
        if index == start {
            if let Some(character) = characters.get(index) {
                output.push(*character);
            }
            index += 1;
            continue;
        }
        let run: String = characters
            .get(start..index)
            .unwrap_or_default()
            .iter()
            .collect();
        let candidate = run.trim_end_matches('.');
        let trailing = run.get(candidate.len()..).unwrap_or_default();
        let before = start
            .checked_sub(1)
            .and_then(|position| characters.get(position));
        let after = characters.get(index);
        let in_word = before.is_some_and(|character| character.is_alphanumeric())
            || (trailing.is_empty() && after.is_some_and(|character| character.is_alphanumeric()));
        match candidate.parse::<Ipv4Addr>() {
            Ok(address) if !in_word && !kept(IpAddr::V4(address), keep) => {
                output.push_str(ADDRESS_MARK);
                output.push_str(trailing);
            }
            _ => output.push_str(&run),
        }
    }
    output
}

/// Returns `text` with each IP address that is not in `keep` replaced by [`ADDRESS_MARK`].
///
/// Do not use this function for a user agent. A browser version such as `120.0.0.0` has
/// the form of an IPv4 address.
pub(crate) fn scrub_addresses(text: &str, keep: &[IpAddr]) -> String {
    let mut output = String::with_capacity(text.len());
    for (piece, is_token) in pieces(text) {
        if !is_token {
            output.push_str(piece);
            continue;
        }
        let candidate = piece.trim_end_matches(['.', ':']);
        let trailing = piece.get(candidate.len()..).unwrap_or_default();
        let without_zone = candidate.split('%').next().unwrap_or(candidate);
        if candidate.matches(':').count() >= 2
            && let Ok(address) = without_zone.parse::<Ipv6Addr>()
        {
            if kept(IpAddr::V6(address), keep) {
                output.push_str(piece);
            } else {
                output.push_str(ADDRESS_MARK);
                output.push_str(trailing);
            }
            continue;
        }
        output.push_str(&scrub_v4(piece, keep));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_of_a_secret_key_is_replaced_in_each_form() {
        let cases = [
            ("password=hunter2", "password=[secret removed]"),
            (
                "/login?user=bob&password=hunter2&next=/home",
                "/login?user=bob&password=[secret removed]&next=/home",
            ),
            (
                "/cb?code=4/0AbCd&state=xyz",
                "/cb?code=[secret removed]&state=xyz",
            ),
            ("api_key=abc123 other", "api_key=[secret removed] other"),
            ("X-Api-Key: abc123", "X-Api-Key: [secret removed]"),
            ("client_secret:s3cr3t", "client_secret:[secret removed]"),
            (
                r#"{"password": "hunter2", "user": "bob"}"#,
                r#"{"password": "[secret removed]", "user": "bob"}"#,
            ),
            (r#"{"token":"abc"}"#, r#"{"token":"[secret removed]"}"#),
            ("pwd = x1", "pwd = [secret removed]"),
            ("sig=abc&se=2026", "sig=[secret removed]&se=2026"),
        ];
        assert_eq!(cases.len(), 10);
        for (input, expected) in cases {
            assert_eq!(scrub_secrets(input), expected, "{input}");
        }
    }

    #[test]
    fn the_credential_after_a_scheme_is_replaced() {
        assert_eq!(
            scrub_secrets("Authorization: Bearer abc.DEF-123_xyz"),
            "Authorization: Bearer [secret removed]"
        );
        assert_eq!(
            scrub_secrets("Authorization: Basic dXNlcjpwYXNz"),
            "Authorization: Basic [secret removed]"
        );
        assert_eq!(
            scrub_secrets("authorization:Bearer AbCdEf123456"),
            "authorization:Bearer [secret removed]"
        );
        assert_eq!(
            scrub_secrets("bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
            "bearer [secret removed]"
        );
        // A scheme name in plain text does not remove the next word.
        assert_eq!(
            scrub_secrets("Basic authentication failed"),
            "Basic authentication failed"
        );
    }

    #[test]
    fn a_url_loses_its_user_and_password() {
        assert_eq!(
            scrub_secrets("https://bob:hunter2@host.example/path"),
            "https://[secret removed]@host.example/path"
        );
        assert_eq!(
            scrub_secrets("see ftp://anonymous@files.example now"),
            "see ftp://[secret removed]@files.example now"
        );
        assert_eq!(
            scrub_secrets("https://host.example/a@b"),
            "https://host.example/a@b"
        );
    }

    #[test]
    fn tokens_with_a_known_shape_are_replaced() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        assert_eq!(scrub_secrets(jwt), SECRET_MARK);
        assert_eq!(
            scrub_secrets(&format!("/v1/x/{jwt}/y")),
            "/v1/x/[secret removed]/y"
        );
        let cases = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijABCDEFGHIJ012345",
            "github_pat_11ABCDEFG0aBcDeFgHiJkL",
            "xoxb-1234567890-abcdefghij",
            "sk-proj-0123456789abcdefghijklmnop",
            "sk_live_0123456789abcdef",
            "AIzaSyA0123456789abcdefghijklmnopqrstuv",
            "0123456789abcdef0123456789abcdef",
            "550e8400-e29b-41d4-a716-446655440000",
        ];
        assert_eq!(cases.len(), 9);
        for token in cases {
            assert_eq!(scrub_secrets(token), SECRET_MARK, "{token}");
            assert_eq!(
                scrub_secrets(&format!("GET /files/{token} done")),
                "GET /files/[secret removed] done",
                "{token}"
            );
        }
    }

    #[test]
    fn base64_with_padding_or_a_plus_is_replaced() {
        assert_eq!(
            scrub_secrets("blob QWxhZGRpbjpvcGVuIHNlc2FtZQ/x+yzAbCd== end"),
            "blob [secret removed] end"
        );
        assert_eq!(
            scrub_secrets("x=QWxhZGRpbjpvcGVuIHNlc2FtZQab="),
            "x=[secret removed]"
        );
    }

    #[test]
    fn a_pem_block_is_replaced() {
        let text =
            "before -----BEGIN PRIVATE KEY-----\nMIIEvQ\nAbCd\n-----END PRIVATE KEY----- after";
        assert_eq!(scrub_secrets(text), "before [secret removed] after");
        assert_eq!(
            scrub_secrets("x -----BEGIN RSA PRIVATE KEY----- MIIE no end"),
            "x [secret removed]"
        );
    }

    #[test]
    fn usual_text_stays_as_it_is() {
        let cases = [
            "python-httpx/0.27.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Invalid username or password.",
            "GET /users",
            "GET /servicePrincipals",
            "/admin/login.php",
            "/api/v1/users/list/of/things/2024/reports/summary/page",
            "The token is not valid for this resource",
            "error_code=50126",
            "curl/8.4.0",
            "sk-learn-contrib-packages",
            "https://example.org/a/b?page=2",
            "SecretGet",
            "10:31:00 sign-in from Bucharest",
        ];
        assert_eq!(cases.len(), 14);
        for text in cases {
            assert_eq!(scrub_secrets(text), text);
        }
    }

    #[test]
    fn a_path_loses_its_query_and_its_fragment() {
        assert_eq!(strip_query("/login"), "/login");
        assert_eq!(strip_query("/login?next=/home"), "/login?[query removed]");
        assert_eq!(strip_query("/a#frag"), "/a#[fragment removed]");
        assert_eq!(strip_query("/a?q=1#frag"), "/a?[query removed]");
        assert_eq!(strip_query("/a#frag?q=1"), "/a#[fragment removed]");
        assert_eq!(strip_query("?x"), "?[query removed]");
    }

    #[test]
    fn other_addresses_are_replaced_and_kept_addresses_stay() {
        let keep: Vec<IpAddr> = vec![
            "203.0.113.50".parse().unwrap(),
            "2001:db8::5".parse().unwrap(),
        ];
        assert_eq!(
            scrub_addresses("from 203.0.113.50 to 10.1.2.3:443.", &keep),
            "from 203.0.113.50 to [address removed]:443."
        );
        assert_eq!(
            scrub_addresses("host=198.51.100.7, next", &keep),
            "host=[address removed], next"
        );
        assert_eq!(
            scrub_addresses("[2001:db8::5]:443 and [fd00::1]:80 and fe80::1%eth0", &keep),
            "[2001:db8::5]:443 and [[address removed]]:80 and [address removed]"
        );
        assert_eq!(
            scrub_addresses("::ffff:203.0.113.50 is kept", &keep),
            "::ffff:203.0.113.50 is kept"
        );
        // A version number in a word and a short number are not addresses.
        assert_eq!(
            scrub_addresses("v1.2.3.4 and 10.0 and 1.2.3", &keep),
            "v1.2.3.4 and 10.0 and 1.2.3"
        );
        assert_eq!(scrub_addresses("no address here", &keep), "no address here");
    }
}
