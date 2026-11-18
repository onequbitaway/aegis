//! The secret seed and the deterministic generator that makes decoy content.
//!
//! All generated content comes from the seed and from public input, for example a path.
//! The same seed and the same input always give the same content. A client that does not
//! know the seed cannot predict the content or make a valid canary path.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The smallest number of bytes in a seed.
pub(crate) const MIN_SEED_BYTES: usize = 32;
/// The largest number of bytes in a seed.
pub(crate) const MAX_SEED_BYTES: usize = 1024;

/// The secret seed of one decoy. The `Debug` output does not show the seed.
#[derive(Clone)]
pub(crate) struct Seed {
    mac: Hmac<Sha256>,
}

impl fmt::Debug for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Seed([REDACTED])")
    }
}

impl Seed {
    /// Makes a seed from secret bytes. Returns `None` if the length is out of range.
    pub(crate) fn new(secret: &[u8]) -> Option<Self> {
        if !(MIN_SEED_BYTES..=MAX_SEED_BYTES).contains(&secret.len()) {
            return None;
        }
        let mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
        Some(Self { mac })
    }

    /// Returns 32 bytes that depend on the seed, the `domain`, and each part.
    ///
    /// The function writes the length before each part. Thus two different lists of parts
    /// never give the same input.
    pub(crate) fn derive(&self, domain: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = self.mac.clone();
        update_with_length(&mut mac, domain.as_bytes());
        for part in parts {
            update_with_length(&mut mac, part);
        }
        mac.finalize().into_bytes().into()
    }

    /// Returns [`derive`](Self::derive) as lower-case hexadecimal text of `length` digits.
    ///
    /// The result has 64 digits at most.
    pub(crate) fn derive_hex(&self, domain: &str, parts: &[&[u8]], length: usize) -> String {
        let mut text = hex::encode(self.derive(domain, parts));
        text.truncate(length);
        text
    }

    /// Returns a generator of bytes that depend on the seed, the `domain`, and each part.
    pub(crate) fn generator(&self, domain: &str, parts: &[&[u8]]) -> Generator {
        Generator {
            key: self.derive(domain, parts),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }
}

fn update_with_length(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    mac.update(&length.to_be_bytes());
    mac.update(bytes);
}

/// A deterministic source of bytes for generated content.
///
/// The generator selects words for decoy text. It is not a source of secrets.
#[derive(Clone)]
pub(crate) struct Generator {
    key: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl Generator {
    fn next_byte(&mut self) -> u8 {
        if self.used >= self.block.len() {
            let mut digest = Sha256::new();
            digest.update(self.key);
            digest.update(self.counter.to_be_bytes());
            self.block = digest.finalize().into();
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let byte = self.block.get(self.used).copied().unwrap_or_default();
        self.used += 1;
        byte
    }

    /// Returns the next 32 bits.
    pub(crate) fn next_u32(&mut self) -> u32 {
        u32::from_be_bytes([
            self.next_byte(),
            self.next_byte(),
            self.next_byte(),
            self.next_byte(),
        ])
    }

    /// Returns a number from 0 to `limit - 1`. Returns 0 if `limit` is 0.
    pub(crate) fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let value = usize::try_from(self.next_u32()).unwrap_or(usize::MAX);
        value % limit
    }

    /// Selects one word of `words`. Returns the empty text if `words` is empty.
    pub(crate) fn word(&mut self, words: &[&'static str]) -> &'static str {
        let index = self.below(words.len());
        words.get(index).copied().unwrap_or("")
    }

    /// Returns `digits` lower-case hexadecimal digits.
    pub(crate) fn hex(&mut self, digits: usize) -> String {
        let mut bytes = Vec::with_capacity(digits.div_ceil(2));
        for _ in 0..digits.div_ceil(2) {
            bytes.push(self.next_byte());
        }
        let mut text = hex::encode(bytes);
        text.truncate(digits);
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &[u8] = b"seed-a-0123456789abcdef0123456789abcdef";
    const SECRET_B: &[u8] = b"seed-b-0123456789abcdef0123456789abcdef";

    fn seed(secret: &[u8]) -> Seed {
        Seed::new(secret).unwrap()
    }

    #[test]
    fn a_seed_needs_32_to_1024_bytes() {
        assert!(Seed::new(&[7; MIN_SEED_BYTES - 1]).is_none());
        assert!(Seed::new(&[7; MIN_SEED_BYTES]).is_some());
        assert!(Seed::new(&[7; MAX_SEED_BYTES]).is_some());
        assert!(Seed::new(&[7; MAX_SEED_BYTES + 1]).is_none());
        assert!(Seed::new(b"").is_none());
    }

    #[test]
    fn the_debug_output_does_not_show_the_seed() {
        assert_eq!(format!("{:?}", seed(SECRET_A)), "Seed([REDACTED])");
    }

    #[test]
    fn the_same_seed_and_input_give_the_same_bytes() {
        let first = seed(SECRET_A).derive("page", &[b"/docs/a"]);
        let second = seed(SECRET_A).derive("page", &[b"/docs/a"]);
        assert_eq!(first, second);
        // The value is HMAC-SHA256 over the length-prefixed domain and parts.
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET_A).unwrap();
        mac.update(&4_u64.to_be_bytes());
        mac.update(b"page");
        mac.update(&7_u64.to_be_bytes());
        mac.update(b"/docs/a");
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(first, expected);
    }

    #[test]
    fn a_different_seed_domain_or_part_gives_different_bytes() {
        let base = seed(SECRET_A).derive("page", &[b"/docs/a"]);
        assert_ne!(base, seed(SECRET_B).derive("page", &[b"/docs/a"]));
        assert_ne!(base, seed(SECRET_A).derive("link", &[b"/docs/a"]));
        assert_ne!(base, seed(SECRET_A).derive("page", &[b"/docs/b"]));
    }

    #[test]
    fn the_part_borders_change_the_result() {
        let seed = seed(SECRET_A);
        assert_ne!(
            seed.derive("x", &[b"ab", b"c"]),
            seed.derive("x", &[b"a", b"bc"])
        );
        assert_ne!(
            seed.derive("x", &[b"abc"]),
            seed.derive("x", &[b"abc", b""])
        );
    }

    #[test]
    fn the_hexadecimal_form_has_the_requested_length() {
        let seed = seed(SECRET_A);
        let full = seed.derive_hex("x", &[b"a"], 64);
        assert_eq!(full, hex::encode(seed.derive("x", &[b"a"])));
        assert_eq!(seed.derive_hex("x", &[b"a"], 16), full[..16]);
        assert_eq!(seed.derive_hex("x", &[b"a"], 200).len(), 64);
    }

    #[test]
    fn a_generator_repeats_its_sequence_for_the_same_input() {
        let mut first = seed(SECRET_A).generator("text", &[b"/a"]);
        let mut second = seed(SECRET_A).generator("text", &[b"/a"]);
        let mut other = seed(SECRET_A).generator("text", &[b"/b"]);
        let first_values: Vec<u32> = (0..40).map(|_| first.next_u32()).collect();
        let second_values: Vec<u32> = (0..40).map(|_| second.next_u32()).collect();
        let other_values: Vec<u32> = (0..40).map(|_| other.next_u32()).collect();
        assert_eq!(first_values, second_values);
        assert_ne!(first_values, other_values);
        // 40 values use 160 bytes, which is five blocks. The blocks are different.
        assert_ne!(first_values[..8], first_values[8..16]);
    }

    #[test]
    fn a_generator_stays_in_the_requested_range() {
        let mut generator = seed(SECRET_A).generator("range", &[]);
        assert_eq!(generator.below(0), 0);
        assert_eq!(generator.below(1), 0);
        let values: Vec<usize> = (0..500).map(|_| generator.below(7)).collect();
        assert!(values.iter().all(|value| *value < 7));
        for expected in 0..7 {
            assert!(values.contains(&expected), "{expected} is missing");
        }
    }

    #[test]
    fn a_generator_selects_words_and_makes_hexadecimal_text() {
        let mut generator = seed(SECRET_A).generator("words", &[]);
        assert_eq!(generator.word(&[]), "");
        assert_eq!(generator.word(&["only"]), "only");
        let word = generator.word(&["a", "b", "c"]);
        assert!(["a", "b", "c"].contains(&word));
        let text = generator.hex(9);
        assert_eq!(text.len(), 9);
        assert!(
            text.chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
        assert_eq!(generator.hex(0), "");
    }
}
