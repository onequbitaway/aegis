//! The vocabulary of the generated decoy text.
//!
//! The words are common business words. The generated text names no real organization,
//! person, system, address, or credential.

use std::collections::VecDeque;

use crate::seed::Generator;

pub(crate) const SECTIONS: &[&str] = &[
    "runbooks", "services", "teams", "releases", "platform", "billing", "storage", "network",
    "reports", "archive", "guides", "policies",
];

pub(crate) const ADJECTIVES: &[&str] = &[
    "regional",
    "internal",
    "legacy",
    "primary",
    "shared",
    "nightly",
    "staging",
    "central",
    "managed",
    "partner",
    "quarterly",
    "archived",
    "interim",
    "standard",
];

pub(crate) const NOUNS: &[&str] = &[
    "ledger",
    "gateway",
    "scheduler",
    "inventory",
    "pipeline",
    "directory",
    "catalog",
    "registry",
    "exporter",
    "console",
    "queue",
    "cache",
    "mirror",
    "broker",
    "planner",
    "indexer",
];

pub(crate) const DOCUMENTS: &[&str] = &[
    "runbook",
    "overview",
    "checklist",
    "handover",
    "notes",
    "schedule",
    "summary",
    "procedure",
];

pub(crate) const COLLECTIONS: &[&str] = &[
    "accounts",
    "invoices",
    "devices",
    "tickets",
    "projects",
    "contracts",
    "shipments",
    "records",
    "assets",
    "orders",
];

pub(crate) const REGIONS: &[&str] = &["north", "south", "east", "west", "central"];

pub(crate) const STATES: &[&str] = &["active", "pending", "archived", "review"];

/// The number of sentence forms for pages.
const PAGE_SENTENCES: usize = 8;
/// The number of sentence forms for model answers.
const ANSWER_SENTENCES: usize = 8;

/// Returns `word` with an upper-case first letter.
pub(crate) fn capitalized(word: &str) -> String {
    let mut characters = word.chars();
    match characters.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + characters.as_str(),
        None => String::new(),
    }
}

/// Makes the title of a generated page, for example `Regional ledger runbook`.
pub(crate) fn title(generator: &mut Generator) -> String {
    format!(
        "{} {} {}",
        capitalized(generator.word(ADJECTIVES)),
        generator.word(NOUNS),
        generator.word(DOCUMENTS)
    )
}

/// Makes one sentence for a generated page.
pub(crate) fn page_sentence(generator: &mut Generator) -> String {
    let adjective = generator.word(ADJECTIVES);
    let noun = generator.word(NOUNS);
    let other = generator.word(NOUNS);
    let document = generator.word(DOCUMENTS);
    let section = generator.word(SECTIONS);
    match generator.below(PAGE_SENTENCES) {
        0 => format!("The {adjective} {noun} team reviews this {document} each quarter."),
        1 => format!("Use the {noun} {document} before a change to the {adjective} {other}."),
        2 => format!("The {noun} moves records to the {adjective} {other} in the nightly window."),
        3 => format!("Ask the owner of the {adjective} {noun} for access to this section."),
        4 => format!("This page replaces the earlier {document} for the {noun}."),
        5 => format!("Status reports for the {adjective} {noun} are in the {section} section."),
        6 => format!("The {document} lists each step for the {adjective} {noun} and the {other}."),
        _ => format!("A change to the {noun} needs a note in the {section} {document}."),
    }
}

/// Makes one sentence for the answer of the decoy model API.
///
/// The sentences are filler. They give no data, no code, and no instruction.
pub(crate) fn answer_sentence(generator: &mut Generator) -> String {
    let adjective = generator.word(ADJECTIVES);
    let noun = generator.word(NOUNS);
    let other = generator.word(NOUNS);
    let document = generator.word(DOCUMENTS);
    match generator.below(ANSWER_SENTENCES) {
        0 => "The request is in review.".to_owned(),
        1 => format!("A complete answer needs more context about the {adjective} {noun}."),
        2 => format!("The first pass covers the {noun} and the {adjective} {other}."),
        3 => format!("This step made no change to the {noun}."),
        4 => format!("The next step is a check of the {adjective} {document}."),
        5 => format!("The summary of the {noun} follows in the next section."),
        6 => format!("The {adjective} {noun} report is not ready at this time."),
        _ => format!("The {document} for the {noun} is not complete at this time."),
    }
}

/// An endless sequence of filler words for a model answer.
pub(crate) struct Filler {
    generator: Generator,
    pending: VecDeque<String>,
}

impl Filler {
    pub(crate) fn new(generator: Generator) -> Self {
        Self {
            generator,
            pending: VecDeque::new(),
        }
    }

    /// Returns the next word.
    pub(crate) fn next_word(&mut self) -> String {
        loop {
            if let Some(word) = self.pending.pop_front() {
                return word;
            }
            let sentence = answer_sentence(&mut self.generator);
            self.pending
                .extend(sentence.split_whitespace().map(str::to_owned));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;

    fn generator(part: &[u8]) -> Generator {
        Seed::new(b"seed-a-0123456789abcdef0123456789abcdef")
            .unwrap()
            .generator("words", &[part])
    }

    fn is_plain(text: &str) -> bool {
        text.chars()
            .all(|character| character.is_ascii_alphabetic() || matches!(character, ' ' | '.'))
    }

    #[test]
    fn each_word_list_has_only_lower_case_letters_and_no_word_two_times() {
        for list in [
            SECTIONS,
            ADJECTIVES,
            NOUNS,
            DOCUMENTS,
            COLLECTIONS,
            REGIONS,
            STATES,
        ] {
            assert!(!list.is_empty());
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), list.len());
            for word in list {
                assert!(
                    !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase()),
                    "{word}"
                );
            }
        }
    }

    #[test]
    fn a_title_has_three_words_and_a_capital_first_letter() {
        let title = title(&mut generator(b"a"));
        assert_eq!(title.split(' ').count(), 3);
        assert!(title.chars().next().unwrap().is_ascii_uppercase());
        assert!(is_plain(&title), "{title}");
        assert_eq!(capitalized("ledger"), "Ledger");
        assert_eq!(capitalized(""), "");
    }

    #[test]
    fn each_sentence_form_is_plain_text_that_ends_with_a_full_stop() {
        let mut generator = generator(b"sentences");
        let mut page_forms = std::collections::BTreeSet::new();
        let mut answer_forms = std::collections::BTreeSet::new();
        for _ in 0..400 {
            let page = page_sentence(&mut generator);
            let answer = answer_sentence(&mut generator);
            for sentence in [&page, &answer] {
                assert!(is_plain(sentence), "{sentence}");
                assert!(sentence.ends_with('.'), "{sentence}");
                assert!(sentence.chars().next().unwrap().is_ascii_uppercase());
            }
            page_forms.insert(page.split(' ').take(2).collect::<Vec<_>>().join(" "));
            answer_forms.insert(answer.split(' ').count());
        }
        // 400 draws reach all forms.
        assert!(page_forms.len() >= PAGE_SENTENCES - 2, "{page_forms:?}");
        assert!(answer_forms.len() >= 4, "{answer_forms:?}");
    }

    #[test]
    fn the_filler_gives_the_words_of_its_sentences_in_order() {
        let mut filler = Filler::new(generator(b"filler"));
        let words: Vec<String> = (0..60).map(|_| filler.next_word()).collect();
        let mut expected_generator = generator(b"filler");
        let mut expected = Vec::new();
        while expected.len() < 60 {
            let sentence = answer_sentence(&mut expected_generator);
            expected.extend(sentence.split_whitespace().map(str::to_owned));
        }
        expected.truncate(60);
        assert_eq!(words, expected);
        assert!(
            words
                .iter()
                .all(|word| !word.is_empty() && !word.contains(' '))
        );
    }
}
