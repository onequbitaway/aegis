//! ATT&CK techniques in the documents.
//!
//! A detection carries technique data as text. A model can write that text. The
//! documents thus keep only what the code can check: the technique identifier and the
//! tactic. A technique name stays only if it comes from a deterministic rule and has
//! plain characters.

use std::collections::BTreeMap;

use aegis_contracts::detection::{AttackTechnique, DetectionTier};
use serde::{Deserialize, Serialize};

/// The enterprise tactics of ATT&CK, as a kill chain phase names them.
pub(crate) const TACTICS: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

/// The largest number of characters of a technique name.
const MAX_NAME_CHARS: usize = 80;

/// One ATT&CK technique in a document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Technique {
    /// The technique identifier, for example `T1110.003`.
    pub id: String,
    /// The name of the technique, if a deterministic rule gives a plain name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The tactics, in order, for example `credential-access`.
    pub tactics: Vec<String>,
    /// The page of the technique on the ATT&CK site.
    pub url: String,
}

/// Returns the technique identifier in its usual form, or `None` if `text` is not one.
///
/// The form is `T`, four digits, and optionally a full stop and three digits.
pub(crate) fn technique_id(text: &str) -> Option<String> {
    let text = text.trim();
    let rest = text.strip_prefix(['T', 't'])?;
    let (main, sub) = match rest.split_once('.') {
        Some((main, sub)) => (main, Some(sub)),
        None => (rest, None),
    };
    let digits = |part: &str, length: usize| {
        part.len() == length && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !digits(main, 4) || !sub.is_none_or(|sub| digits(sub, 3)) {
        return None;
    }
    Some(format!("T{rest}"))
}

/// Returns the tactic if it is an enterprise tactic of ATT&CK.
pub(crate) fn tactic(text: &str) -> Option<&'static str> {
    let text = text.trim();
    TACTICS
        .iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(text))
}

/// Returns the page of a technique on the ATT&CK site. `id` must be a valid identifier.
pub(crate) fn technique_url(id: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        id.replace('.', "/")
    )
}

fn plain_name(text: &str) -> Option<String> {
    let name = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let plain = name.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '-' | '/' | '(' | ')' | ',' | '.' | '&' | '\''
            )
    });
    (plain && !name.is_empty() && name.chars().count() <= MAX_NAME_CHARS).then_some(name)
}

/// Collects techniques with no duplicates, in the order of the identifiers.
#[derive(Debug, Default)]
pub(crate) struct TechniqueSet {
    found: BTreeMap<String, Technique>,
}

impl TechniqueSet {
    /// Adds one technique of a detection. A technique with no valid identifier is ignored.
    ///
    /// `redact` masks the values of the operator in a name. A name that changes is not
    /// kept.
    pub(crate) fn add(
        &mut self,
        technique: &AttackTechnique,
        tier: DetectionTier,
        redact: impl Fn(&str) -> String,
    ) {
        let Some(id) = technique_id(&technique.technique_id) else {
            return;
        };
        let name = (tier == DetectionTier::Deterministic)
            .then(|| plain_name(&technique.name))
            .flatten()
            .filter(|name| redact(name) == *name);
        let entry = self.found.entry(id.clone()).or_insert_with(|| Technique {
            url: technique_url(&id),
            id,
            name: None,
            tactics: Vec::new(),
        });
        if entry.name.is_none() {
            entry.name = name;
        }
        if let Some(tactic) = tactic(&technique.tactic)
            && !entry.tactics.iter().any(|known| known == tactic)
        {
            entry.tactics.push(tactic.to_owned());
            entry.tactics.sort_unstable();
        }
    }

    /// Adds all techniques of `other`.
    pub(crate) fn merge(&mut self, other: &[Technique]) {
        for technique in other {
            let entry = self
                .found
                .entry(technique.id.clone())
                .or_insert_with(|| Technique {
                    id: technique.id.clone(),
                    name: None,
                    tactics: Vec::new(),
                    url: technique.url.clone(),
                });
            if entry.name.is_none() {
                entry.name.clone_from(&technique.name);
            }
            for tactic in &technique.tactics {
                if !entry.tactics.contains(tactic) {
                    entry.tactics.push(tactic.clone());
                }
            }
            entry.tactics.sort_unstable();
        }
    }

    /// Returns the techniques, in the order of the identifiers.
    pub(crate) fn into_vec(self) -> Vec<Technique> {
        self.found.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(text: &str) -> String {
        text.to_owned()
    }

    #[test]
    fn a_technique_identifier_must_have_the_attack_form() {
        assert_eq!(technique_id("T1110"), Some("T1110".to_owned()));
        assert_eq!(technique_id("T1110.003"), Some("T1110.003".to_owned()));
        assert_eq!(technique_id(" t1098.001 "), Some("T1098.001".to_owned()));
        for bad in [
            "",
            "T",
            "1110",
            "T111",
            "T11100",
            "T1110.3",
            "T1110.0033",
            "T1110.",
            "TA0006",
            "T1110 by APT29",
            "T1110.003\n# x",
            "T１１１０",
        ] {
            assert_eq!(technique_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_enterprise_tactics_are_tactics() {
        assert_eq!(tactic("credential-access"), Some("credential-access"));
        assert_eq!(tactic(" Initial-Access "), Some("initial-access"));
        assert_eq!(tactic("unknown"), None);
        assert_eq!(tactic("credential access"), None);
        assert_eq!(tactic("the group APT29"), None);
        assert_eq!(TACTICS.len(), 14);
    }

    #[test]
    fn the_url_has_the_sub_technique_as_a_path_part() {
        assert_eq!(
            technique_url("T1110.003"),
            "https://attack.mitre.org/techniques/T1110/003/"
        );
        assert_eq!(
            technique_url("T1528"),
            "https://attack.mitre.org/techniques/T1528/"
        );
    }

    #[test]
    fn a_deterministic_rule_gives_the_name_and_a_model_does_not() {
        let technique = AttackTechnique::new("credential-access", "T1110.003", "Password Spraying");
        let mut rule = TechniqueSet::default();
        rule.add(&technique, DetectionTier::Deterministic, same);
        assert_eq!(
            rule.into_vec(),
            [Technique {
                id: "T1110.003".to_owned(),
                name: Some("Password Spraying".to_owned()),
                tactics: vec!["credential-access".to_owned()],
                url: "https://attack.mitre.org/techniques/T1110/003/".to_owned(),
            }]
        );

        let mut model = TechniqueSet::default();
        model.add(&technique, DetectionTier::Llm, same);
        let found = model.into_vec();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "T1110.003");
        assert_eq!(found[0].name, None);
    }

    #[test]
    fn a_name_with_markup_or_a_masked_value_is_not_kept() {
        let mut set = TechniqueSet::default();
        set.add(
            &AttackTechnique::new("impact", "T1485", "Data <b>Destruction</b>"),
            DetectionTier::Deterministic,
            same,
        );
        set.add(
            &AttackTechnique::new("impact", "T1486", "Encrypt contoso data"),
            DetectionTier::Deterministic,
            |text| text.replace("contoso", "[masked]"),
        );
        set.add(
            &AttackTechnique::new("impact", "T1489", "long ".repeat(30)),
            DetectionTier::Deterministic,
            same,
        );
        set.add(
            &AttackTechnique::new("impact", "T1490", "Line\nbreak  and   spaces"),
            DetectionTier::Deterministic,
            same,
        );
        let found = set.into_vec();
        assert_eq!(found.len(), 4);
        assert_eq!(found[0].name, None);
        assert_eq!(found[1].name, None);
        assert_eq!(found[2].name, None);
        assert_eq!(found[3].name.as_deref(), Some("Line break and spaces"));
    }

    #[test]
    fn techniques_merge_by_identifier_and_come_in_order() {
        let mut set = TechniqueSet::default();
        set.add(
            &AttackTechnique::new("persistence", "T1078", "Valid Accounts"),
            DetectionTier::Deterministic,
            same,
        );
        set.add(
            &AttackTechnique::new("initial-access", "T1078", "Valid Accounts"),
            DetectionTier::Llm,
            same,
        );
        set.add(
            &AttackTechnique::new("unknown", "T1041", "Exfiltration Over C2 Channel"),
            DetectionTier::Deterministic,
            same,
        );
        set.add(
            &AttackTechnique::new("impact", "not a technique", "Text"),
            DetectionTier::Deterministic,
            same,
        );
        let found = set.into_vec();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].id, "T1041");
        assert!(found[0].tactics.is_empty());
        assert_eq!(found[1].id, "T1078");
        assert_eq!(found[1].tactics, ["initial-access", "persistence"]);
        assert_eq!(found[1].name.as_deref(), Some("Valid Accounts"));

        let mut merged = TechniqueSet::default();
        merged.merge(&found);
        merged.merge(&found);
        assert_eq!(merged.into_vec(), found);
    }
}
