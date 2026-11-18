//! MITRE ATT&CK names for rule tags.
//!
//! A Sigma rule and an indicator carry tags such as `attack.t1110.003` and
//! `attack.credential-access`. This module converts the tags to
//! [`AttackTechnique`] values.

use aegis_contracts::AttackTechnique;

/// The tactic that a technique gets when no tag and no catalog entry gives one.
pub const UNKNOWN_TACTIC: &str = "unknown";

const TACTICS: &[&str] = &[
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

struct Entry {
    id: &'static str,
    name: &'static str,
    /// The tactics of the technique. The first tactic is the default.
    tactics: &'static [&'static str],
}

const VALID_ACCOUNTS: &[&str] = &[
    "initial-access",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
];
const ACCOUNT_MANIPULATION: &[&str] = &["persistence", "privilege-escalation"];
const CREDENTIAL_ACCESS: &[&str] = &["credential-access"];
const MODIFY_AUTHENTICATION: &[&str] = &["credential-access", "defense-evasion", "persistence"];
const ALTERNATE_AUTHENTICATION: &[&str] = &["defense-evasion", "lateral-movement"];
const POLICY_MODIFICATION: &[&str] = &["defense-evasion", "privilege-escalation"];
const ELEVATION_CONTROL: &[&str] = &["privilege-escalation", "defense-evasion"];
const PERSISTENCE: &[&str] = &["persistence"];
const DISCOVERY: &[&str] = &["discovery"];
const INITIAL_ACCESS: &[&str] = &["initial-access"];
const COMMAND_AND_CONTROL: &[&str] = &["command-and-control"];
const COLLECTION: &[&str] = &["collection"];
const EXFILTRATION: &[&str] = &["exfiltration"];
const EXECUTION: &[&str] = &["execution"];
const RECONNAISSANCE: &[&str] = &["reconnaissance"];

/// The techniques that the catalog knows. Keep the list in order of identifier.
const CATALOG: &[Entry] = &[
    entry("T1041", "Exfiltration Over C2 Channel", EXFILTRATION),
    entry("T1059", "Command and Scripting Interpreter", EXECUTION),
    entry("T1059.009", "Cloud API", EXECUTION),
    entry("T1069", "Permission Groups Discovery", DISCOVERY),
    entry("T1069.003", "Cloud Groups", DISCOVERY),
    entry("T1071", "Application Layer Protocol", COMMAND_AND_CONTROL),
    entry("T1071.001", "Web Protocols", COMMAND_AND_CONTROL),
    entry("T1071.004", "DNS", COMMAND_AND_CONTROL),
    entry("T1078", "Valid Accounts", VALID_ACCOUNTS),
    entry("T1078.001", "Default Accounts", VALID_ACCOUNTS),
    entry("T1078.002", "Domain Accounts", VALID_ACCOUNTS),
    entry("T1078.003", "Local Accounts", VALID_ACCOUNTS),
    entry("T1078.004", "Cloud Accounts", VALID_ACCOUNTS),
    entry("T1087", "Account Discovery", DISCOVERY),
    entry("T1087.004", "Cloud Account", DISCOVERY),
    entry("T1090", "Proxy", COMMAND_AND_CONTROL),
    entry("T1090.003", "Multi-hop Proxy", COMMAND_AND_CONTROL),
    entry("T1098", "Account Manipulation", ACCOUNT_MANIPULATION),
    entry(
        "T1098.001",
        "Additional Cloud Credentials",
        ACCOUNT_MANIPULATION,
    ),
    entry(
        "T1098.002",
        "Additional Email Delegate Permissions",
        ACCOUNT_MANIPULATION,
    ),
    entry("T1098.003", "Additional Cloud Roles", ACCOUNT_MANIPULATION),
    entry("T1098.005", "Device Registration", ACCOUNT_MANIPULATION),
    entry("T1110", "Brute Force", CREDENTIAL_ACCESS),
    entry("T1110.001", "Password Guessing", CREDENTIAL_ACCESS),
    entry("T1110.002", "Password Cracking", CREDENTIAL_ACCESS),
    entry("T1110.003", "Password Spraying", CREDENTIAL_ACCESS),
    entry("T1110.004", "Credential Stuffing", CREDENTIAL_ACCESS),
    entry("T1114", "Email Collection", COLLECTION),
    entry("T1114.002", "Remote Email Collection", COLLECTION),
    entry("T1114.003", "Email Forwarding Rule", COLLECTION),
    entry(
        "T1133",
        "External Remote Services",
        &["persistence", "initial-access"],
    ),
    entry("T1136", "Create Account", PERSISTENCE),
    entry("T1136.003", "Cloud Account", PERSISTENCE),
    entry("T1190", "Exploit Public-Facing Application", INITIAL_ACCESS),
    entry("T1199", "Trusted Relationship", INITIAL_ACCESS),
    entry(
        "T1484",
        "Domain or Tenant Policy Modification",
        POLICY_MODIFICATION,
    ),
    entry("T1484.002", "Trust Modification", POLICY_MODIFICATION),
    entry("T1526", "Cloud Service Discovery", DISCOVERY),
    entry("T1528", "Steal Application Access Token", CREDENTIAL_ACCESS),
    entry("T1530", "Data from Cloud Storage", COLLECTION),
    entry("T1531", "Account Access Removal", &["impact"]),
    entry("T1539", "Steal Web Session Cookie", CREDENTIAL_ACCESS),
    entry(
        "T1548",
        "Abuse Elevation Control Mechanism",
        ELEVATION_CONTROL,
    ),
    entry(
        "T1548.005",
        "Temporary Elevated Cloud Access",
        ELEVATION_CONTROL,
    ),
    entry(
        "T1550",
        "Use Alternate Authentication Material",
        ALTERNATE_AUTHENTICATION,
    ),
    entry(
        "T1550.001",
        "Application Access Token",
        ALTERNATE_AUTHENTICATION,
    ),
    entry("T1550.004", "Web Session Cookie", ALTERNATE_AUTHENTICATION),
    entry("T1552", "Unsecured Credentials", CREDENTIAL_ACCESS),
    entry("T1552.001", "Credentials In Files", CREDENTIAL_ACCESS),
    entry(
        "T1552.005",
        "Cloud Instance Metadata API",
        CREDENTIAL_ACCESS,
    ),
    entry(
        "T1555",
        "Credentials from Password Stores",
        CREDENTIAL_ACCESS,
    ),
    entry(
        "T1555.006",
        "Cloud Secrets Management Stores",
        CREDENTIAL_ACCESS,
    ),
    entry(
        "T1556",
        "Modify Authentication Process",
        MODIFY_AUTHENTICATION,
    ),
    entry(
        "T1556.006",
        "Multi-Factor Authentication",
        MODIFY_AUTHENTICATION,
    ),
    entry("T1556.007", "Hybrid Identity", MODIFY_AUTHENTICATION),
    entry(
        "T1556.009",
        "Conditional Access Policies",
        MODIFY_AUTHENTICATION,
    ),
    entry("T1562", "Impair Defenses", &["defense-evasion"]),
    entry(
        "T1562.008",
        "Disable or Modify Cloud Logs",
        &["defense-evasion"],
    ),
    entry("T1566", "Phishing", INITIAL_ACCESS),
    entry("T1566.002", "Spearphishing Link", INITIAL_ACCESS),
    entry("T1567", "Exfiltration Over Web Service", EXFILTRATION),
    entry("T1580", "Cloud Infrastructure Discovery", DISCOVERY),
    entry(
        "T1589",
        "Gather Victim Identity Information",
        RECONNAISSANCE,
    ),
    entry("T1589.001", "Credentials", RECONNAISSANCE),
    entry("T1595", "Active Scanning", RECONNAISSANCE),
    entry("T1595.001", "Scanning IP Blocks", RECONNAISSANCE),
    entry("T1595.002", "Vulnerability Scanning", RECONNAISSANCE),
    entry("T1595.003", "Wordlist Scanning", RECONNAISSANCE),
    entry("T1606", "Forge Web Credentials", CREDENTIAL_ACCESS),
    entry("T1606.001", "Web Cookies", CREDENTIAL_ACCESS),
    entry("T1606.002", "SAML Tokens", CREDENTIAL_ACCESS),
    entry(
        "T1621",
        "Multi-Factor Authentication Request Generation",
        CREDENTIAL_ACCESS,
    ),
    entry("T1651", "Cloud Administration Command", EXECUTION),
];

const fn entry(id: &'static str, name: &'static str, tactics: &'static [&'static str]) -> Entry {
    Entry { id, name, tactics }
}

fn lookup(id: &str) -> Option<&'static Entry> {
    CATALOG
        .binary_search_by(|candidate| candidate.id.cmp(id))
        .ok()
        .and_then(|index| CATALOG.get(index))
}

/// Returns the catalog entry for a technique identifier, with the default tactic.
///
/// The identifier is in the ATT&CK format, for example `T1098.001`. The function returns
/// `None` for a technique that the catalog does not know.
#[must_use]
pub fn technique(technique_id: &str) -> Option<AttackTechnique> {
    let found = lookup(technique_id)?;
    let tactic = found.tactics.first()?;
    Some(AttackTechnique::new(*tactic, found.id, found.name))
}

/// Returns a technique with the given tactic.
///
/// The name comes from the catalog. For a technique that the catalog does not know, the
/// name is the identifier.
pub(crate) fn technique_in(tactic: &str, technique_id: &str) -> AttackTechnique {
    let name = lookup(technique_id).map_or(technique_id, |found| found.name);
    AttackTechnique::new(tactic, technique_id, name)
}

/// Converts a tag to a tactic name, if the tag names an ATT&CK tactic.
fn tactic_of(tag_body: &str) -> Option<&'static str> {
    TACTICS.iter().copied().find(|tactic| {
        tactic.len() == tag_body.len()
            && tactic
                .bytes()
                .zip(tag_body.bytes())
                .all(|(expected, found)| {
                    let found = if found == b'_' { b'-' } else { found };
                    expected == found.to_ascii_lowercase()
                })
    })
}

/// Converts a tag body such as `t1110.003` to the identifier `T1110.003`.
fn technique_id_of(tag_body: &str) -> Option<String> {
    let bytes = tag_body.as_bytes();
    let (letter, rest) = bytes.split_first()?;
    if !letter.eq_ignore_ascii_case(&b't') {
        return None;
    }
    let is_digits = |part: &[u8]| part.iter().all(u8::is_ascii_digit);
    let valid = match rest.len() {
        4 => is_digits(rest),
        8 => is_digits(rest.get(..4)?) && rest.get(4) == Some(&b'.') && is_digits(rest.get(5..)?),
        _ => false,
    };
    if !valid {
        return None;
    }
    Some(format!("T{}", tag_body.get(1..)?))
}

/// Converts Sigma tags to ATT&CK techniques.
///
/// - A tag such as `attack.t1110.003` names a technique.
/// - A tag such as `attack.credential-access` names a tactic.
///
/// Each technique gets the first tactic tag that the catalog accepts for it. If there is
/// none, the technique gets its default tactic from the catalog. A technique that the
/// catalog does not know gets the first tactic tag, or [`UNKNOWN_TACTIC`].
///
/// The result has no duplicates and keeps the order of the tags. Tags in other namespaces
/// are ignored.
#[must_use]
pub fn techniques_from_tags<S: AsRef<str>>(tags: &[S]) -> Vec<AttackTechnique> {
    let bodies = || {
        tags.iter().filter_map(|tag| {
            let tag = tag.as_ref().trim();
            let prefix = tag.get(..7)?;
            prefix
                .eq_ignore_ascii_case("attack.")
                .then(|| tag.get(7..))
                .flatten()
        })
    };
    let tactics: Vec<&'static str> = bodies().filter_map(tactic_of).collect();

    let mut techniques: Vec<AttackTechnique> = Vec::new();
    for id in bodies().filter_map(technique_id_of) {
        if techniques.iter().any(|known| known.technique_id == id) {
            continue;
        }
        let parent = id.split('.').next().unwrap_or(&id);
        let found = lookup(&id).or_else(|| lookup(parent));
        let tactic = match found {
            Some(found) => tactics
                .iter()
                .copied()
                .find(|tactic| found.tactics.contains(tactic))
                .or_else(|| found.tactics.first().copied()),
            None => tactics.first().copied(),
        }
        .unwrap_or(UNKNOWN_TACTIC);
        let name = found.map_or(id.as_str(), |found| found.name).to_owned();
        techniques.push(AttackTechnique {
            tactic: tactic.to_owned(),
            technique_id: id,
            name,
        });
    }
    techniques
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_is_in_order_so_that_the_binary_search_finds_each_entry() {
        assert!(CATALOG.len() > 60);
        assert!(CATALOG.is_sorted_by(|left, right| left.id < right.id));
        for found in CATALOG {
            assert!(!found.tactics.is_empty(), "{}", found.id);
            assert!(
                found.tactics.iter().all(|tactic| TACTICS.contains(tactic)),
                "{}",
                found.id
            );
            assert_eq!(
                technique_id_of(&found.id.to_lowercase()).as_deref(),
                Some(found.id)
            );
        }
    }

    #[test]
    fn technique_returns_the_default_tactic_and_the_name() {
        assert_eq!(
            technique("T1110.003"),
            Some(AttackTechnique::new(
                "credential-access",
                "T1110.003",
                "Password Spraying"
            ))
        );
        assert_eq!(technique("T9999"), None);
    }

    #[test]
    fn a_technique_tag_takes_the_matching_tactic_tag() {
        let tags = ["attack.privilege-escalation", "attack.t1098.003"];
        assert_eq!(
            techniques_from_tags(&tags),
            [AttackTechnique::new(
                "privilege-escalation",
                "T1098.003",
                "Additional Cloud Roles"
            )]
        );
    }

    #[test]
    fn a_tactic_tag_that_does_not_fit_the_technique_is_not_used() {
        let tags = ["attack.discovery", "attack.t1098.003"];
        assert_eq!(techniques_from_tags(&tags)[0].tactic, "persistence");
    }

    #[test]
    fn tags_accept_upper_case_and_the_underscore_form_of_a_tactic() {
        let tags = ["ATTACK.Credential_Access", "Attack.T1528"];
        assert_eq!(
            techniques_from_tags(&tags),
            [AttackTechnique::new(
                "credential-access",
                "T1528",
                "Steal Application Access Token"
            )]
        );
    }

    #[test]
    fn an_unknown_technique_keeps_its_identifier_and_takes_the_first_tactic_tag() {
        assert_eq!(
            techniques_from_tags(&["attack.impact", "attack.t1499"]),
            [AttackTechnique::new("impact", "T1499", "T1499")]
        );
        assert_eq!(
            techniques_from_tags(&["attack.t1499.002"]),
            [AttackTechnique::new(
                UNKNOWN_TACTIC,
                "T1499.002",
                "T1499.002"
            )]
        );
    }

    #[test]
    fn an_unknown_sub_technique_takes_the_data_of_its_parent() {
        assert_eq!(
            techniques_from_tags(&["attack.t1098.004"]),
            [AttackTechnique::new(
                "persistence",
                "T1098.004",
                "Account Manipulation"
            )]
        );
    }

    #[test]
    fn duplicates_and_other_tags_are_dropped_and_the_order_is_kept() {
        let tags = [
            "attack.t1528",
            "cve.2024-0001",
            "attack.t1110.003",
            "attack.T1528",
            "attack.g0016",
            "attack.t12345",
            "attack.t1110.03",
            "attack.",
            "tlp.clear",
        ];
        let ids: Vec<String> = techniques_from_tags(&tags)
            .into_iter()
            .map(|found| found.technique_id)
            .collect();
        assert_eq!(ids, ["T1528", "T1110.003"]);
    }

    #[test]
    fn tactic_tags_alone_give_no_technique() {
        assert_eq!(techniques_from_tags(&["attack.credential-access"]), []);
        assert_eq!(techniques_from_tags::<&str>(&[]), []);
    }
}
