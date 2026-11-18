//! Rule packs: a directory of Sigma rules and indicators that the engine loads as one unit.
//!
//! A pack is a directory with this layout:
//!
//! ```text
//! aegis-identity/
//!   pack.yml            the manifest: name, version, description
//!   rules/*.yml         Sigma rules, one rule in each file
//!   indicators/*.yml    indicator files (YAML or JSON)
//! ```
//!
//! [`RulePack::load`] reads and validates the full directory. A pack is valid only if each
//! file in it is valid. The engine thus never runs a part of a pack.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{DetectError, yaml_reason};
use crate::files::{list_files, read_text};
use crate::ioc::{Indicator, IocStore, load_indicators};
use crate::sigma::{SigmaDetector, SigmaRule};

/// The name of the manifest file of a pack.
pub const MANIFEST_FILE: &str = "pack.yml";

/// The name of the directory that holds the Sigma rules of a pack.
pub const RULES_DIRECTORY: &str = "rules";

/// The name of the directory that holds the indicator files of a pack.
pub const INDICATORS_DIRECTORY: &str = "indicators";

/// The largest size of a manifest file in bytes.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// The largest number of characters in the name of a pack.
pub const MAX_PACK_NAME_CHARS: usize = 64;

/// The manifest of a rule pack: the content of `pack.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    /// The name of the pack. Use lower case letters, digits, `-`, `_`, and `.`.
    pub name: String,
    /// The version of the pack, for example `1.2.0`.
    pub version: String,
    /// What the pack detects.
    pub description: String,
}

impl PackManifest {
    /// Returns the reason that the manifest is not valid, if it is not valid.
    fn check(&self) -> Result<(), String> {
        let name_is_valid = !self.name.is_empty()
            && self.name.chars().count() <= MAX_PACK_NAME_CHARS
            && self.name.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '-' | '_' | '.')
            });
        if !name_is_valid {
            return Err(format!(
                "the name {:?} is not valid; use 1 to {MAX_PACK_NAME_CHARS} lower case \
                 letters, digits, \"-\", \"_\", and \".\"",
                self.name
            ));
        }
        if self.version.trim().is_empty() {
            return Err("the version is empty".to_owned());
        }
        if self.description.trim().is_empty() {
            return Err("the description is empty".to_owned());
        }
        Ok(())
    }
}

/// A validated set of Sigma rules and indicators, with its manifest.
///
/// The pack holds the compiled rules and the indicator indexes. Give it to
/// [`DetectionEngine::new`](crate::engine::DetectionEngine::new) or to
/// [`DetectionEngine::reload`](crate::engine::DetectionEngine::reload).
#[derive(Debug)]
pub struct RulePack {
    manifest: PackManifest,
    sigma: SigmaDetector,
    indicators: IocStore,
}

impl RulePack {
    /// Makes a pack with no rule and no indicator. An engine with this pack runs only the
    /// velocity detectors.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            manifest: PackManifest {
                name: "empty".to_owned(),
                version: "0".to_owned(),
                description: "A pack with no rule and no indicator.".to_owned(),
            },
            sigma: SigmaDetector::default(),
            indicators: IocStore::default(),
        }
    }

    /// Makes a pack from compiled rules and indicators.
    ///
    /// # Errors
    ///
    /// Returns [`DetectError::Pack`] if the manifest is not valid, if the pack has no rule
    /// and no indicator, or if two rules have one identifier. Returns
    /// [`DetectError::Indicator`] if the indicators are not a valid set.
    pub fn new(
        manifest: PackManifest,
        rules: Vec<SigmaRule>,
        indicators: Vec<Indicator>,
    ) -> Result<Self, DetectError> {
        let origin = manifest.name.clone();
        Self::build(Path::new(&origin), manifest, rules, indicators, &origin)
    }

    fn build(
        path: &Path,
        manifest: PackManifest,
        rules: Vec<SigmaRule>,
        indicators: Vec<Indicator>,
        indicator_origin: &str,
    ) -> Result<Self, DetectError> {
        manifest
            .check()
            .map_err(|reason| DetectError::pack(path, reason))?;
        if rules.is_empty() && indicators.is_empty() {
            return Err(DetectError::pack(
                path,
                "the pack has no rule and no indicator",
            ));
        }
        let mut origins: HashMap<&str, &str> = HashMap::with_capacity(rules.len());
        for rule in &rules {
            if let Some(first) = origins.insert(rule.id(), rule.origin()) {
                return Err(DetectError::pack(
                    path,
                    format!(
                        "the rule identifier {:?} is in {first} and in {}",
                        rule.id(),
                        rule.origin()
                    ),
                ));
            }
        }
        let indicators = IocStore::with_origin(indicators, indicator_origin)?;
        Ok(Self {
            manifest,
            sigma: SigmaDetector::new(rules),
            indicators,
        })
    }

    /// Reads and validates the pack in the directory `directory`.
    ///
    /// The function reads `pack.yml`, each `.yml` and `.yaml` file in `rules`, and each
    /// `.yml`, `.yaml`, and `.json` file in `indicators`, in order of file name. It does
    /// not read subdirectories. The `rules` directory and the `indicators` directory are
    /// each optional, but the pack must have one rule or one indicator.
    ///
    /// The function reads files and blocks the thread. In an asynchronous task, call it
    /// with `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// - [`DetectError::Io`] if the directory or a file cannot be read.
    /// - [`DetectError::Pack`] if the manifest is not valid, if the pack is empty, or if
    ///   two rules have one identifier.
    /// - [`DetectError::Rule`] if a rule file is not valid. The error names the file.
    /// - [`DetectError::Indicator`] if an indicator file is not valid, or if two files hold
    ///   the same indicator.
    pub fn load(directory: impl AsRef<Path>) -> Result<Self, DetectError> {
        let directory = directory.as_ref();
        let manifest_path = directory.join(MANIFEST_FILE);
        let text = read_text(&manifest_path, MAX_MANIFEST_BYTES, |reason| {
            DetectError::pack(&manifest_path, reason)
        })?;
        let manifest: PackManifest = serde_saphyr::from_str(&text)
            .map_err(|error| DetectError::pack(&manifest_path, yaml_reason(&error)))?;

        let rules = list_files(&directory.join(RULES_DIRECTORY), &["yml", "yaml"])?
            .iter()
            .map(|path| SigmaRule::load(path))
            .collect::<Result<Vec<SigmaRule>, DetectError>>()?;

        let indicator_directory = directory.join(INDICATORS_DIRECTORY);
        let mut indicators: Vec<Indicator> = Vec::new();
        for path in list_files(&indicator_directory, &["yml", "yaml", "json"])? {
            let found = load_indicators(&path)?;
            // Validate each file alone first, so that an error names the file.
            IocStore::with_origin(found.clone(), &path.display().to_string())?;
            indicators.extend(found);
        }

        Self::build(
            directory,
            manifest,
            rules,
            indicators,
            &indicator_directory.display().to_string(),
        )
    }

    /// Returns the manifest of the pack.
    #[must_use]
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }

    /// Returns the Sigma rules of the pack, in order of file name.
    #[must_use]
    pub fn rules(&self) -> &[SigmaRule] {
        self.sigma.rules()
    }

    /// Returns the detector that evaluates the Sigma rules of the pack.
    #[must_use]
    pub fn sigma(&self) -> &SigmaDetector {
        &self.sigma
    }

    /// Returns the indicators of the pack.
    #[must_use]
    pub fn indicators(&self) -> &IocStore {
        &self.indicators
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};

    use aegis_contracts::common::{EntityKind, Severity};
    use aegis_contracts::event::{Actor, Event, EventClass, EventSource, action};
    use chrono::DateTime;

    use super::*;
    use crate::ioc::IndicatorKind;

    const MANIFEST: &str =
        "name: test-pack\nversion: \"1.2.0\"\ndescription: Rules for the tests.\n";

    fn rule_text(id: &str, action: &str) -> String {
        format!(
            "title: Rule {id}\nid: {id}\nlevel: high\ndetection:\n  selection:\n    action: \
             {action}\n  condition: selection\n"
        )
    }

    const INDICATORS: &str = "indicators:\n  - type: ip\n    value: 192.0.2.200\n    \
                              description: An example address.\n    severity: high\n";

    /// Writes a pack directory. Each item is a path in the pack and the text of the file.
    fn write_pack(files: &[(&str, &str)]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = directory.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        directory
    }

    fn event(action: &str, ip: Ipv4Addr) -> Event {
        Event::new(
            DateTime::UNIX_EPOCH,
            EventSource::new("c", "v", "p"),
            EventClass::Other,
            action,
            Actor::new(EntityKind::User, "user-1").with_ip(IpAddr::V4(ip)),
        )
    }

    #[test]
    fn load_reads_the_manifest_the_rules_and_the_indicators() {
        let directory = write_pack(&[
            ("pack.yml", MANIFEST),
            ("rules/b.yml", &rule_text("rule-b", "role.assign")),
            ("rules/a.yaml", &rule_text("rule-a", "sign_in")),
            ("rules/notes.txt", "This file is not a rule."),
            ("rules/nested/c.yml", "This file is in a subdirectory."),
            ("indicators/addresses.yml", INDICATORS),
            (
                "indicators/domains.json",
                r#"{"indicators":[{"type":"domain","value":"bad.example","description":"d","severity":"low"}]}"#,
            ),
        ]);
        let pack = RulePack::load(directory.path()).unwrap();
        assert_eq!(
            pack.manifest(),
            &PackManifest {
                name: "test-pack".to_owned(),
                version: "1.2.0".to_owned(),
                description: "Rules for the tests.".to_owned(),
            }
        );
        let ids: Vec<&str> = pack.rules().iter().map(SigmaRule::id).collect();
        assert_eq!(ids, ["rule-a", "rule-b"]);
        let kinds: Vec<IndicatorKind> = pack
            .indicators()
            .indicators()
            .map(|indicator| indicator.kind)
            .collect();
        assert_eq!(kinds, [IndicatorKind::Ip, IndicatorKind::Domain]);

        // The compiled pack detects with the rules and with the indicators.
        let by_rule = pack
            .sigma()
            .evaluate(&event(action::SIGN_IN, Ipv4Addr::new(198, 51, 100, 1)));
        assert_eq!(by_rule.len(), 1);
        assert_eq!(by_rule[0].rule_id, "rule-a");
        let by_indicator = pack
            .indicators()
            .evaluate(&event(action::API_CALL, Ipv4Addr::new(192, 0, 2, 200)));
        assert_eq!(by_indicator.len(), 1);
        assert_eq!(by_indicator[0].rule_id, "ioc:ip:192.0.2.200");
    }

    #[test]
    fn a_pack_can_have_only_rules_or_only_indicators() {
        let only_rules = write_pack(&[
            ("pack.yml", MANIFEST),
            ("rules/a.yml", &rule_text("rule-a", "sign_in")),
        ]);
        let pack = RulePack::load(only_rules.path()).unwrap();
        assert_eq!(pack.rules().len(), 1);
        assert!(pack.indicators().is_empty());

        let only_indicators =
            write_pack(&[("pack.yml", MANIFEST), ("indicators/a.yml", INDICATORS)]);
        let pack = RulePack::load(only_indicators.path()).unwrap();
        assert_eq!(pack.rules().len(), 0);
        assert_eq!(pack.indicators().len(), 1);
    }

    #[test]
    fn a_pack_with_no_rule_and_no_indicator_is_an_error() {
        let directory = write_pack(&[("pack.yml", MANIFEST), ("rules/readme.txt", "x")]);
        let error = RulePack::load(directory.path()).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "rule pack {}: the pack has no rule and no indicator",
                directory.path().display()
            )
        );
        assert!(matches!(error, DetectError::Pack { .. }));
    }

    #[test]
    fn a_directory_with_no_manifest_is_a_read_error_that_names_the_file() {
        let directory = write_pack(&[("rules/a.yml", &rule_text("rule-a", "sign_in"))]);
        let error = RulePack::load(directory.path()).unwrap_err();
        let expected = directory.path().join("pack.yml").display().to_string();
        assert!(
            matches!(
                &error,
                DetectError::Io { path, source }
                    if *path == expected && source.kind() == std::io::ErrorKind::NotFound
            ),
            "{error}"
        );
        let contract: aegis_contracts::Error = error.into();
        assert!(
            matches!(&contract, aegis_contracts::Error::NotFound(path) if *path == expected),
            "{contract}"
        );
    }

    #[test]
    fn a_manifest_that_is_not_valid_is_an_error_that_names_the_file_and_the_cause() {
        let cases = [
            (
                "name: Test Pack\nversion: \"1\"\ndescription: d\n",
                "the name \"Test Pack\" is not valid; use 1 to 64 lower case letters, digits, \
                 \"-\", \"_\", and \".\"",
            ),
            (
                "name: ''\nversion: \"1\"\ndescription: d\n",
                "the name \"\" is not valid; use 1 to 64 lower case letters, digits, \"-\", \
                 \"_\", and \".\"",
            ),
            (
                "name: test-pack\nversion: '  '\ndescription: d\n",
                "the version is empty",
            ),
            (
                "name: test-pack\nversion: \"1\"\ndescription: ''\n",
                "the description is empty",
            ),
        ];
        for (manifest, expected) in cases {
            let directory = write_pack(&[
                ("pack.yml", manifest),
                ("rules/a.yml", &rule_text("rule-a", "sign_in")),
            ]);
            let error = RulePack::load(directory.path()).unwrap_err();
            assert!(
                matches!(&error, DetectError::Pack { reason, .. } if reason == expected),
                "{manifest:?}: {error}"
            );
        }

        for (manifest, part) in [
            (
                "name: test-pack\nversion: \"1\"\n",
                "missing field `description`",
            ),
            (
                "name: test-pack\nversion: \"1\"\ndescription: d\nauthor: a\n",
                "unknown field `author`",
            ),
            ("- a\n- b\n", "expected mapping start"),
            ("name: [unclosed\n", "line "),
        ] {
            let directory = write_pack(&[
                ("pack.yml", manifest),
                ("rules/a.yml", &rule_text("rule-a", "sign_in")),
            ]);
            let error = RulePack::load(directory.path()).unwrap_err();
            let manifest_path = directory.path().join("pack.yml").display().to_string();
            assert!(
                matches!(
                    &error,
                    DetectError::Pack { path, reason }
                        if *path == manifest_path && reason.contains(part)
                ),
                "{manifest:?}: {error}"
            );
        }
    }

    #[test]
    fn a_version_that_yaml_reads_as_a_number_is_accepted_as_text() {
        for (version, expected) in [("1", "1"), ("1.5", "1.5"), ("2026.11.03", "2026.11.03")] {
            let manifest = format!("name: test-pack\nversion: {version}\ndescription: d\n");
            let directory = write_pack(&[
                ("pack.yml", &manifest),
                ("rules/a.yml", &rule_text("rule-a", "sign_in")),
            ]);
            let pack = RulePack::load(directory.path()).unwrap();
            assert_eq!(pack.manifest().version, expected);
        }
    }

    #[test]
    fn one_rule_that_is_not_valid_rejects_the_pack_and_names_the_rule_file() {
        let directory = write_pack(&[
            ("pack.yml", MANIFEST),
            ("rules/a.yml", &rule_text("rule-a", "sign_in")),
            (
                "rules/broken.yml",
                "title: Broken\ndetection:\n  selection: {}\n  condition: selection\n",
            ),
        ]);
        let error = RulePack::load(directory.path()).unwrap_err();
        let broken = directory.path().join("rules").join("broken.yml");
        assert_eq!(
            error.to_string(),
            format!(
                "rule {}: the selection \"selection\" has an empty map, which would match all \
                 events",
                broken.display()
            )
        );
        assert!(matches!(error, DetectError::Rule { .. }));
    }

    #[test]
    fn two_rules_with_one_identifier_reject_the_pack_and_name_the_two_files() {
        let directory = write_pack(&[
            ("pack.yml", MANIFEST),
            ("rules/a.yml", &rule_text("rule-same", "sign_in")),
            ("rules/b.yml", &rule_text("rule-same", "role.assign")),
        ]);
        let error = RulePack::load(directory.path()).unwrap_err();
        let rules = directory.path().join("rules");
        assert!(
            matches!(
                &error,
                DetectError::Pack { reason, .. }
                    if *reason == format!(
                        "the rule identifier \"rule-same\" is in {} and in {}",
                        rules.join("a.yml").display(),
                        rules.join("b.yml").display()
                    )
            ),
            "{error}"
        );
    }

    #[test]
    fn an_indicator_file_that_is_not_valid_rejects_the_pack_and_names_the_file() {
        let directory = write_pack(&[
            ("pack.yml", MANIFEST),
            ("rules/a.yml", &rule_text("rule-a", "sign_in")),
            ("indicators/good.yml", INDICATORS),
            (
                "indicators/zero.yml",
                "indicators:\n  - type: ip\n    value: 0.0.0.0/0\n    description: d\n    \
                 severity: low\n",
            ),
        ]);
        let error = RulePack::load(directory.path()).unwrap_err();
        let file = directory.path().join("indicators").join("zero.yml");
        assert_eq!(
            error.to_string(),
            format!(
                "indicator file {}: indicator 1: the network \"0.0.0.0/0\" contains all addresses",
                file.display()
            )
        );
    }

    #[test]
    fn one_indicator_in_two_files_rejects_the_pack() {
        let directory = write_pack(&[
            ("pack.yml", MANIFEST),
            ("indicators/a.yml", INDICATORS),
            ("indicators/b.yml", INDICATORS),
        ]);
        let error = RulePack::load(directory.path()).unwrap_err();
        assert!(
            matches!(
                &error,
                DetectError::Indicator { file, reason }
                    if *file == directory.path().join("indicators").display().to_string()
                        && reason == "indicator 2: the ip indicator \"192.0.2.200\" is in the set \
                                      two times"
            ),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_above_the_size_limit_is_an_error() {
        let size = usize::try_from(MAX_MANIFEST_BYTES).unwrap() + 1;
        let large = format!("{MANIFEST}#{}", "x".repeat(size));
        let directory = write_pack(&[
            ("pack.yml", &large),
            ("rules/a.yml", &rule_text("rule-a", "sign_in")),
        ]);
        let error = RulePack::load(directory.path()).unwrap_err();
        assert!(
            matches!(
                &error,
                DetectError::Pack { reason, .. }
                    if reason == "the file is larger than the limit of 65536 bytes"
            ),
            "{error}"
        );
    }

    #[test]
    fn new_makes_a_pack_from_parts_with_the_same_checks() {
        let manifest = PackManifest {
            name: "from-parts".to_owned(),
            version: "1".to_owned(),
            description: "A pack that the code makes.".to_owned(),
        };
        let rule = |id: &str| SigmaRule::parse(&rule_text(id, "sign_in"), "inline").unwrap();
        let indicator = Indicator {
            kind: IndicatorKind::Ip,
            value: "192.0.2.200".to_owned(),
            description: "An example address.".to_owned(),
            severity: Severity::High,
            tags: Vec::new(),
            verdict: None,
            id: None,
        };
        let pack = RulePack::new(manifest.clone(), vec![rule("a")], vec![indicator]).unwrap();
        assert_eq!(pack.manifest().name, "from-parts");
        assert_eq!(pack.rules().len(), 1);
        assert_eq!(pack.indicators().len(), 1);

        let empty = RulePack::new(manifest.clone(), Vec::new(), Vec::new()).unwrap_err();
        assert_eq!(
            empty.to_string(),
            "rule pack from-parts: the pack has no rule and no indicator"
        );
        let duplicate =
            RulePack::new(manifest, vec![rule("a"), rule("a")], Vec::new()).unwrap_err();
        assert_eq!(
            duplicate.to_string(),
            "rule pack from-parts: the rule identifier \"a\" is in inline and in inline"
        );
    }

    #[test]
    fn the_empty_pack_detects_nothing() {
        let pack = RulePack::empty();
        assert_eq!(pack.manifest().name, "empty");
        assert_eq!(pack.rules().len(), 0);
        assert!(pack.indicators().is_empty());
        let event = event(action::SIGN_IN, Ipv4Addr::new(192, 0, 2, 200));
        assert_eq!(pack.sigma().evaluate(&event), []);
        assert_eq!(pack.indicators().evaluate(&event), []);
    }
}
