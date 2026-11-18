//! Tests for configuration loading, environment overrides, and section access.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Write;

use aegis_contracts::Error;
use aegis_core::Config;
use aegis_core::config::REDACTED;
use serde::Deserialize;

const SECRET: &str = "hunter2-s3cret";

const DOCUMENT: &str = r#"
[telemetry]
service_name = "aegis"
log_level = "info"

[ingest]
batch_size = 100
ratio = 0.25
enabled = false
sources = ["entra"]

[models.router]
default_provider = "local"
"#;

#[derive(Debug, PartialEq, Deserialize)]
struct Telemetry {
    service_name: String,
    log_level: String,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Ingest {
    batch_size: u32,
    ratio: f64,
    enabled: bool,
    sources: Vec<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Router {
    default_provider: String,
    #[serde(default)]
    retries: Option<u8>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Models {
    router: Router,
}

#[derive(Debug, PartialEq, Default, Deserialize)]
struct Store {
    url: Option<String>,
    pool_size: Option<u32>,
}

fn variables(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn config_error<T: std::fmt::Debug>(result: aegis_contracts::Result<T>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

fn document() -> Config {
    Config::from_toml_str(DOCUMENT).unwrap()
}

#[test]
fn a_section_deserializes_into_the_type_of_the_caller() {
    let config = document();
    assert_eq!(
        config.section::<Telemetry>("telemetry").unwrap(),
        Telemetry {
            service_name: "aegis".to_owned(),
            log_level: "info".to_owned(),
        }
    );
    assert_eq!(
        config.section::<Ingest>("ingest").unwrap(),
        Ingest {
            batch_size: 100,
            ratio: 0.25,
            enabled: false,
            sources: vec!["entra".to_owned()],
            label: None,
        }
    );
}

#[test]
fn load_reads_a_file_and_an_override_wins_over_the_file_value() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(DOCUMENT.as_bytes()).unwrap();

    let from_file = Config::load(file.path()).unwrap();
    assert_eq!(from_file, document());
    assert_eq!(
        from_file
            .section::<Telemetry>("telemetry")
            .unwrap()
            .service_name,
        "aegis"
    );

    let with_override = from_file
        .with_overrides(variables(&[(
            "AEGIS__TELEMETRY__SERVICE_NAME",
            "aegis-dev",
        )]))
        .unwrap();
    assert_eq!(
        with_override.section::<Telemetry>("telemetry").unwrap(),
        Telemetry {
            service_name: "aegis-dev".to_owned(),
            log_level: "info".to_owned(),
        }
    );
}

#[test]
fn an_override_value_becomes_a_number_a_boolean_an_array_or_a_string() {
    let config = document()
        .with_overrides(variables(&[
            ("AEGIS__INGEST__BATCH_SIZE", "500"),
            ("AEGIS__INGEST__RATIO", "0.75"),
            ("AEGIS__INGEST__ENABLED", "true"),
            ("AEGIS__INGEST__SOURCES", r#"["entra", "okta"]"#),
            ("AEGIS__INGEST__LABEL", "edge-1"),
        ]))
        .unwrap();
    assert_eq!(
        config.section::<Ingest>("ingest").unwrap(),
        Ingest {
            batch_size: 500,
            ratio: 0.75,
            enabled: true,
            sources: vec!["entra".to_owned(), "okta".to_owned()],
            label: Some("edge-1".to_owned()),
        }
    );
}

#[test]
fn quotation_marks_keep_digits_as_a_string() {
    let unquoted = document()
        .with_overrides(variables(&[("AEGIS__INGEST__LABEL", "12345")]))
        .unwrap();
    assert_eq!(
        config_error(unquoted.section::<Ingest>("ingest")),
        "the section `ingest` is not valid: key `label`: invalid type: integer, expected a string"
    );

    let quoted = document()
        .with_overrides(variables(&[("AEGIS__INGEST__LABEL", "\"12345\"")]))
        .unwrap();
    assert_eq!(
        quoted.section::<Ingest>("ingest").unwrap().label,
        Some("12345".to_owned())
    );
}

#[test]
fn an_override_sets_a_nested_key_and_keeps_the_other_keys() {
    let config = document()
        .with_overrides(variables(&[
            ("AEGIS__MODELS__ROUTER__DEFAULT_PROVIDER", "hosted"),
            ("AEGIS__MODELS__ROUTER__RETRIES", "3"),
        ]))
        .unwrap();
    assert_eq!(
        config.section::<Models>("models").unwrap(),
        Models {
            router: Router {
                default_provider: "hosted".to_owned(),
                retries: Some(3),
            }
        }
    );
}

#[test]
fn an_override_makes_a_section_and_nested_tables_that_the_file_does_not_have() {
    let config = Config::default()
        .with_overrides(variables(&[
            ("AEGIS__STORE__POOL_SIZE", "8"),
            ("AEGIS__MODELS__ROUTER__DEFAULT_PROVIDER", "local"),
        ]))
        .unwrap();
    assert!(config.has_section("store"));
    assert_eq!(
        config.section::<Store>("store").unwrap(),
        Store {
            url: None,
            pool_size: Some(8),
        }
    );
    assert_eq!(
        config
            .section::<Models>("models")
            .unwrap()
            .router
            .default_provider,
        "local"
    );
}

#[test]
fn the_name_of_an_override_is_not_case_sensitive() {
    let config = Config::from_toml_str("[Ingest]\nBatchSize = 1\n")
        .unwrap()
        .with_overrides(variables(&[
            ("aegis__ingest__batchsize", "2"),
            ("Aegis__Telemetry__Service_Name", "mixed"),
        ]))
        .unwrap();
    let ingest: BTreeMap<String, u32> = config.section("Ingest").unwrap();
    assert_eq!(ingest, BTreeMap::from([("BatchSize".to_owned(), 2)]));
    let telemetry: BTreeMap<String, String> = config.section("telemetry").unwrap();
    assert_eq!(
        telemetry,
        BTreeMap::from([("service_name".to_owned(), "mixed".to_owned())])
    );
}

#[test]
fn variables_without_the_prefix_have_no_effect() {
    let config = document()
        .with_overrides(variables(&[
            ("PATH", "/usr/bin"),
            ("AEGIS_TELEMETRY__SERVICE_NAME", "one-underscore"),
            ("OTHER__TELEMETRY__SERVICE_NAME", "other-prefix"),
            ("", ""),
        ]))
        .unwrap();
    assert_eq!(config, document());
}

#[test]
fn the_order_of_the_variables_does_not_change_the_result() {
    let forward = variables(&[
        ("AEGIS__INGEST__BATCH_SIZE", "7"),
        ("AEGIS__MODELS__ROUTER__RETRIES", "2"),
        ("AEGIS__STORE__URL", "memory"),
    ]);
    let mut backward = forward.clone();
    backward.reverse();
    let first = document().with_overrides(forward).unwrap();
    let second = document().with_overrides(backward).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.section::<Ingest>("ingest").unwrap().batch_size, 7);
}

#[test]
fn an_override_with_a_bad_name_is_an_error_that_does_not_show_the_value() {
    for (name, cause) in [
        (
            "AEGIS__TELEMETRY",
            "use the form AEGIS__<SECTION>__<KEY> with a section and a key",
        ),
        (
            "AEGIS__",
            "use the form AEGIS__<SECTION>__<KEY> with no empty part",
        ),
        (
            "AEGIS__TELEMETRY____SERVICE_NAME",
            "use the form AEGIS__<SECTION>__<KEY> with no empty part",
        ),
        (
            "AEGIS__TELEMETRY__",
            "use the form AEGIS__<SECTION>__<KEY> with no empty part",
        ),
    ] {
        let message = config_error(document().with_overrides(variables(&[(name, SECRET)])));
        assert_eq!(
            message,
            format!("the environment variable {name} is not a valid override: {cause}")
        );
    }
}

#[test]
fn an_override_with_too_many_path_parts_is_an_error() {
    let deepest = format!("AEGIS__{}", ["A"; 16].join("__"));
    assert!(
        Config::default()
            .with_overrides(variables(&[(&deepest, "1")]))
            .unwrap()
            .has_section("a")
    );

    let too_deep = format!("AEGIS__{}", ["A"; 17].join("__"));
    assert_eq!(
        config_error(Config::default().with_overrides(variables(&[(&too_deep, SECRET)]))),
        format!(
            "the environment variable {too_deep} is not a valid override: the key path has too many parts"
        )
    );
}

#[test]
fn an_override_below_a_key_that_is_not_a_table_is_an_error() {
    let message = config_error(document().with_overrides(variables(&[(
        "AEGIS__TELEMETRY__SERVICE_NAME__SUFFIX",
        SECRET,
    )])));
    assert_eq!(
        message,
        "the environment variable AEGIS__TELEMETRY__SERVICE_NAME__SUFFIX cannot set a key below \
         `telemetry.service_name`, because that key is not a table"
    );
}

#[test]
fn an_override_cannot_set_one_element_of_an_array() {
    let config = Config::from_toml_str("[[sources]]\nname = \"entra\"\n").unwrap();
    assert_eq!(
        config_error(config.with_overrides(variables(&[("AEGIS__SOURCES__0__NAME", SECRET)]))),
        "the environment variable AEGIS__SOURCES__0__NAME cannot set a key below `sources`, \
         because that key is not a table"
    );
}

#[test]
fn an_override_that_matches_two_keys_is_an_error() {
    let config = Config::from_toml_str("[ingest]\nBatch = 1\nbATCH = 2\n").unwrap();
    assert_eq!(
        config_error(config.with_overrides(variables(&[("AEGIS__INGEST__BATCH", SECRET)]))),
        "the environment variable AEGIS__INGEST__BATCH is ambiguous: two or more keys match \
         `batch` when case is ignored"
    );
}

#[test]
fn two_overrides_for_the_same_key_are_an_error() {
    assert_eq!(
        config_error(document().with_overrides(variables(&[
            ("AEGIS__INGEST__BATCH_SIZE", "1"),
            ("aegis__ingest__batch_size", "2"),
        ]))),
        "the environment variables AEGIS__INGEST__BATCH_SIZE and aegis__ingest__batch_size set \
         the same key or a key below it: `ingest.batch_size`"
    );
}

#[test]
fn an_override_of_a_table_and_of_a_key_in_that_table_is_an_error() {
    assert_eq!(
        config_error(document().with_overrides(variables(&[
            ("AEGIS__MODELS__ROUTER__RETRIES", "2"),
            ("aegis__models__router", SECRET),
        ]))),
        "the environment variables AEGIS__MODELS__ROUTER__RETRIES and aegis__models__router set \
         the same key or a key below it: `models.router`"
    );
}

#[test]
fn a_conflict_between_two_overrides_gives_the_same_error_for_each_sequence() {
    let expected = "the environment variables AEGIS__MODELS__ROUTER and \
                    AEGIS__MODELS__ROUTER__RETRIES set the same key or a key below it: \
                    `models.router`";
    let forward = variables(&[
        ("AEGIS__MODELS__ROUTER", SECRET),
        ("AEGIS__MODELS__ROUTER__RETRIES", "2"),
    ]);
    let mut backward = forward.clone();
    backward.reverse();
    assert_eq!(config_error(document().with_overrides(forward)), expected);
    assert_eq!(config_error(document().with_overrides(backward)), expected);
}

#[test]
fn overrides_that_make_the_same_new_table_are_not_in_conflict() {
    let config = Config::default()
        .with_overrides(variables(&[
            ("AEGIS__Store__URL", "memory"),
            ("AEGIS__STORE__POOL_SIZE", "8"),
        ]))
        .unwrap();
    assert_eq!(config.section_names(), ["store"]);
    assert_eq!(
        config.section::<Store>("store").unwrap(),
        Store {
            url: Some("memory".to_owned()),
            pool_size: Some(8),
        }
    );
}

#[test]
fn a_missing_section_is_an_error_that_names_the_section() {
    let config = document();
    assert!(!config.has_section("policy"));
    assert_eq!(
        config_error(config.section::<Store>("policy")),
        "the section `policy` is missing"
    );
}

#[test]
fn section_or_default_gives_the_default_only_for_a_missing_section() {
    let config = Config::from_toml_str("[store]\npool_size = 4\n").unwrap();
    assert_eq!(
        config.section_or_default::<Store>("absent").unwrap(),
        Store::default()
    );
    assert_eq!(
        config.section_or_default::<Store>("store").unwrap(),
        Store {
            url: None,
            pool_size: Some(4),
        }
    );
    let invalid = Config::from_toml_str("[store]\npool_size = \"many\"\n").unwrap();
    assert_eq!(
        config_error(invalid.section_or_default::<Store>("store")),
        "the section `store` is not valid: key `pool_size`: invalid type: string, expected u32"
    );
}

#[test]
fn an_invalid_section_error_names_the_section_and_the_key_but_not_a_value() {
    #[derive(Debug, Deserialize)]
    struct Database {
        #[expect(dead_code, reason = "the test reads only the error")]
        password: String,
        #[expect(dead_code, reason = "the test reads only the error")]
        port: u16,
    }
    let config = Config::from_toml_str(&format!(
        "[database]\npassword = \"{SECRET}\"\nport = \"{SECRET}-port\"\n"
    ))
    .unwrap();
    let message = config_error(config.section::<Database>("database"));
    assert_eq!(
        message,
        "the section `database` is not valid: key `port`: invalid type: string, expected u16"
    );
    assert!(!message.contains(SECRET));
}

#[test]
fn an_invalid_section_error_hides_a_value_that_a_type_puts_in_its_message() {
    /// A type that shows the incorrect value in its message, as some libraries do.
    #[derive(Debug)]
    struct Endpoint;

    impl<'de> Deserialize<'de> for Endpoint {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let text = String::deserialize(deserializer)?;
            Err(serde::de::Error::custom(format!(
                "relative URL without a base: {text:?}"
            )))
        }
    }

    #[derive(Debug, Deserialize)]
    struct Database {
        #[expect(dead_code, reason = "the test reads only the error")]
        url: Endpoint,
    }

    let url = format!("postgres://aegis:{SECRET}@db.internal/aegis");
    let config = Config::from_toml_str(&format!("[database]\nurl = \"{url}\"\n")).unwrap();
    let message = config_error(config.section::<Database>("database"));
    assert_eq!(
        message,
        format!(
            "the section `database` is not valid: key `url`: relative URL without a base: \"{REDACTED}\""
        )
    );
    assert!(!message.contains(SECRET));
}

#[test]
fn an_invalid_section_error_hides_a_part_of_a_value_that_a_type_puts_in_its_message() {
    /// A type that shows only the part of the value that it could not read, as a parser does.
    #[derive(Debug)]
    struct Dsn;

    impl<'de> Deserialize<'de> for Dsn {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let text = String::deserialize(deserializer)?;
            let password = text
                .split('@')
                .next()
                .and_then(|credentials| credentials.rsplit(':').next())
                .unwrap_or_default();
            Err(serde::de::Error::custom(format!(
                "invalid character in the password '{password}'"
            )))
        }
    }

    #[derive(Debug, Deserialize)]
    struct Database {
        #[expect(dead_code, reason = "the test reads only the error")]
        url: Dsn,
    }

    let url = format!("postgres://aegis:{SECRET}@db.internal/aegis");
    let config = Config::from_toml_str(&format!("[database]\nurl = \"{url}\"\n")).unwrap();
    let message = config_error(config.section::<Database>("database"));
    assert_eq!(
        message,
        format!(
            "the section `database` is not valid: key `url`: invalid character in the password '{REDACTED}'"
        )
    );
}

#[test]
fn an_invalid_section_error_hides_a_value_in_the_description_of_the_expected_value() {
    /// A type that shows the incorrect value in the description of what it accepts.
    #[derive(Debug)]
    struct Level;

    impl<'de> Deserialize<'de> for Level {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let text = String::deserialize(deserializer)?;
            Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&text),
                &format!("a level, not {text}").as_str(),
            ))
        }
    }

    #[derive(Debug, Deserialize)]
    struct Logging {
        #[expect(dead_code, reason = "the test reads only the error")]
        level: Level,
    }

    let config = Config::from_toml_str(&format!("[logging]\nlevel = \"{SECRET}\"\n")).unwrap();
    assert_eq!(
        config_error(config.section::<Logging>("logging")),
        format!(
            "the section `logging` is not valid: key `level`: invalid value: string, expected a \
             level, not {REDACTED}"
        )
    );
}

#[test]
fn a_secret_from_an_override_does_not_reach_an_error_message() {
    let config = document()
        .with_overrides(variables(&[("AEGIS__INGEST__BATCH_SIZE", SECRET)]))
        .unwrap();
    assert_eq!(
        config_error(config.section::<Ingest>("ingest")),
        "the section `ingest` is not valid: key `batch_size`: invalid type: string, expected u32"
    );
}

#[test]
fn a_top_level_key_can_be_an_array_of_tables() {
    #[derive(Debug, PartialEq, Deserialize)]
    struct Source {
        name: String,
    }
    let config =
        Config::from_toml_str("[[sources]]\nname = \"entra\"\n[[sources]]\nname = \"okta\"\n")
            .unwrap();
    assert_eq!(
        config.section::<Vec<Source>>("sources").unwrap(),
        vec![
            Source {
                name: "entra".to_owned()
            },
            Source {
                name: "okta".to_owned()
            }
        ]
    );
}

#[test]
fn section_names_and_has_section_report_the_top_level_keys() {
    let config = document();
    assert_eq!(config.section_names(), ["ingest", "models", "telemetry"]);
    assert!(config.has_section("models"));
    assert!(!config.has_section("router"));
    assert!(!config.has_section("Models"));
    assert_eq!(Config::default().section_names(), Vec::<&str>::new());
}

#[test]
fn the_debug_output_shows_the_section_names_and_no_value() {
    let config = Config::from_toml_str(&format!("[database]\npassword = \"{SECRET}\"\n")).unwrap();
    assert_eq!(
        format!("{config:?}"),
        r#"Config { sections: ["database"] }"#
    );
}

#[test]
fn load_of_a_missing_file_is_an_error_that_names_the_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("absent.toml");
    let message = config_error(Config::load(&path));
    assert!(
        message.starts_with(&format!(
            "cannot read the configuration file {}: ",
            path.display()
        )),
        "{message}"
    );
}

#[test]
fn a_syntax_error_gives_the_line_and_the_column_but_not_the_text_of_the_line() {
    let text = format!("[database]\nuser = \"aegis\"\npassword = \"{SECRET}\n");
    assert_eq!(
        config_error(Config::from_toml_str(&text)),
        "the configuration text is not valid TOML at line 3, column 27: invalid basic string, \
         expected `\"`"
    );

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(text.as_bytes()).unwrap();
    assert_eq!(
        config_error(Config::load(file.path())),
        format!(
            "the configuration file {} is not valid TOML at line 3, column 27: invalid basic \
             string, expected `\"`",
            file.path().display()
        )
    );
}

#[test]
fn no_parse_error_contains_text_from_the_document() {
    let documents = [
        format!("password = \"{SECRET}"),
        format!("password = '{SECRET}\n"),
        format!("password = \"\"\"{SECRET}"),
        format!("password = {SECRET}"),
        format!("password = \"{SECRET}\" trailing"),
        format!("password = \"{SECRET}\\q\""),
        format!("list = [\"{SECRET}\", "),
        format!("table = {{ a = \"{SECRET}\", a = 2 }}"),
        format!("a.b = \"{SECRET}\"\na = 1"),
        format!("[db]\npassword = \"{SECRET}\"\n[db]\nx = 1"),
        format!("password = 0x{SECRET}"),
        format!("password = {SECRET}.5"),
        format!("password = 1979-05-27T{SECRET}"),
        "pin = 99999999999999999999999123456".to_owned(),
        "pin = 0x99999999999999999999999123456".to_owned(),
    ];
    for document in documents {
        let message = config_error(Config::from_toml_str(&document));
        assert!(
            message.starts_with("the configuration text is not valid TOML at line "),
            "{message}"
        );
        assert!(!message.contains(SECRET), "{message}");
        assert!(!message.contains("123456"), "{message}");
    }
}

#[test]
fn a_number_that_is_out_of_range_gives_a_location_and_no_value() {
    assert_eq!(
        config_error(Config::from_toml_str(
            "[store]\npin = 99999999999999999999999123456\n"
        )),
        "the configuration text is not valid TOML at line 2, column 7: a value is not valid or \
         is out of range"
    );
}
