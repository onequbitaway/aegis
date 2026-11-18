//! Tests of the configuration file format and of the start of a service.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use aegis_contracts::Error;
use aegis_decoy::{DecoyConfig, DecoyKeyConfig, DecoyService, PersonaKind};
use common::*;

const FULL: &str = r#"
id = "decoy-lab"
bind = "127.0.0.1:0"
personas = ["tarpit", "maze", "model_api"]
seed_env = "AEGIS_DECOY_SEED"

[limits]
max_connections = 128
max_connections_per_address = 4
max_header_bytes = 4096
max_headers = 32
max_body_bytes = 16384
header_read_timeout = "5s"
body_read_timeout = "6s"
write_timeout = "7s"
max_hold = "90s"
max_response_bytes = 131072

[tarpit]
chunk_bytes = 2
interval = "500ms"

[maze]
page_root = "/wiki"
api_root = "/data"
links_per_page = 6
items_per_page = 20
delay = "250ms"

[model_api]
models = ["assistant-large"]
interval = "1s"
answer_words = 80
max_prompt_chars = 2000

[[model_api.keys]]
id = "ht-decoy-model-key"
value_env = "AEGIS_DECOY_MODEL_KEY"

[canary]
enabled = true
path_prefix = "/trace"
origin = "http://192.0.2.10:8081"

[events]
max_queued = 1000
max_queued_bytes = 1048576
batch_size = 50
"#;

const MINIMAL: &str = r#"
id = "decoy-lab"
bind = "127.0.0.1:0"
personas = ["tarpit"]
seed_env = "AEGIS_DECOY_SEED"
"#;

#[test]
fn a_full_configuration_file_sets_each_value() {
    let config: DecoyConfig = toml::from_str(FULL).unwrap();
    config.validate().unwrap();
    assert_eq!(config.id, "decoy-lab");
    assert_eq!(config.bind, "127.0.0.1:0".parse().unwrap());
    assert_eq!(
        config.personas,
        [
            PersonaKind::Tarpit,
            PersonaKind::Maze,
            PersonaKind::ModelApi
        ]
    );
    assert_eq!(config.seed_env, "AEGIS_DECOY_SEED");
    assert_eq!(config.limits.max_connections, 128);
    assert_eq!(config.limits.max_connections_per_address, 4);
    assert_eq!(config.limits.max_header_bytes, 4096);
    assert_eq!(config.limits.max_headers, 32);
    assert_eq!(config.limits.max_body_bytes, 16_384);
    assert_eq!(config.limits.header_read_timeout, Duration::from_secs(5));
    assert_eq!(config.limits.body_read_timeout, Duration::from_secs(6));
    assert_eq!(config.limits.write_timeout, Duration::from_secs(7));
    assert_eq!(config.limits.max_hold, Duration::from_secs(90));
    assert_eq!(config.limits.max_response_bytes, 131_072);
    assert_eq!(config.tarpit.chunk_bytes, 2);
    assert_eq!(config.tarpit.interval, Duration::from_millis(500));
    assert_eq!(config.maze.page_root, "/wiki");
    assert_eq!(config.maze.api_root, "/data");
    assert_eq!(config.maze.links_per_page, 6);
    assert_eq!(config.maze.items_per_page, 20);
    assert_eq!(config.maze.delay, Duration::from_millis(250));
    assert_eq!(config.model_api.models, ["assistant-large"]);
    assert_eq!(config.model_api.interval, Duration::from_secs(1));
    assert_eq!(config.model_api.answer_words, 80);
    assert_eq!(config.model_api.max_prompt_chars, 2000);
    assert_eq!(
        config.model_api.keys,
        [DecoyKeyConfig::new(
            "ht-decoy-model-key",
            "AEGIS_DECOY_MODEL_KEY"
        )]
    );
    assert!(config.canary.enabled);
    assert_eq!(config.canary.path_prefix, "/trace");
    assert_eq!(
        config.canary.origin.as_deref(),
        Some("http://192.0.2.10:8081")
    );
    assert_eq!(config.events.max_queued, 1000);
    assert_eq!(config.events.max_queued_bytes, 1_048_576);
    assert_eq!(config.events.batch_size, 50);

    // The configuration survives a write and a read.
    let written = toml::to_string(&config).unwrap();
    assert_eq!(toml::from_str::<DecoyConfig>(&written).unwrap(), config);
    let json = serde_json::to_string(&config).unwrap();
    assert_eq!(serde_json::from_str::<DecoyConfig>(&json).unwrap(), config);
}

#[test]
fn a_minimal_configuration_file_gets_the_documented_defaults() {
    let config: DecoyConfig = toml::from_str(MINIMAL).unwrap();
    config.validate().unwrap();
    assert_eq!(
        config,
        DecoyConfig::new(
            "decoy-lab",
            "127.0.0.1:0".parse().unwrap(),
            [PersonaKind::Tarpit],
            "AEGIS_DECOY_SEED"
        )
    );
    assert_eq!(config.limits.max_connections, 256);
    assert_eq!(config.limits.max_connections_per_address, 8);
    assert_eq!(config.limits.max_header_bytes, 8192);
    assert_eq!(config.limits.max_headers, 64);
    assert_eq!(config.limits.max_body_bytes, 65_536);
    assert_eq!(config.limits.header_read_timeout, Duration::from_secs(10));
    assert_eq!(config.limits.body_read_timeout, Duration::from_secs(10));
    assert_eq!(config.limits.write_timeout, Duration::from_secs(10));
    assert_eq!(config.limits.max_hold, Duration::from_secs(120));
    assert_eq!(config.limits.max_response_bytes, 262_144);
    assert_eq!(config.tarpit.chunk_bytes, 8);
    assert_eq!(config.tarpit.interval, Duration::from_secs(1));
    assert_eq!(config.maze.page_root, "/docs");
    assert_eq!(config.maze.api_root, "/api");
    assert_eq!(config.maze.links_per_page, 8);
    assert_eq!(config.maze.items_per_page, 10);
    assert_eq!(config.maze.delay, Duration::from_millis(500));
    assert!(config.model_api.keys.is_empty());
    assert_eq!(
        config.model_api.models,
        ["assistant-large", "assistant-small"]
    );
    assert_eq!(config.model_api.interval, Duration::from_millis(750));
    assert_eq!(config.model_api.answer_words, 160);
    assert_eq!(config.model_api.max_prompt_chars, 4000);
    assert!(config.canary.enabled);
    assert_eq!(config.canary.path_prefix, "/ref");
    assert_eq!(config.canary.origin, None);
    assert_eq!(config.events.max_queued, 4096);
    assert_eq!(config.events.max_queued_bytes, 8 * 1024 * 1024);
    assert_eq!(config.events.batch_size, 100);
}

#[test]
fn an_unknown_key_is_an_error_in_each_table() {
    for (addition, key) in [
        ("extra = 1\n", "extra"),
        ("seed = \"a secret in the file\"\n", "seed"),
        ("[limits]\nmax_conections = 1\n", "max_conections"),
        ("[tarpit]\nbytes = 1\n", "bytes"),
        ("[maze]\nroot = \"/x\"\n", "root"),
        ("[model_api]\nupstream = \"http://192.0.2.1\"\n", "upstream"),
        (
            "[[model_api.keys]]\nid = \"a\"\nvalue_env = \"A\"\nvalue = \"x\"\n",
            "value",
        ),
        ("[canary]\ninstruction = \"do more\"\n", "instruction"),
        ("[events]\nunbounded = true\n", "unbounded"),
    ] {
        let text = format!("{MINIMAL}{addition}");
        let error = toml::from_str::<DecoyConfig>(&text)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("unknown field `{key}`")),
            "{addition:?}: {error}"
        );
    }
}

#[test]
fn a_file_with_no_mandatory_key_or_with_a_wrong_value_is_an_error() {
    for missing in ["id", "bind", "personas", "seed_env"] {
        let text: String = MINIMAL
            .lines()
            .filter(|line| !line.starts_with(missing))
            .collect::<Vec<_>>()
            .join("\n");
        let error = toml::from_str::<DecoyConfig>(&text)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("missing field `{missing}`")),
            "{error}"
        );
    }
    let wrong_persona = MINIMAL.replace("\"tarpit\"", "\"shell\"");
    let error = toml::from_str::<DecoyConfig>(&wrong_persona)
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown variant `shell`"), "{error}");
    let wrong_time = format!("{MINIMAL}[limits]\nmax_hold = \"soon\"\n");
    assert!(toml::from_str::<DecoyConfig>(&wrong_time).is_err());
}

fn config_error(result: aegis_contracts::Result<DecoyService>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        Err(other) => panic!("expected a configuration error, got {other:?}"),
        Ok(_) => panic!("expected a configuration error, got a service"),
    }
}

#[test]
fn the_seed_must_be_present_and_long_and_no_error_shows_it() {
    let config = config(&[PersonaKind::Maze]);
    assert_eq!(
        config_error(DecoyService::with_env(config.clone(), |_| None)),
        "decoy decoy-test: the environment variable AEGIS_DECOY_SEED is not set"
    );
    let short = "short-seed-EXAMPLE";
    let message = config_error(DecoyService::with_env(config.clone(), |_| {
        Some(short.to_owned())
    }));
    assert_eq!(
        message,
        "decoy decoy-test: the seed in AEGIS_DECOY_SEED must have 32 to 1024 bytes"
    );
    assert!(!message.contains(short));
    let long = "x".repeat(1025);
    config_error(DecoyService::with_env(config.clone(), move |_| {
        Some(long.clone())
    }));
    assert!(DecoyService::with_env(config, |_| Some("x".repeat(32))).is_ok());
}

#[test]
fn a_service_reads_the_process_environment_and_fails_closed_without_the_seed() {
    let mut config = config(&[PersonaKind::Maze]);
    // No process sets a variable with this name.
    config.seed_env = "AEGIS_DECOY_TEST_SEED_THAT_IS_NEVER_SET".to_owned();
    assert_eq!(
        config_error(DecoyService::new(config)),
        "decoy decoy-test: the environment variable AEGIS_DECOY_TEST_SEED_THAT_IS_NEVER_SET is not set"
    );
}

#[test]
fn a_decoy_key_must_be_present_and_valid_and_no_error_shows_it() {
    let config = config(&[PersonaKind::ModelApi]);
    let seed_only = |name: &str| (name == SEED_ENV).then(|| SEED_A.to_owned());
    assert_eq!(
        config_error(DecoyService::with_env(config.clone(), seed_only)),
        "decoy decoy-test: the environment variable AEGIS_DECOY_MODEL_KEY is not set"
    );
    let short_key = "short-EXAMPLE";
    let message = config_error(DecoyService::with_env(config.clone(), move |name| {
        Some(if name == SEED_ENV { SEED_A } else { short_key }.to_owned())
    }));
    assert_eq!(
        message,
        "decoy decoy-test: the decoy key ht-decoy-model-key must have 16 to 512 visible ASCII characters"
    );
    assert!(!message.contains(short_key));

    let mut two = config.clone();
    two.model_api
        .keys
        .push(DecoyKeyConfig::new("ht-second", "AEGIS_DECOY_SECOND_KEY"));
    let message = config_error(DecoyService::with_env(two, |name| {
        Some(if name == SEED_ENV { SEED_A } else { DECOY_KEY }.to_owned())
    }));
    assert_eq!(
        message,
        "decoy decoy-test: the decoy keys ht-decoy-model-key and ht-second have the same value"
    );
    assert!(!message.contains(DECOY_KEY));

    // With the model API off, the service does not read the key variables.
    let mut off = config;
    off.personas = vec![PersonaKind::Maze];
    assert!(DecoyService::with_env(off, seed_only).is_ok());
}

#[test]
fn a_configuration_that_is_not_valid_does_not_start() {
    let mut config = config(&[PersonaKind::Maze]);
    config.limits.max_connections = 0;
    assert_eq!(
        config_error(DecoyService::with_env(config, env(SEED_A))),
        "decoy configuration: limits.max_connections must be from 1 to 65536"
    );
}

#[test]
fn the_debug_output_of_a_service_shows_no_secret() {
    let service = service(config(&[PersonaKind::ModelApi]));
    let text = format!("{service:?}");
    assert_eq!(
        text,
        "DecoyService { id: \"decoy-test\", personas: [ModelApi], .. }"
    );
    assert!(!text.contains(SEED_A) && !text.contains(DECOY_KEY));
}

#[tokio::test]
async fn bind_selects_a_free_port_and_refuses_an_address_that_is_in_use() {
    let bound = DecoyService::bind_with_env(config(&[PersonaKind::Maze]), env(SEED_A))
        .await
        .unwrap();
    let address = bound.local_addr();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    assert_eq!(bound.service().config().id, DECOY_ID);
    assert_eq!(
        format!("{bound:?}"),
        format!("BoundDecoy {{ id: \"decoy-test\", local_addr: {address}, .. }}")
    );

    // A second decoy on the same address does not start.
    let mut second = config(&[PersonaKind::Maze]);
    second.bind = address;
    let error = DecoyService::bind_with_env(second, env(SEED_A))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message)
            if message.starts_with(&format!("the decoy decoy-test cannot listen on {address}: "))),
        "{error:?}"
    );

    // A configuration error comes before the listener.
    let mut invalid = config(&[PersonaKind::Maze]);
    invalid.seed_env = "not a name".to_owned();
    let error = DecoyService::bind_with_env(invalid, env(SEED_A))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Config(_)), "{error:?}");
}

#[tokio::test]
async fn a_stopped_decoy_closes_its_port() {
    let running = Running::start({
        let mut config = config(&[PersonaKind::Maze]);
        config.maze.delay = Duration::ZERO;
        config
    })
    .await;
    let address = running.address;
    let page = parse_response(&tcp_exchange(address, &get_request("/docs", "")).await);
    assert_eq!(page.status, 200);
    let service = running.service.clone();
    running.stop().await;
    // The listener is closed: a new connection is refused by the operating system.
    let error = tokio::net::TcpStream::connect(address).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert_eq!(service.stats().requests, 1);
}
