//! Integration tests for the configuration and for `build_router`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::time::Duration;

use aegis_contracts::Error;
use aegis_contracts::model::{ChatRequest, EmbeddingRequest, Message, ModelProvider, TaskKind};
use aegis_model::{
    Budget, MaxTokensField, ModelConfig, ProviderConfig, Route, RoutesConfig, TASK_KINDS,
    build_router,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{header, json_body, requests};

/// Parses the `model` table of a configuration file, as the configuration loader does.
fn model_section(text: &str) -> ModelConfig {
    let mut file: toml::Table = toml::from_str(text).unwrap();
    file.remove("model").unwrap().try_into().unwrap()
}

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let values: HashMap<String, String> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name: &str| values.get(name).cloned()
}

fn config_error(config: &ModelConfig, env: impl Fn(&str) -> Option<String>) -> String {
    match build_router(config, env) {
        Err(Error::Config(text)) => text,
        Err(error) => panic!("the error is not a configuration error: {error}"),
        Ok(_) => panic!("the configuration is not valid, but a router was built"),
    }
}

/// Returns the first TOML block of the crate README.
fn readme_example() -> &'static str {
    let readme = include_str!("../README.md");
    let start = readme.find("```toml\n").unwrap() + "```toml\n".len();
    let length = readme[start..].find("```").unwrap();
    &readme[start..start + length]
}

#[test]
fn readme_example_builds_a_router_when_the_key_variables_are_set() {
    let config = model_section(readme_example());
    let variables: Vec<&str> = config
        .providers
        .values()
        .filter_map(|provider| match provider {
            ProviderConfig::OpenAiCompatible { api_key_env, .. } => api_key_env.as_deref(),
            ProviderConfig::Anthropic { api_key_env, .. } => Some(api_key_env.as_str()),
        })
        .collect();
    assert!(variables.len() >= 2, "the example must show key variables");
    let pairs: Vec<(&str, &str)> = variables.iter().map(|name| (*name, "test-key")).collect();

    let router = build_router(&config, env_of(&pairs)).unwrap();

    for task in TASK_KINDS {
        let routes = router.routes(task);
        assert!(!routes.is_empty(), "{task:?} has no route");
        for route in routes {
            assert!(
                config.providers.contains_key(&route.provider),
                "{task:?} names the provider {}",
                route.provider
            );
        }
    }
    assert!(!router.budget().is_unlimited());

    // Without the environment, the example names the first missing variable.
    let message = config_error(&config, |_| None);
    assert!(
        variables.iter().any(|name| message
            == format!(
                "provider {}: the environment variable {name} is not set",
                provider_of(&config, name)
            )),
        "{message}"
    );
}

/// Returns the name of the provider that uses the key variable `variable`.
fn provider_of<'a>(config: &'a ModelConfig, variable: &str) -> &'a str {
    config
        .providers
        .iter()
        .find(|(_, provider)| match provider {
            ProviderConfig::OpenAiCompatible { api_key_env, .. } => {
                api_key_env.as_deref() == Some(variable)
            }
            ProviderConfig::Anthropic { api_key_env, .. } => api_key_env == variable,
        })
        .map(|(name, _)| name.as_str())
        .unwrap()
}

fn chat(task: TaskKind) -> ChatRequest {
    ChatRequest::new(task, vec![Message::user("classify this alert")])
}

#[tokio::test]
async fn configuration_routes_requests_to_the_providers_with_keys_from_the_environment() {
    let local = MockServer::start().await;
    let gateway = MockServer::start().await;
    let claude = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "local-small",
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": "from local" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 7, "completion_tokens": 3 },
        })))
        .mount(&local)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "local-embed",
            "data": [{ "index": 0, "embedding": [0.5, 0.5] }],
            "usage": { "prompt_tokens": 2, "total_tokens": 2 },
        })))
        .mount(&local)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "gateway-large",
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": "from the gateway" }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 11, "completion_tokens": 5 },
        })))
        .mount(&gateway)
        .await;
    // The first choice for analysis is overloaded, so the router uses the gateway.
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(529).set_body_json(json!({
            "type": "error",
            "error": { "type": "overloaded_error", "message": "Overloaded" },
        })))
        .mount(&claude)
        .await;
    let config = model_section(&format!(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "{local}/v1"
        chat_model = "local-small"
        embedding_model = "local-embed"
        timeout = "5s"

        [model.providers.gateway]
        kind = "openai_compatible"
        base_url = "{gateway}/v1"
        api_key_env = "TEST_GATEWAY_KEY"
        chat_model = "gateway-large"
        max_tokens_field = "max_completion_tokens"
        headers = {{ "x-team" = "soc" }}
        timeout = "5s"

        [model.providers.claude]
        kind = "anthropic"
        base_url = "{claude}"
        api_key_env = "TEST_CLAUDE_KEY"
        chat_model = "claude-large"
        max_output_tokens = 1024
        timeout = "5s"

        [model.routes]
        default = [{{ provider = "claude" }}, {{ provider = "gateway" }}]
        triage = [{{ provider = "local" }}]
        embedding = [{{ provider = "local" }}]

        [model.budget]
        window = "10m"
        total_tokens = 27

        [model.budget.tasks]
        triage = 100
        "#,
        local = local.uri(),
        gateway = gateway.uri(),
        claude = claude.uri(),
    ));
    let router = build_router(
        &config,
        env_of(&[
            ("TEST_GATEWAY_KEY", "gw-key-from-env"),
            ("TEST_CLAUDE_KEY", "claude-key-from-env"),
        ]),
    )
    .unwrap();

    let triage = router.chat(chat(TaskKind::Triage)).await.unwrap();
    let mut analysis_request = chat(TaskKind::Analysis);
    analysis_request.max_output_tokens = Some(300);
    let analysis = router.chat(analysis_request).await.unwrap();
    let embedding = router
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["sign-in burst".to_owned()],
        })
        .await
        .unwrap();

    assert_eq!(triage.provider, "local");
    assert_eq!(triage.message.content, "from local");
    assert_eq!(analysis.provider, "gateway");
    assert_eq!(analysis.message.content, "from the gateway");
    assert_eq!(embedding.provider, "local");
    assert_eq!(embedding.embeddings, vec![vec![0.5, 0.5]]);

    let local_requests = requests(&local).await;
    assert_eq!(local_requests.len(), 2);
    assert_eq!(header(&local_requests[0], "authorization"), None);
    assert_eq!(json_body(&local_requests[0])["model"], json!("local-small"));
    assert_eq!(
        json_body(&local_requests[1]),
        json!({ "model": "local-embed", "input": ["sign-in burst"] })
    );

    let claude_requests = requests(&claude).await;
    assert_eq!(claude_requests.len(), 1);
    assert_eq!(
        header(&claude_requests[0], "x-api-key"),
        Some("claude-key-from-env")
    );
    let claude_body = json_body(&claude_requests[0]);
    assert_eq!(claude_body["model"], json!("claude-large"));
    assert_eq!(claude_body["max_tokens"], json!(300));

    let gateway_requests = requests(&gateway).await;
    assert_eq!(gateway_requests.len(), 1);
    assert_eq!(
        header(&gateway_requests[0], "authorization"),
        Some("Bearer gw-key-from-env")
    );
    assert_eq!(header(&gateway_requests[0], "x-team"), Some("soc"));
    assert_eq!(
        json_body(&gateway_requests[0]),
        json!({
            "model": "gateway-large",
            "messages": [{ "role": "user", "content": "classify this alert" }],
            "max_completion_tokens": 300,
        })
    );

    // 10 + 16 tokens are below the total limit of 27 tokens. 10 + 16 + 2 tokens are not.
    let counters = router.usage();
    assert_eq!(counters.window.tokens(), 28);
    assert_eq!(counters.fallbacks, 1);
    let rejected = router.chat(chat(TaskKind::Triage)).await.unwrap_err();
    assert!(
        matches!(&rejected, Error::BudgetExceeded(text)
            if text == "the total budget of 27 tokens in 600s is spent"),
        "{rejected}"
    );
    assert_eq!(requests(&local).await.len(), 2);
}

#[tokio::test]
async fn configured_key_header_carries_the_key_from_the_environment() {
    let gateway = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/openai/deployments/d1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": "ok" }, "finish_reason": "stop" }],
        })))
        .mount(&gateway)
        .await;
    let config = model_section(&format!(
        r#"
        [model.providers.gateway]
        kind = "openai_compatible"
        base_url = "{gateway}/openai/deployments/d1?api-version=2024-06-01"
        api_key_env = "TEST_GATEWAY_KEY"
        api_key_header = "api-key"
        chat_model = "d1"
        timeout = "5s"

        [model.routes]
        default = [{{ provider = "gateway" }}]
        "#,
        gateway = gateway.uri(),
    ));
    let router = build_router(&config, env_of(&[("TEST_GATEWAY_KEY", "gw-key-from-env")])).unwrap();

    let response = router.chat(chat(TaskKind::Analysis)).await.unwrap();

    assert_eq!(response.provider, "gateway");
    assert_eq!(response.message.content, "ok");
    let sent = requests(&gateway).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(header(&sent[0], "api-key"), Some("gw-key-from-env"));
    assert_eq!(header(&sent[0], "authorization"), None);
    assert_eq!(sent[0].url.query(), Some("api-version=2024-06-01"));

    // A key header with no key variable is a configuration error.
    let no_key = model_section(
        r#"
        [model.providers.gateway]
        kind = "openai_compatible"
        base_url = "https://gw.example.test/v1"
        api_key_header = "api-key"

        [model.routes]
        default = [{ provider = "gateway" }]
        "#,
    );
    assert_eq!(
        config_error(&no_key, |_| None),
        "provider gateway: api_key_header is set, but the provider has no API key"
    );
}

fn hosted_config(variable: &str) -> ModelConfig {
    model_section(&format!(
        r#"
        [model.providers.hosted]
        kind = "openai_compatible"
        base_url = "https://api.example.test/v1"
        api_key_env = "{variable}"
        chat_model = "m"

        [model.routes]
        default = [{{ provider = "hosted" }}]
        "#
    ))
}

#[test]
fn key_variable_that_is_not_set_is_a_configuration_error_that_names_the_variable() {
    let config = hosted_config("AEGIS_TEST_HOSTED_KEY");
    let expected = "provider hosted: the environment variable AEGIS_TEST_HOSTED_KEY is not set";

    assert_eq!(config_error(&config, |_| None), expected);
    assert_eq!(
        config_error(&config, env_of(&[("AEGIS_TEST_HOSTED_KEY", "")])),
        expected
    );
    assert_eq!(
        config_error(&config, env_of(&[("OTHER_KEY", "sk-other")])),
        expected
    );
    assert!(build_router(&config, env_of(&[("AEGIS_TEST_HOSTED_KEY", "sk-test")])).is_ok());
}

#[test]
fn key_in_the_place_of_the_variable_name_stays_out_of_the_error() {
    let config = hosted_config("sk-proj-51f0aa");

    let message = config_error(&config, |_| None);

    assert_eq!(
        message,
        "provider hosted: api_key_env must be the name of an environment variable"
    );
}

#[test]
fn anthropic_provider_needs_a_key_variable() {
    let text = r#"
        [providers.claude]
        kind = "anthropic"
        chat_model = "claude-large"
    "#;
    let error = toml::from_str::<ModelConfig>(text).unwrap_err();
    assert!(
        error.message().contains("missing field `api_key_env`"),
        "{error}"
    );

    let config = model_section(
        r#"
        [model.providers.claude]
        kind = "anthropic"
        api_key_env = "AEGIS_TEST_CLAUDE_KEY"

        [model.routes]
        default = [{ provider = "claude" }]
        "#,
    );
    assert_eq!(
        config_error(&config, |_| None),
        "provider claude: the environment variable AEGIS_TEST_CLAUDE_KEY is not set"
    );
}

#[test]
fn invalid_sections_are_configuration_errors() {
    assert_eq!(
        config_error(&ModelConfig::default(), |_| None),
        "the model configuration has no providers"
    );

    let unknown_route = model_section(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "http://localhost:11434/v1"

        [model.routes]
        default = [{ provider = "local" }]
        reporting = [{ provider = "remote" }]
        "#,
    );
    assert_eq!(
        config_error(&unknown_route, |_| None),
        "the reporting route names the provider remote, which is not configured"
    );

    let no_default = model_section(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "http://localhost:11434/v1"

        [model.routes]
        triage = [{ provider = "local" }]
        "#,
    );
    assert_eq!(
        config_error(&no_default, |_| None),
        "there is no route for the task analysis and no default route"
    );

    let bad_url = model_section(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "localhost:11434"

        [model.routes]
        default = [{ provider = "local" }]
        "#,
    );
    assert_eq!(
        config_error(&bad_url, |_| None),
        "provider local: base_url must use the http or https scheme"
    );
}

#[test]
fn section_has_defaults_and_reads_each_field() {
    let minimal = model_section(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "http://localhost:11434/v1"

        [model.providers.claude]
        kind = "anthropic"
        api_key_env = "K"
        "#,
    );
    assert_eq!(
        minimal.providers["local"],
        ProviderConfig::OpenAiCompatible {
            base_url: "http://localhost:11434/v1".to_owned(),
            api_key_env: None,
            api_key_header: None,
            chat_model: None,
            embedding_model: None,
            timeout: Duration::from_secs(60),
            headers: Default::default(),
            max_tokens_field: MaxTokensField::MaxTokens,
        }
    );
    assert_eq!(
        minimal.providers["claude"],
        ProviderConfig::Anthropic {
            base_url: "https://api.anthropic.com".to_owned(),
            api_key_env: "K".to_owned(),
            chat_model: None,
            timeout: Duration::from_secs(60),
            headers: Default::default(),
            max_output_tokens: 4096,
        }
    );
    assert_eq!(minimal.routes, RoutesConfig::default());
    assert_eq!(minimal.budget, Budget::default());
    assert!(minimal.budget.is_unlimited());

    let full = model_section(
        r#"
        [model.providers.gateway]
        kind = "openai_compatible"
        base_url = "https://gw.example.test/v1"
        api_key_env = "GW_KEY"
        api_key_header = "api-key"
        chat_model = "large"
        embedding_model = "embed"
        timeout = "1m 30s"
        headers = { "x-team" = "soc" }
        max_tokens_field = "max_completion_tokens"

        [model.routes]
        default = [{ provider = "gateway" }]
        response_draft = [{ provider = "gateway", model = "small" }]

        [model.budget]
        window = "15m"
        total_tokens = 1000

        [model.budget.tasks]
        response_draft = 100
        "#,
    );
    assert_eq!(
        full.providers["gateway"],
        ProviderConfig::OpenAiCompatible {
            base_url: "https://gw.example.test/v1".to_owned(),
            api_key_env: Some("GW_KEY".to_owned()),
            api_key_header: Some("api-key".to_owned()),
            chat_model: Some("large".to_owned()),
            embedding_model: Some("embed".to_owned()),
            timeout: Duration::from_secs(90),
            headers: [("x-team".to_owned(), "soc".to_owned())].into(),
            max_tokens_field: MaxTokensField::MaxCompletionTokens,
        }
    );
    assert_eq!(
        full.routes,
        RoutesConfig {
            default: vec![Route::new("gateway")],
            tasks: HashMap::from([(
                TaskKind::ResponseDraft,
                vec![Route::new("gateway").with_model("small")]
            )]),
        }
    );
    assert_eq!(
        full.budget,
        Budget::new(Duration::from_secs(15 * 60))
            .with_total_tokens(1000)
            .with_task_tokens(TaskKind::ResponseDraft, 100)
    );

    // The text form and the JSON form give the same configuration.
    let from_toml: ModelConfig = toml::from_str(&toml::to_string(&full).unwrap()).unwrap();
    assert_eq!(from_toml, full);
    let from_json: ModelConfig =
        serde_json::from_value(serde_json::to_value(&full).unwrap()).unwrap();
    assert_eq!(from_json, full);
}

#[test]
fn yaml_section_gives_the_same_configuration_as_the_toml_section() {
    let from_toml = model_section(
        r#"
        [model.providers.local]
        kind = "openai_compatible"
        base_url = "http://localhost:11434/v1"
        chat_model = "llama3.1:8b"
        embedding_model = "nomic-embed-text"
        timeout = "2m"

        [model.providers.claude]
        kind = "anthropic"
        api_key_env = "ANTHROPIC_API_KEY"
        chat_model = "claude-large"
        max_output_tokens = 2048

        [model.routes]
        default = [{ provider = "claude" }, { provider = "local" }]
        triage = [{ provider = "local", model = "llama3.1:8b" }]

        [model.budget]
        window = "30m"
        total_tokens = 500000

        [model.budget.tasks]
        triage = 100000
        "#,
    );
    let from_yaml: ModelConfig = serde_saphyr::from_str(
        r#"
providers:
  local:
    kind: openai_compatible
    base_url: http://localhost:11434/v1
    chat_model: "llama3.1:8b"
    embedding_model: nomic-embed-text
    timeout: 2m
  claude:
    kind: anthropic
    api_key_env: ANTHROPIC_API_KEY
    chat_model: claude-large
    max_output_tokens: 2048
routes:
  default:
    - provider: claude
    - provider: local
  triage:
    - provider: local
      model: "llama3.1:8b"
budget:
  window: 30m
  total_tokens: 500000
  tasks:
    triage: 100000
"#,
    )
    .unwrap();

    assert_eq!(from_yaml, from_toml);
    assert_eq!(from_yaml.providers.len(), 2);
    assert_eq!(
        from_yaml.routes.tasks[&TaskKind::Triage],
        vec![Route::new("local").with_model("llama3.1:8b")]
    );
    assert_eq!(
        from_yaml.budget,
        Budget::new(Duration::from_secs(30 * 60))
            .with_total_tokens(500_000)
            .with_task_tokens(TaskKind::Triage, 100_000)
    );
    let unknown = serde_saphyr::from_str::<ModelConfig>(
        "providers: {}
budgets: {}
",
    )
    .unwrap_err();
    assert!(
        unknown.to_string().contains("unknown field `budgets`"),
        "{unknown}"
    );
}

#[test]
fn unknown_fields_kinds_and_task_names_are_rejected() {
    let parse = |text: &str| toml::from_str::<ModelConfig>(text).unwrap_err();

    // A key in the file is an error. The file can hold only the name of the variable.
    let inline_key = parse(
        r#"
        [providers.hosted]
        kind = "openai_compatible"
        base_url = "https://api.example.test/v1"
        api_key = "sk-inline"
        "#,
    );
    assert!(
        inline_key.message().starts_with("unknown field `api_key`"),
        "{inline_key}"
    );
    assert!(
        !inline_key.to_string().contains("sk-inline"),
        "{inline_key}"
    );

    let wrong_kind_field = parse(
        r#"
        [providers.claude]
        kind = "anthropic"
        api_key_env = "K"
        embedding_model = "embed"
        "#,
    );
    assert!(
        wrong_kind_field
            .message()
            .starts_with("unknown field `embedding_model`"),
        "{wrong_kind_field}"
    );

    let kind = parse(
        r#"
        [providers.other]
        kind = "other_api"
        base_url = "https://api.example.test/v1"
        "#,
    );
    assert!(
        kind.message().starts_with("unknown variant `other_api`"),
        "{kind}"
    );

    let task = parse(
        r#"
        [routes]
        triagee = [{ provider = "local" }]
        "#,
    );
    assert!(
        task.message().starts_with("unknown variant `triagee`"),
        "{task}"
    );

    let section = parse("[budgets]\ntotal_tokens = 5\n");
    assert!(
        section.message().starts_with("unknown field `budgets`"),
        "{section}"
    );
}
