//! Integration tests for the router with scripted providers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::model::{
    ChatChunk, ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse,
    FinishReason, Message, ModelCapabilities, ModelProvider, TaskKind, Usage,
};
use aegis_contracts::{Error, Result};
use aegis_model::{
    AnthropicConfig, AnthropicProvider, Budget, Route, Router, RouterUsage, UsageCounters,
};
use aegis_testkit::{EMBEDDING_DIMENSIONS, ScriptedModel};
use async_trait::async_trait;
use futures::StreamExt;

use common::{collect, collect_ok, within};

fn request(task: TaskKind) -> ChatRequest {
    ChatRequest::new(task, vec![Message::user("classify this alert")])
}

fn usage(input_tokens: u64, output_tokens: u64) -> Usage {
    Usage {
        input_tokens,
        output_tokens,
    }
}

/// A scripted provider that reports fixed token counts for each answer.
struct Metered {
    inner: ScriptedModel,
    usage: Usage,
}

impl Metered {
    fn new(inner: ScriptedModel, usage: Usage) -> Arc<Self> {
        Arc::new(Self { inner, usage })
    }
}

#[async_trait]
impl ModelProvider for Metered {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> ModelCapabilities {
        self.inner.capabilities()
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let mut response = self.inner.chat(request).await?;
        response.usage = self.usage;
        Ok(response)
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream> {
        let usage = self.usage;
        let stream = self.inner.chat_stream(request).await?;
        Ok(stream
            .map(move |item| {
                item.map(|mut chunk| {
                    if chunk.finish_reason.is_some() {
                        chunk.usage = Some(usage);
                    }
                    chunk
                })
            })
            .boxed())
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let mut response = self.inner.embed(request).await?;
        response.usage = self.usage;
        Ok(response)
    }
}

/// A provider whose stream gives fixed items. It counts the stream requests.
struct StreamOnly {
    name: &'static str,
    items: fn() -> Vec<Result<ChatChunk>>,
    calls: std::sync::atomic::AtomicUsize,
}

impl StreamOnly {
    fn new(name: &'static str, items: fn() -> Vec<Result<ChatChunk>>) -> Arc<Self> {
        Arc::new(Self {
            name,
            items,
            calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl ModelProvider for StreamOnly {
    fn name(&self) -> &str {
        self.name
    }

    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            tools: false,
            streaming: true,
            embeddings: false,
        }
    }

    async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse> {
        Err(Error::Unsupported(format!("{} only streams", self.name)))
    }

    async fn chat_stream(&self, _request: ChatRequest) -> Result<ChatStream> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(futures::stream::iter((self.items)()).boxed())
    }

    async fn embed(&self, _request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        Err(Error::Unsupported(format!("{} only streams", self.name)))
    }
}

fn text_chunk(text: &str) -> ChatChunk {
    ChatChunk {
        delta: text.to_owned(),
        ..ChatChunk::default()
    }
}

#[tokio::test]
async fn router_picks_the_route_of_the_task_kind() {
    let fast = Arc::new(ScriptedModel::new("fast").reply("benign"));
    let strong = Arc::new(
        ScriptedModel::new("strong")
            .reply("the incident is real")
            .reply("the plan"),
    );
    let router = Router::builder()
        .provider(fast.clone())
        .provider(strong.clone())
        .route(TaskKind::Triage, vec![Route::new("fast")])
        .default_routes(vec![Route::new("strong")])
        .build()
        .unwrap();
    assert_eq!(router.name(), "router");
    // Agents hold the router as a shared provider.
    let models: Arc<dyn ModelProvider> = Arc::new(router);

    let triage = models.chat(request(TaskKind::Triage)).await.unwrap();
    let analysis = models.chat(request(TaskKind::Analysis)).await.unwrap();
    let planning = models.chat(request(TaskKind::Planning)).await.unwrap();

    assert_eq!(triage.provider, "fast");
    assert_eq!(triage.message, Message::assistant("benign"));
    assert_eq!(analysis.provider, "strong");
    assert_eq!(analysis.message, Message::assistant("the incident is real"));
    assert_eq!(planning.provider, "strong");
    assert_eq!(planning.message, Message::assistant("the plan"));
    let fast_requests = fast.requests();
    assert_eq!(fast_requests.len(), 1);
    assert_eq!(fast_requests[0], request(TaskKind::Triage));
    let strong_tasks: Vec<TaskKind> = strong
        .requests()
        .iter()
        .map(|request| request.task)
        .collect();
    assert_eq!(strong_tasks, vec![TaskKind::Analysis, TaskKind::Planning]);
}

#[tokio::test]
async fn route_model_goes_to_the_provider_and_the_request_model_wins() {
    let provider = Arc::new(
        ScriptedModel::new("local")
            .reply("one")
            .reply("two")
            .reply("three"),
    );
    let router = Router::builder()
        .provider(provider.clone())
        .route(
            TaskKind::Triage,
            vec![Route::new("local").with_model("small")],
        )
        .default_routes(vec![Route::new("local")])
        .build()
        .unwrap();

    let routed = router.chat(request(TaskKind::Triage)).await.unwrap();
    let mut explicit_request = request(TaskKind::Triage);
    explicit_request.model = Some("explicit".to_owned());
    let explicit = router.chat(explicit_request).await.unwrap();
    let default = router.chat(request(TaskKind::Analysis)).await.unwrap();

    assert_eq!(routed.model, "small");
    assert_eq!(explicit.model, "explicit");
    let models: Vec<Option<String>> = provider
        .requests()
        .into_iter()
        .map(|request| request.model)
        .collect();
    assert_eq!(
        models,
        vec![Some("small".to_owned()), Some("explicit".to_owned()), None]
    );
    // With no model in the request or the route, the provider used its own default.
    assert_eq!(default.model, "scripted");
}

#[tokio::test]
async fn router_falls_back_on_each_error_that_a_different_provider_can_prevent() {
    let failures = [
        Error::Unavailable("primary is down".to_owned()),
        Error::Refused("primary refused".to_owned()),
        Error::RateLimited("primary is busy".to_owned()),
        Error::Timeout("primary is slow".to_owned()),
        Error::Unsupported("primary cannot do this".to_owned()),
    ];
    for failure in failures {
        let label = failure.to_string();
        let primary = Arc::new(ScriptedModel::new("primary").fail(failure));
        let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
        let router = Router::builder()
            .provider(primary.clone())
            .provider(backup.clone())
            .default_routes(vec![
                Route::new("primary").with_model("p-model"),
                Route::new("backup").with_model("b-model"),
            ])
            .build()
            .unwrap();

        let response = router.chat(request(TaskKind::Analysis)).await.unwrap();

        assert_eq!(response.provider, "backup", "{label}");
        assert_eq!(response.model, "b-model", "{label}");
        assert_eq!(response.message, Message::assistant("from the backup"));
        assert_eq!(primary.requests().len(), 1, "{label}");
        assert_eq!(backup.requests().len(), 1, "{label}");
        // Each route gets its own model.
        assert_eq!(primary.requests()[0].model.as_deref(), Some("p-model"));
        assert_eq!(backup.requests()[0].model.as_deref(), Some("b-model"));
        let usage = router.usage();
        assert_eq!(usage.fallbacks, 1, "{label}");
        assert_eq!(usage.total.requests, 1, "{label}");
        assert_eq!(usage.by_provider.get("primary"), None, "{label}");
        assert_eq!(usage.by_provider["backup"].requests, 1, "{label}");
    }
}

/// A check that an error is the same error that a provider returned.
type SameError = fn(&Error) -> bool;

#[tokio::test]
async fn router_does_not_fall_back_on_an_error_that_the_request_causes() {
    let failures: [(Error, SameError); 3] = [
        (
            Error::InvalidInput("the request is not valid".to_owned()),
            |error| matches!(error, Error::InvalidInput(text) if text == "the request is not valid"),
        ),
        (
            Error::Unauthorized("the key is not valid".to_owned()),
            |error| matches!(error, Error::Unauthorized(text) if text == "the key is not valid"),
        ),
        (
            Error::Config("no default model".to_owned()),
            |error| matches!(error, Error::Config(text) if text == "no default model"),
        ),
    ];
    for (failure, is_same) in failures {
        let primary = Arc::new(ScriptedModel::new("primary").fail(failure));
        let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
        let router = Router::builder()
            .provider(primary.clone())
            .provider(backup.clone())
            .default_routes(vec![Route::new("primary"), Route::new("backup")])
            .build()
            .unwrap();

        let error = router.chat(request(TaskKind::Analysis)).await.unwrap_err();

        assert!(is_same(&error), "{error}");
        assert_eq!(primary.requests().len(), 1);
        assert_eq!(backup.requests().len(), 0, "{error}");
        assert_eq!(backup.remaining(), 1);
        assert_eq!(router.usage().fallbacks, 0);
    }
}

#[tokio::test]
async fn router_returns_the_last_error_when_all_routes_fail() {
    let first =
        Arc::new(ScriptedModel::new("first").fail(Error::Unavailable("first is down".to_owned())));
    let second =
        Arc::new(ScriptedModel::new("second").fail(Error::Refused("second refused".to_owned())));
    let router = Router::builder()
        .provider(first.clone())
        .provider(second.clone())
        .default_routes(vec![Route::new("first"), Route::new("second")])
        .build()
        .unwrap();

    let error = router.chat(request(TaskKind::Analysis)).await.unwrap_err();

    assert!(
        matches!(&error, Error::Refused(text) if text == "second refused"),
        "{error}"
    );
    assert_eq!(first.requests().len(), 1);
    assert_eq!(second.requests().len(), 1);
    let usage = router.usage();
    assert_eq!(usage.fallbacks, 1);
    assert_eq!(usage.total, UsageCounters::default());
}

#[tokio::test]
async fn spent_total_budget_stops_the_request_without_a_provider_call() {
    let provider = Metered::new(
        ScriptedModel::new("metered")
            .reply("one")
            .reply("two")
            .reply("three"),
        usage(60, 40),
    );
    let router = Router::builder()
        .provider(provider.clone())
        .default_routes(vec![Route::new("metered")])
        .budget(Budget::new(Duration::from_secs(3600)).with_total_tokens(150))
        .build()
        .unwrap();

    // 0 and 100 tokens are below the limit of 150. 200 tokens are not.
    router.chat(request(TaskKind::Triage)).await.unwrap();
    router.chat(request(TaskKind::Analysis)).await.unwrap();
    let error = router.chat(request(TaskKind::Triage)).await.unwrap_err();

    assert!(
        matches!(&error, Error::BudgetExceeded(text)
            if text == "the total budget of 150 tokens in 3600s is spent"),
        "{error}"
    );
    assert!(!error.is_retryable());
    assert_eq!(provider.inner.requests().len(), 2);
    assert_eq!(provider.inner.remaining(), 1);
    let stream_error = router
        .chat_stream(request(TaskKind::Triage))
        .await
        .err()
        .unwrap();
    let embed_error = router
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["text".to_owned()],
        })
        .await
        .unwrap_err();
    assert!(matches!(stream_error, Error::BudgetExceeded(_)));
    assert!(matches!(embed_error, Error::BudgetExceeded(_)));
    assert_eq!(provider.inner.requests().len(), 2);
    let counters = router.usage();
    assert_eq!(counters.budget_rejections, 3);
    assert_eq!(counters.window.tokens(), 200);
}

#[tokio::test]
async fn task_budget_limits_only_its_task_kind() {
    let provider = Metered::new(
        ScriptedModel::new("metered")
            .reply("triage one")
            .reply("analysis one")
            .reply("analysis two"),
        usage(70, 30),
    );
    let router = Router::builder()
        .provider(provider.clone())
        .default_routes(vec![Route::new("metered")])
        .budget(Budget::new(Duration::from_secs(60)).with_task_tokens(TaskKind::Triage, 100))
        .build()
        .unwrap();

    router.chat(request(TaskKind::Triage)).await.unwrap();
    let triage = router.chat(request(TaskKind::Triage)).await.unwrap_err();
    let analysis = router.chat(request(TaskKind::Analysis)).await.unwrap();
    let analysis_again = router.chat(request(TaskKind::Analysis)).await.unwrap();

    assert!(
        matches!(&triage, Error::BudgetExceeded(text)
            if text == "the triage budget of 100 tokens in 60s is spent"),
        "{triage}"
    );
    assert_eq!(analysis.message, Message::assistant("analysis one"));
    assert_eq!(analysis_again.message, Message::assistant("analysis two"));
    assert_eq!(provider.inner.requests().len(), 3);
    assert_eq!(router.usage().budget_rejections, 1);
}

#[tokio::test(start_paused = true)]
async fn new_budget_window_admits_requests_again() {
    let provider = Metered::new(
        ScriptedModel::new("metered").reply("one").reply("two"),
        usage(100, 0),
    );
    let router = Router::builder()
        .provider(provider.clone())
        .default_routes(vec![Route::new("metered")])
        .budget(Budget::new(Duration::from_secs(60)).with_total_tokens(100))
        .build()
        .unwrap();

    router.chat(request(TaskKind::Triage)).await.unwrap();
    tokio::time::advance(Duration::from_secs(59)).await;
    let rejected = router.chat(request(TaskKind::Triage)).await.unwrap_err();
    assert!(matches!(rejected, Error::BudgetExceeded(_)));

    tokio::time::advance(Duration::from_secs(1)).await;
    let admitted = router.chat(request(TaskKind::Triage)).await.unwrap();

    assert_eq!(admitted.message, Message::assistant("two"));
    let counters = router.usage();
    assert_eq!(counters.window.tokens(), 100);
    assert_eq!(counters.total.tokens(), 200);
    assert_eq!(counters.budget_rejections, 1);
}

#[tokio::test]
async fn usage_counters_follow_each_task_kind_and_each_provider() {
    let fast = Metered::new(
        ScriptedModel::new("fast").reply("one").reply("two"),
        usage(10, 2),
    );
    let strong = Metered::new(ScriptedModel::new("strong").reply("three"), usage(500, 80));
    let router = Router::builder()
        .provider(fast)
        .provider(strong)
        .route(TaskKind::Triage, vec![Route::new("fast")])
        .route(TaskKind::Embedding, vec![Route::new("fast")])
        .default_routes(vec![Route::new("strong")])
        .build()
        .unwrap();
    assert_eq!(router.usage(), RouterUsage::default());

    router.chat(request(TaskKind::Triage)).await.unwrap();
    router.chat(request(TaskKind::Triage)).await.unwrap();
    router.chat(request(TaskKind::Analysis)).await.unwrap();
    router
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["text".to_owned()],
        })
        .await
        .unwrap();

    let triage = UsageCounters {
        requests: 2,
        input_tokens: 20,
        output_tokens: 4,
    };
    let analysis = UsageCounters {
        requests: 1,
        input_tokens: 500,
        output_tokens: 80,
    };
    let embedding = UsageCounters {
        requests: 1,
        input_tokens: 10,
        output_tokens: 2,
    };
    let total = UsageCounters {
        requests: 4,
        input_tokens: 530,
        output_tokens: 86,
    };
    let by_task = HashMap::from([
        (TaskKind::Triage, triage),
        (TaskKind::Analysis, analysis),
        (TaskKind::Embedding, embedding),
    ]);
    assert_eq!(
        router.usage(),
        RouterUsage {
            total,
            by_task: by_task.clone(),
            by_provider: HashMap::from([
                (
                    "fast".to_owned(),
                    UsageCounters {
                        requests: 3,
                        input_tokens: 30,
                        output_tokens: 6,
                    }
                ),
                ("strong".to_owned(), analysis),
            ]),
            window: total,
            window_by_task: by_task,
            budget_rejections: 0,
            fallbacks: 0,
        }
    );
    assert_eq!(total.tokens(), 616);
}

#[tokio::test]
async fn stream_routes_by_task_kind_and_records_the_usage_of_the_last_chunk() {
    let provider = Metered::new(
        ScriptedModel::new("metered").reply("true positive"),
        usage(40, 9),
    );
    let router = Router::builder()
        .provider(provider.clone())
        .default_routes(vec![Route::new("metered").with_model("stream-model")])
        .build()
        .unwrap();

    let stream = router.chat_stream(request(TaskKind::Triage)).await.unwrap();
    // The request counts when the stream starts. The tokens count when the usage arrives.
    assert_eq!(
        router.usage().total,
        UsageCounters {
            requests: 1,
            input_tokens: 0,
            output_tokens: 0,
        }
    );
    let chunks = collect_ok(stream).await;

    let text: String = chunks.iter().map(|chunk| chunk.delta.as_str()).collect();
    assert_eq!(text, "true positive");
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[2].finish_reason, Some(FinishReason::Stop));
    assert_eq!(chunks[2].usage, Some(usage(40, 9)));
    assert_eq!(
        provider.inner.requests()[0].model.as_deref(),
        Some("stream-model")
    );
    let counters = router.usage();
    assert_eq!(
        counters.by_task[&TaskKind::Triage],
        UsageCounters {
            requests: 1,
            input_tokens: 40,
            output_tokens: 9,
        }
    );
    assert_eq!(counters.by_provider["metered"].tokens(), 49);
}

#[tokio::test]
async fn stream_request_model_wins_over_the_route_model() {
    let provider = Arc::new(ScriptedModel::new("local").reply("ok"));
    let router = Router::builder()
        .provider(provider.clone())
        .default_routes(vec![Route::new("local").with_model("route-model")])
        .build()
        .unwrap();
    let mut explicit = request(TaskKind::Triage);
    explicit.model = Some("explicit".to_owned());

    let stream = router.chat_stream(explicit).await.unwrap();
    let chunks = collect_ok(stream).await;

    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].delta, "ok");
    let requests = provider.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model.as_deref(), Some("explicit"));
}

#[tokio::test]
async fn stream_falls_back_when_the_provider_rejects_the_request() {
    let primary = Arc::new(
        ScriptedModel::new("primary").fail(Error::Unavailable("primary is down".to_owned())),
    );
    let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
    let router = Router::builder()
        .provider(primary.clone())
        .provider(backup.clone())
        .default_routes(vec![Route::new("primary"), Route::new("backup")])
        .build()
        .unwrap();

    let stream = router.chat_stream(request(TaskKind::Triage)).await.unwrap();
    let chunks = collect_ok(stream).await;

    let text: String = chunks.iter().map(|chunk| chunk.delta.as_str()).collect();
    assert_eq!(text, "from the backup");
    assert_eq!(primary.requests().len(), 1);
    assert_eq!(backup.requests().len(), 1);
    assert_eq!(router.usage().fallbacks, 1);
}

#[tokio::test]
async fn stream_falls_back_when_the_first_item_is_an_error() {
    let primary = StreamOnly::new("primary", || {
        vec![Err(Error::Refused("primary refused".to_owned()))]
    });
    let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
    let router = Router::builder()
        .provider(primary.clone())
        .provider(backup.clone())
        .default_routes(vec![Route::new("primary"), Route::new("backup")])
        .build()
        .unwrap();

    let stream = within(router.chat_stream(request(TaskKind::Triage)))
        .await
        .unwrap();
    let chunks = collect_ok(stream).await;

    let text: String = chunks.iter().map(|chunk| chunk.delta.as_str()).collect();
    assert_eq!(text, "from the backup");
    assert_eq!(primary.calls(), 1);
    assert_eq!(backup.requests().len(), 1);
    let counters = router.usage();
    assert_eq!(counters.fallbacks, 1);
    assert_eq!(counters.by_provider.get("primary"), None);
    assert_eq!(counters.by_provider["backup"].requests, 1);
}

#[tokio::test]
async fn stream_does_not_fall_back_after_the_first_chunk() {
    let primary = StreamOnly::new("primary", || {
        vec![
            Ok(text_chunk("partial ")),
            Err(Error::Unavailable("primary broke".to_owned())),
        ]
    });
    let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
    let router = Router::builder()
        .provider(primary.clone())
        .provider(backup.clone())
        .default_routes(vec![Route::new("primary"), Route::new("backup")])
        .build()
        .unwrap();

    let stream = router.chat_stream(request(TaskKind::Triage)).await.unwrap();
    let items = collect(stream).await;

    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap(), &text_chunk("partial "));
    assert!(
        matches!(&items[1], Err(Error::Unavailable(text)) if text == "primary broke"),
        "{items:?}"
    );
    assert_eq!(backup.requests().len(), 0);
    assert_eq!(router.usage().fallbacks, 0);
}

#[tokio::test]
async fn stream_returns_an_error_of_the_first_item_that_the_request_causes() {
    let primary = StreamOnly::new("primary", || {
        vec![Err(Error::InvalidInput(
            "the request is not valid".to_owned(),
        ))]
    });
    let backup = Arc::new(ScriptedModel::new("backup").reply("from the backup"));
    let router = Router::builder()
        .provider(primary)
        .provider(backup.clone())
        .default_routes(vec![Route::new("primary"), Route::new("backup")])
        .build()
        .unwrap();

    let error = router
        .chat_stream(request(TaskKind::Triage))
        .await
        .err()
        .unwrap();

    assert!(
        matches!(&error, Error::InvalidInput(text) if text == "the request is not valid"),
        "{error}"
    );
    assert_eq!(backup.requests().len(), 0);
}

#[tokio::test]
async fn embed_uses_the_embedding_route_and_falls_back_from_a_provider_without_embeddings() {
    // This provider returns `Unsupported` for embeddings and does not use the network.
    let chat_only = AnthropicProvider::new(AnthropicConfig::new("claude", "test-key")).unwrap();
    let embedder = Arc::new(ScriptedModel::new("embedder"));
    let router = Router::builder()
        .provider(Arc::new(chat_only))
        .provider(embedder)
        .route(
            TaskKind::Embedding,
            vec![
                Route::new("claude"),
                Route::new("embedder").with_model("embed-small"),
            ],
        )
        .default_routes(vec![Route::new("claude")])
        .build()
        .unwrap();

    let routed = router
        .embed(EmbeddingRequest {
            model: None,
            input: vec!["sign-in burst".to_owned(), "vault access".to_owned()],
        })
        .await
        .unwrap();
    let explicit = router
        .embed(EmbeddingRequest {
            model: Some("embed-large".to_owned()),
            input: vec!["sign-in burst".to_owned()],
        })
        .await
        .unwrap();

    assert_eq!(routed.provider, "embedder");
    assert_eq!(routed.model, "embed-small");
    assert_eq!(routed.embeddings.len(), 2);
    assert_eq!(routed.embeddings[0].len(), EMBEDDING_DIMENSIONS);
    assert_eq!(
        routed.embeddings[0],
        aegis_testkit::embed_text("sign-in burst")
    );
    assert_eq!(explicit.model, "embed-large");
    let counters = router.usage();
    assert_eq!(counters.fallbacks, 2);
    assert_eq!(counters.by_task[&TaskKind::Embedding].requests, 2);
}

#[tokio::test]
async fn capabilities_are_the_union_of_the_providers_and_the_name_is_configurable() {
    let stream_only = StreamOnly::new("stream-only", Vec::new);
    let chat_only = AnthropicProvider::new(AnthropicConfig::new("claude", "test-key")).unwrap();
    let narrow = Router::builder()
        .name("soc-router")
        .provider(stream_only.clone())
        .default_routes(vec![Route::new("stream-only")])
        .build()
        .unwrap();
    let wide = Router::builder()
        .provider(stream_only)
        .provider(Arc::new(chat_only))
        .provider(Arc::new(ScriptedModel::new("scripted")))
        .default_routes(vec![Route::new("claude")])
        .build()
        .unwrap();

    assert_eq!(narrow.name(), "soc-router");
    assert_eq!(
        narrow.capabilities(),
        ModelCapabilities {
            tools: false,
            streaming: true,
            embeddings: false,
        }
    );
    assert_eq!(
        wide.capabilities(),
        ModelCapabilities {
            tools: true,
            streaming: true,
            embeddings: true,
        }
    );
}

fn build_error(builder: aegis_model::RouterBuilder) -> String {
    match builder.build() {
        Err(Error::Config(text)) => text,
        Err(error) => panic!("the error is not a configuration error: {error}"),
        Ok(_) => panic!("the builder accepted invalid settings"),
    }
}

#[test]
fn builder_rejects_settings_that_cannot_route_each_task() {
    let scripted = |name: &str| -> Arc<dyn ModelProvider> { Arc::new(ScriptedModel::new(name)) };

    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .default_routes(vec![Route::new("a"), Route::new("missing")])
        ),
        "the default route names the provider missing, which is not configured"
    );
    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .route(TaskKind::ResponseDraft, vec![Route::new("b")])
                .default_routes(vec![Route::new("a")])
        ),
        "the response_draft route names the provider b, which is not configured"
    );
    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .provider(scripted("a"))
                .default_routes(vec![Route::new("a")])
        ),
        "the router has two providers with the name a"
    );
    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .route(TaskKind::Triage, Vec::new())
                .default_routes(vec![Route::new("a")])
        ),
        "the triage route list is empty; remove it to use the default routes"
    );
    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .route(TaskKind::Triage, vec![Route::new("a")])
        ),
        "there is no route for the task analysis and no default route"
    );
    assert_eq!(
        build_error(
            Router::builder()
                .provider(scripted("a"))
                .default_routes(vec![Route::new("a")])
                .budget(Budget::new(Duration::ZERO).with_total_tokens(10))
        ),
        "the budget window must be longer than zero"
    );
}

#[test]
fn builder_accepts_one_route_for_each_task_kind_without_a_default() {
    let mut builder = Router::builder().provider(Arc::new(ScriptedModel::new("a")));
    for task in aegis_model::TASK_KINDS {
        builder = builder.route(task, vec![Route::new("a")]);
    }
    let router = builder.build().unwrap();
    assert_eq!(router.routes(TaskKind::Reporting), [Route::new("a")]);
    assert!(router.budget().is_unlimited());
}
