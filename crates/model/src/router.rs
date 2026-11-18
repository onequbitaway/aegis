//! The model router: route selection, fallback, token budgets, and usage counters.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use aegis_contracts::model::{
    ChatRequest, ChatResponse, ChatStream, EmbeddingRequest, EmbeddingResponse, ModelCapabilities,
    ModelProvider, TaskKind, Usage,
};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

/// The default name of a router.
pub const DEFAULT_ROUTER_NAME: &str = "router";

/// The default length of the budget window.
pub const DEFAULT_BUDGET_WINDOW: Duration = Duration::from_secs(60 * 60);

/// All task kinds, in the order of the contract.
pub const TASK_KINDS: [TaskKind; 6] = [
    TaskKind::Triage,
    TaskKind::Analysis,
    TaskKind::Planning,
    TaskKind::ResponseDraft,
    TaskKind::Reporting,
    TaskKind::Embedding,
];

/// Returns the name of a task kind as the configuration writes it.
#[must_use]
pub fn task_name(task: TaskKind) -> &'static str {
    match task {
        TaskKind::Triage => "triage",
        TaskKind::Analysis => "analysis",
        TaskKind::Planning => "planning",
        TaskKind::ResponseDraft => "response_draft",
        TaskKind::Reporting => "reporting",
        TaskKind::Embedding => "embedding",
    }
}

/// One candidate for a task: a provider and, optionally, one model of that provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The name of the provider.
    pub provider: String,
    /// The model to use. With `None`, the provider uses its default model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl Route {
    /// Makes a route to the default model of `provider`.
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: None,
        }
    }

    /// Sets the model of the route.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

fn default_budget_window() -> Duration {
    DEFAULT_BUDGET_WINDOW
}

/// Token limits over a time window.
///
/// The router counts input tokens plus output tokens. The first window starts when the
/// router starts. At the end of each window, the window counters go back to zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// The length of the window, for example `1h` in a configuration file.
    #[serde(default = "default_budget_window", with = "humantime_serde")]
    pub window: Duration,
    /// The limit for all task kinds together. `None` means no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    /// The limit for each task kind. A task kind that is not in the map has no limit.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tasks: HashMap<TaskKind, u64>,
}

impl Default for Budget {
    /// Makes a budget with no limits.
    fn default() -> Self {
        Self::new(DEFAULT_BUDGET_WINDOW)
    }
}

impl Budget {
    /// Makes a budget with no limits and a window of `window`.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            total_tokens: None,
            tasks: HashMap::new(),
        }
    }

    /// Sets the limit for all task kinds together.
    #[must_use]
    pub fn with_total_tokens(mut self, limit: u64) -> Self {
        self.total_tokens = Some(limit);
        self
    }

    /// Sets the limit for one task kind.
    #[must_use]
    pub fn with_task_tokens(mut self, task: TaskKind, limit: u64) -> Self {
        self.tasks.insert(task, limit);
        self
    }

    /// Returns `true` if the budget has no limit.
    #[must_use]
    pub fn is_unlimited(&self) -> bool {
        self.total_tokens.is_none() && self.tasks.is_empty()
    }
}

/// Request and token counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UsageCounters {
    /// The number of requests that a provider answered.
    pub requests: u64,
    /// The number of input tokens.
    pub input_tokens: u64,
    /// The number of output tokens.
    pub output_tokens: u64,
}

impl UsageCounters {
    /// Returns the input tokens plus the output tokens.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    fn add(&mut self, requests: u64, usage: Usage) {
        self.requests = self.requests.saturating_add(requests);
        self.input_tokens = self.input_tokens.saturating_add(usage.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(usage.output_tokens);
    }
}

/// The usage counters of a [`Router`] at one moment.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouterUsage {
    /// The counts since the router started.
    pub total: UsageCounters,
    /// The counts since the router started, for each task kind.
    pub by_task: HashMap<TaskKind, UsageCounters>,
    /// The counts since the router started, for each provider.
    pub by_provider: HashMap<String, UsageCounters>,
    /// The counts in the current budget window.
    pub window: UsageCounters,
    /// The counts in the current budget window, for each task kind.
    pub window_by_task: HashMap<TaskKind, UsageCounters>,
    /// The number of requests that a budget limit stopped.
    pub budget_rejections: u64,
    /// The number of times that the router went to the next route after a failure.
    pub fallbacks: u64,
}

struct Ledger {
    window_start: Instant,
    usage: RouterUsage,
}

impl Ledger {
    /// Starts a new window if the current window is complete.
    fn roll(&mut self, window: Duration, now: Instant) {
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed < window {
            return;
        }
        // The new window starts on a multiple of the window length after the first start.
        let periods = elapsed.as_nanos() / window.as_nanos().max(1);
        self.window_start = u32::try_from(periods)
            .ok()
            .and_then(|periods| window.checked_mul(periods))
            .and_then(|advance| self.window_start.checked_add(advance))
            .unwrap_or(now);
        self.usage.window = UsageCounters::default();
        self.usage.window_by_task.clear();
    }
}

/// The accounting state. The stream of a streamed answer shares it with the router.
#[derive(Clone)]
struct Accounts {
    budget: Arc<Budget>,
    ledger: Arc<Mutex<Ledger>>,
}

impl Accounts {
    fn new(budget: Budget) -> Self {
        Self {
            budget: Arc::new(budget),
            ledger: Arc::new(Mutex::new(Ledger {
                window_start: Instant::now(),
                usage: RouterUsage::default(),
            })),
        }
    }

    /// Locks the ledger and brings the window up to date.
    fn ledger(&self) -> MutexGuard<'_, Ledger> {
        // The ledger holds only counters, so the data of a poisoned lock is still correct.
        let mut ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.roll(self.budget.window, Instant::now());
        ledger
    }

    /// Rejects a request for `task` when a budget limit is spent.
    fn admit(&self, task: TaskKind) -> Result<()> {
        let mut ledger = self.ledger();
        let window = self.budget.window;
        let total_spent = ledger.usage.window.tokens();
        let task_spent = ledger
            .usage
            .window_by_task
            .get(&task)
            .map_or(0, UsageCounters::tokens);
        let rejection = match (self.budget.total_tokens, self.budget.tasks.get(&task)) {
            (Some(limit), _) if total_spent >= limit => Some(format!(
                "the total budget of {limit} tokens in {window:?} is spent"
            )),
            (_, Some(&limit)) if task_spent >= limit => Some(format!(
                "the {} budget of {limit} tokens in {window:?} is spent",
                task_name(task)
            )),
            _ => None,
        };
        match rejection {
            Some(message) => {
                ledger.usage.budget_rejections = ledger.usage.budget_rejections.saturating_add(1);
                Err(Error::BudgetExceeded(message))
            }
            None => Ok(()),
        }
    }

    /// Adds requests and tokens to the counters.
    fn record(&self, task: TaskKind, provider: &str, requests: u64, usage: Usage) {
        let mut ledger = self.ledger();
        let counters = &mut ledger.usage;
        counters.total.add(requests, usage);
        counters.window.add(requests, usage);
        counters
            .by_task
            .entry(task)
            .or_default()
            .add(requests, usage);
        counters
            .window_by_task
            .entry(task)
            .or_default()
            .add(requests, usage);
        match counters.by_provider.get_mut(provider) {
            Some(provider_counters) => provider_counters.add(requests, usage),
            None => {
                let mut provider_counters = UsageCounters::default();
                provider_counters.add(requests, usage);
                counters
                    .by_provider
                    .insert(provider.to_owned(), provider_counters);
            }
        }
    }

    fn record_fallback(&self) {
        let mut ledger = self.ledger();
        ledger.usage.fallbacks = ledger.usage.fallbacks.saturating_add(1);
    }
}

/// Returns `true` if a different provider can succeed after `error`.
fn falls_back(error: &Error) -> bool {
    error.is_retryable() || matches!(error, Error::Refused(_) | Error::Unsupported(_))
}

/// Builds a [`Router`].
#[derive(Default)]
pub struct RouterBuilder {
    name: Option<String>,
    providers: Vec<Arc<dyn ModelProvider>>,
    routes: HashMap<TaskKind, Vec<Route>>,
    default_routes: Vec<Route>,
    budget: Budget,
}

impl RouterBuilder {
    /// Sets the name that [`ModelProvider::name`] returns for the router.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds a provider. A route refers to the provider by [`ModelProvider::name`].
    #[must_use]
    pub fn provider(mut self, provider: Arc<dyn ModelProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Sets the ordered routes for one task kind. The first route is the first choice.
    #[must_use]
    pub fn route(mut self, task: TaskKind, routes: Vec<Route>) -> Self {
        self.routes.insert(task, routes);
        self
    }

    /// Sets the ordered routes for each task kind that has no routes of its own.
    #[must_use]
    pub fn default_routes(mut self, routes: Vec<Route>) -> Self {
        self.default_routes = routes;
        self
    }

    /// Sets the token budget.
    #[must_use]
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Checks the settings and makes the router.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] in these conditions:
    ///
    /// - Two providers have the same name.
    /// - A route names a provider that the builder does not have.
    /// - A task kind has an empty list of routes.
    /// - A task kind has no routes and there are no default routes.
    /// - The budget has a limit and a window of zero length.
    pub fn build(self) -> Result<Router> {
        let mut providers: HashMap<String, Arc<dyn ModelProvider>> = HashMap::new();
        for provider in self.providers {
            let name = provider.name().to_owned();
            if providers.insert(name.clone(), provider).is_some() {
                return Err(Error::Config(format!(
                    "the router has two providers with the name {name}"
                )));
            }
        }
        let lists = self
            .routes
            .iter()
            .map(|(task, routes)| (task_name(*task), routes))
            .chain(std::iter::once(("default", &self.default_routes)));
        for (list, routes) in lists {
            if let Some(route) = routes
                .iter()
                .find(|route| !providers.contains_key(&route.provider))
            {
                return Err(Error::Config(format!(
                    "the {list} route names the provider {}, which is not configured",
                    route.provider
                )));
            }
        }
        for task in TASK_KINDS {
            match self.routes.get(&task) {
                Some(routes) if routes.is_empty() => {
                    return Err(Error::Config(format!(
                        "the {} route list is empty; remove it to use the default routes",
                        task_name(task)
                    )));
                }
                None if self.default_routes.is_empty() => {
                    return Err(Error::Config(format!(
                        "there is no route for the task {} and no default route",
                        task_name(task)
                    )));
                }
                _ => {}
            }
        }
        if !self.budget.is_unlimited() && self.budget.window.is_zero() {
            return Err(Error::Config(
                "the budget window must be longer than zero".to_owned(),
            ));
        }
        Ok(Router {
            name: self.name.unwrap_or_else(|| DEFAULT_ROUTER_NAME.to_owned()),
            providers,
            routes: self.routes,
            default_routes: self.default_routes,
            accounts: Accounts::new(self.budget),
        })
    }
}

/// A model provider that selects one of many providers for each request.
///
/// # Selection
///
/// The router reads [`ChatRequest::task`] and takes the routes of that task kind, or the
/// default routes. An embedding request uses [`TaskKind::Embedding`]. The first route is
/// the first choice. A model in the request overrides the model of each route.
///
/// # Fallback
///
/// When a provider fails with an error that a different provider can prevent, the router
/// tries the next route. These errors are the retryable errors, [`Error::Refused`], and
/// [`Error::Unsupported`]. A different error stops the request. When all routes fail, the
/// router returns the last error. For a stream, the router can change the route until the
/// first chunk arrives.
///
/// # Budget
///
/// The router rejects a request with [`Error::BudgetExceeded`] when a limit of the
/// [`Budget`] is spent. It does not call a provider for such a request. The router adds
/// the token counts of each answer to the counters, so requests that are in progress can
/// exceed a limit.
pub struct Router {
    name: String,
    providers: HashMap<String, Arc<dyn ModelProvider>>,
    routes: HashMap<TaskKind, Vec<Route>>,
    default_routes: Vec<Route>,
    accounts: Accounts,
}

impl Router {
    /// Starts a builder with no providers, no routes, and no budget limits.
    #[must_use]
    pub fn builder() -> RouterBuilder {
        RouterBuilder::default()
    }

    /// Returns the usage counters. The window counters are for the current window.
    #[must_use]
    pub fn usage(&self) -> RouterUsage {
        self.accounts.ledger().usage.clone()
    }

    /// Returns the budget of the router.
    #[must_use]
    pub fn budget(&self) -> &Budget {
        &self.accounts.budget
    }

    /// Returns the ordered routes that the router uses for `task`.
    #[must_use]
    pub fn routes(&self, task: TaskKind) -> &[Route] {
        self.routes.get(&task).unwrap_or(&self.default_routes)
    }

    /// Calls the routes of `task` in order until one succeeds.
    ///
    /// `call` gets the provider and the model of the route. It returns the answer. The
    /// result has the answer and the name of the provider that gave it.
    async fn dispatch<T, F, Fut>(&self, task: TaskKind, call: F) -> Result<(T, &str)>
    where
        F: Fn(Arc<dyn ModelProvider>, Option<String>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.accounts.admit(task)?;
        let routes = self.routes(task);
        let mut last_error = None;
        for (position, route) in routes.iter().enumerate() {
            let provider = self.providers.get(&route.provider).ok_or_else(|| {
                Error::Config(format!(
                    "the route names the provider {}, which is not configured",
                    route.provider
                ))
            })?;
            match call(Arc::clone(provider), route.model.clone()).await {
                Ok(answer) => return Ok((answer, route.provider.as_str())),
                Err(error) if falls_back(&error) => {
                    if position.saturating_add(1) < routes.len() {
                        self.accounts.record_fallback();
                        tracing::warn!(
                            router = %self.name,
                            task = task_name(task),
                            provider = %route.provider,
                            %error,
                            "the provider failed; the router tries the next route"
                        );
                    }
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            Error::Config(format!(
                "there is no route for the task {}",
                task_name(task)
            ))
        }))
    }
}

impl fmt::Debug for Router {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut providers: Vec<&String> = self.providers.keys().collect();
        providers.sort();
        formatter
            .debug_struct("Router")
            .field("name", &self.name)
            .field("providers", &providers)
            .field("routes", &self.routes)
            .field("default_routes", &self.default_routes)
            .field("budget", &self.accounts.budget)
            .finish()
    }
}

#[async_trait]
impl ModelProvider for Router {
    fn name(&self) -> &str {
        &self.name
    }

    /// Returns each capability that one or more providers have.
    fn capabilities(&self) -> ModelCapabilities {
        self.providers
            .values()
            .map(|provider| provider.capabilities())
            .fold(ModelCapabilities::default(), |all, one| ModelCapabilities {
                tools: all.tools || one.tools,
                streaming: all.streaming || one.streaming,
                embeddings: all.embeddings || one.embeddings,
            })
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let task = request.task;
        let (response, provider) = self
            .dispatch(task, |provider, route_model| {
                let mut attempt = request.clone();
                attempt.model = attempt.model.or(route_model);
                async move { provider.chat(attempt).await }
            })
            .await?;
        self.accounts.record(task, provider, 1, response.usage);
        Ok(response)
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChatStream> {
        let task = request.task;
        let (stream, provider) = self
            .dispatch(task, |provider, route_model| {
                let mut attempt = request.clone();
                attempt.model = attempt.model.or(route_model);
                async move {
                    let mut stream = provider.chat_stream(attempt).await?;
                    // The first item shows if the provider accepted the request. After
                    // the first chunk, the caller has output and a new route is not possible.
                    let stream: ChatStream = match stream.next().await {
                        Some(Err(error)) => return Err(error),
                        Some(Ok(first)) => futures::stream::once(std::future::ready(Ok(first)))
                            .chain(stream)
                            .boxed(),
                        None => futures::stream::empty().boxed(),
                    };
                    Ok(stream)
                }
            })
            .await?;
        self.accounts.record(task, provider, 1, Usage::default());
        let accounts = self.accounts.clone();
        let provider = provider.to_owned();
        Ok(stream
            .inspect(move |item| {
                if let Ok(chunk) = item
                    && let Some(usage) = chunk.usage
                {
                    accounts.record(task, &provider, 0, usage);
                }
            })
            .boxed())
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let task = TaskKind::Embedding;
        let (response, provider) = self
            .dispatch(task, |provider, route_model| {
                let mut attempt = request.clone();
                attempt.model = attempt.model.or(route_model);
                async move { provider.embed(attempt).await }
            })
            .await?;
        self.accounts.record(task, provider, 1, response.usage);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input_tokens: u64, output_tokens: u64) -> Usage {
        Usage {
            input_tokens,
            output_tokens,
        }
    }

    #[test]
    fn fallback_applies_to_retryable_refused_and_unsupported_errors_only() {
        let text = || "x".to_owned();
        assert!(falls_back(&Error::Unavailable(text())));
        assert!(falls_back(&Error::RateLimited(text())));
        assert!(falls_back(&Error::Timeout(text())));
        assert!(falls_back(&Error::Refused(text())));
        assert!(falls_back(&Error::Unsupported(text())));
        assert!(!falls_back(&Error::InvalidInput(text())));
        assert!(!falls_back(&Error::Unauthorized(text())));
        assert!(!falls_back(&Error::Config(text())));
        assert!(!falls_back(&Error::NotFound(text())));
        assert!(!falls_back(&Error::Serialization(text())));
        assert!(!falls_back(&Error::BudgetExceeded(text())));
    }

    #[test]
    fn task_names_match_the_serialized_names() {
        for task in TASK_KINDS {
            assert_eq!(
                serde_json::to_value(task).unwrap(),
                serde_json::Value::String(task_name(task).to_owned())
            );
        }
    }

    #[test]
    fn counters_add_and_saturate() {
        let mut counters = UsageCounters::default();
        counters.add(1, usage(10, 5));
        counters.add(2, usage(1, 1));
        assert_eq!(
            counters,
            UsageCounters {
                requests: 3,
                input_tokens: 11,
                output_tokens: 6,
            }
        );
        assert_eq!(counters.tokens(), 17);
        counters.add(u64::MAX, usage(u64::MAX, u64::MAX));
        assert_eq!(counters.requests, u64::MAX);
        assert_eq!(counters.tokens(), u64::MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn window_restarts_on_a_multiple_of_its_length() {
        let window = Duration::from_secs(60);
        let accounts = Accounts::new(Budget::new(window).with_total_tokens(100));
        let start = Instant::now();
        accounts.record(TaskKind::Triage, "a", 1, usage(60, 40));
        assert_eq!(accounts.ledger().usage.window.tokens(), 100);
        assert!(matches!(
            accounts.admit(TaskKind::Triage),
            Err(Error::BudgetExceeded(_))
        ));

        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(accounts.ledger().usage.window.tokens(), 100);

        tokio::time::advance(Duration::from_secs(1)).await;
        {
            let ledger = accounts.ledger();
            assert_eq!(ledger.usage.window, UsageCounters::default());
            assert!(ledger.usage.window_by_task.is_empty());
            assert_eq!(ledger.usage.total.tokens(), 100);
            assert_eq!(ledger.window_start, start + window);
        }
        assert!(accounts.admit(TaskKind::Triage).is_ok());

        // 150 seconds after the second window started, the fourth window is 30 seconds old.
        tokio::time::advance(Duration::from_secs(150)).await;
        assert_eq!(accounts.ledger().window_start, start + window * 3);
    }

    #[test]
    fn budget_and_route_round_trip_through_serde() {
        let budget: Budget = serde_json::from_value(serde_json::json!({
            "window": "15m",
            "total_tokens": 1000,
            "tasks": { "triage": 100, "response_draft": 50 },
        }))
        .unwrap();
        assert_eq!(
            budget,
            Budget::new(Duration::from_secs(15 * 60))
                .with_total_tokens(1000)
                .with_task_tokens(TaskKind::Triage, 100)
                .with_task_tokens(TaskKind::ResponseDraft, 50)
        );
        let again: Budget = serde_json::from_value(serde_json::to_value(&budget).unwrap()).unwrap();
        assert_eq!(again, budget);

        let empty: Budget = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(empty, Budget::default());
        assert!(empty.is_unlimited());
        assert_eq!(empty.window, Duration::from_secs(3600));

        let route: Route =
            serde_json::from_value(serde_json::json!({ "provider": "local" })).unwrap();
        assert_eq!(route, Route::new("local"));
        let unknown = serde_json::from_value::<Route>(
            serde_json::json!({ "provider": "local", "modle": "x" }),
        )
        .unwrap_err();
        assert!(
            unknown.to_string().contains("unknown field `modle`"),
            "{unknown}"
        );
    }
}
