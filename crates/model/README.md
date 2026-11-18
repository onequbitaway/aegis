# aegis-model

`aegis-model` is the model abstraction layer of AEGIS. It puts each LLM behind the
`aegis_contracts::ModelProvider` contract. It also supplies a router that selects a model
for each task.

Agents and detectors write a request one time, in the contract types. They do not see the
wire format of a provider.

## Contents

| Item | Function |
| --- | --- |
| `OpenAiCompatibleProvider` | The adapter for the OpenAI chat-completions format. |
| `AnthropicProvider` | The adapter for the Anthropic Messages API. |
| `Router` | Route selection, fallback, token budgets, and usage counters. |
| `ModelConfig`, `build_router` | The configuration section, and the function that builds a router from it. |

## Providers

### `OpenAiCompatibleProvider`

The adapter sends `POST {base_url}/chat/completions` and `POST {base_url}/embeddings`.
One adapter covers these servers:

- OpenAI, and gateways that use the same format.
- DeepSeek, Kimi, and other hosted APIs with the same format.
- Ollama and vLLM on the network of the operator.

The adapter supports chat, tool calls, JSON mode, streams, embeddings, and token counts.

- The adapter sends the API key as `Authorization: Bearer <key>`. A provider with no key
  sends no `Authorization` header.
- Some gateways read the key from a different header, for example `api-key`. Set
  `api_key_header` for such a gateway. The header then holds the key only.
- A query in `base_url` stays in each request URL. Thus a gateway that needs
  `?api-version=...` works.
- The arguments of a tool call must parse to a JSON object. If they do not, the adapter
  returns `Error::Serialization`.
- `ResponseFormat::Json` sends `response_format: {"type": "json_object"}`. Hosted APIs
  reject this mode when no message has the word "JSON". If no message has the word, the
  adapter adds a JSON instruction to the system message.
- A stream request sends `stream_options: {"include_usage": true}`.
- In a stream, the last chunk holds all tool calls, the finish reason, and the usage.
  The adapter joins the fragments of each call. Calls that have one index and different
  identifiers stay separate.
- `embed` returns `Error::Unsupported` when the request and the provider name no
  embedding model.

For a local server with no API key, use the short constructor. This is the air-gap path.

```rust
use aegis_model::{OLLAMA_BASE_URL, OpenAiCompatibleProvider};

let local = OpenAiCompatibleProvider::local(OLLAMA_BASE_URL, "llama3.1")?;
```

### `AnthropicProvider`

The adapter sends `POST {base_url}/v1/messages` with the `x-api-key` and
`anthropic-version` headers.

- The adapter moves system messages to the `system` field.
- The adapter joins adjacent messages of one role. All results of one set of tool calls
  thus go into one `user` message.
- The API requires `max_tokens`. A request with no limit uses `max_output_tokens` of the
  provider.
- The API has no JSON mode. For `ResponseFormat::Json`, the adapter adds an instruction to
  the system prompt. For `chat`, it also removes a code fence around the answer.
- In a stream, a tool call arrives in a chunk when its content block is complete. The
  last chunk holds the finish reason and the usage.
- `embed` returns `Error::Unsupported`.

## Error mapping

Both adapters map failures in the same way.

| Condition | Error | The router tries the next route |
| --- | --- | --- |
| HTTP 401 or 403 | `Unauthorized` | No |
| HTTP 429 | `RateLimited` | Yes |
| HTTP 408, or no answer in the permitted time | `Timeout` | Yes |
| HTTP 5xx, a connection failure, or a broken stream | `Unavailable` | Yes |
| HTTP 400 and other 4xx codes | `InvalidInput` | No |
| HTTP 404 | `NotFound` | No |
| HTTP 3xx | `Config` | No |
| A refusal by the model or by a content filter | `Refused` | Yes |
| An answer that the adapter cannot decode | `Serialization` | No |
| A request with no model, or settings that are not valid | `Config` | No |

A refusal is one of these conditions:

- OpenAI format: `finish_reason: "content_filter"`, a `refusal` field, or HTTP 400 with
  the error code `content_filter` or `content_policy_violation`.
- Anthropic: `stop_reason: "refusal"`.

An error message has the provider name, the HTTP status, and the `type` and `code`
identifiers of the provider. It never has the API key, the prompt, the URL, or the
message text of the provider.

## Router

`Router` implements `ModelProvider`. Give it to the agents as `Arc<dyn ModelProvider>`.

```rust
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::model::TaskKind;
use aegis_model::{Budget, OLLAMA_BASE_URL, OpenAiCompatibleProvider, Route, Router};

let local = OpenAiCompatibleProvider::local(OLLAMA_BASE_URL, "llama3.1")?;
let router = Router::builder()
    .provider(Arc::new(local))
    .default_routes(vec![Route::new("local")])
    .route(TaskKind::Triage, vec![Route::new("local").with_model("llama3.1:8b")])
    .budget(Budget::new(Duration::from_secs(3600)).with_total_tokens(2_000_000))
    .build()?;
```

**Selection.** The router reads `ChatRequest::task`. It uses the routes of that task
kind, or the default routes. An embedding request uses the routes of
`TaskKind::Embedding`. The first route is the first choice. `ChatRequest::model`
overrides the model of each route. For an embedding route, the model of the route is
the embedding model. Set the `embedding` routes when a default route names a chat model.

**Fallback.** The router tries the next route after a retryable error, `Error::Refused`,
or `Error::Unsupported`. A different error stops the request. When all routes fail, the
router returns the last error. For a stream, the router can change the route until the
first chunk arrives. Thus `chat_stream` returns after the first chunk is available.

**Budget.** A budget has a window, a total limit, and a limit for each task kind. The
router counts input tokens plus output tokens. When a limit is spent, the router returns
`Error::BudgetExceeded` and does not call a provider. The first window starts when the
router starts. Each new window sets the window counters to zero. The router adds the
tokens after each answer, so requests that are in progress can exceed a limit.

**Usage.** `Router::usage()` returns the counters: totals, counts for each task kind and
each provider, the counts of the current window, the budget rejections, and the fallbacks.

## Configuration

`ModelConfig` is the `model` section of the AEGIS configuration file.

```toml
# A local model does the triage. A hosted model does the analysis.
[model.providers.local]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
chat_model = "llama3.1:8b"
embedding_model = "nomic-embed-text"
timeout = "120s"

[model.providers.gateway]
kind = "openai_compatible"
base_url = "https://llm-gateway.example.com/v1"
api_key_env = "AEGIS_GATEWAY_API_KEY"
chat_model = "gateway-large"
max_tokens_field = "max_completion_tokens"
headers = { "x-team" = "soc" }

[model.providers.claude]
kind = "anthropic"
api_key_env = "ANTHROPIC_API_KEY"
chat_model = "claude-large"
max_output_tokens = 4096

[model.routes]
default = [{ provider = "claude" }, { provider = "gateway" }, { provider = "local" }]
triage = [{ provider = "local" }, { provider = "gateway", model = "gateway-small" }]
embedding = [{ provider = "local" }]

[model.budget]
window = "1h"
total_tokens = 2000000

[model.budget.tasks]
triage = 500000
```

`ModelConfig` implements `serde::Deserialize`. The tests read the section from TOML and
from YAML. Build the router from the section. `process_env` reads the environment of the
process. This example uses the `toml` crate.

```rust
use aegis_model::{ModelConfig, build_router, process_env};

let mut file: toml::Table = toml::from_str(&text)?;
let section = file.remove("model").ok_or("the file has no model section")?;
let config: ModelConfig = section.try_into()?;
let router = build_router(&config, process_env)?;
```

### Provider fields

| Field | Kind | Default | Description |
| --- | --- | --- | --- |
| `kind` | both | none | `openai_compatible` or `anthropic`. |
| `base_url` | both | `https://api.anthropic.com` for `anthropic`; none for `openai_compatible` | The base URL of the API. |
| `api_key_env` | both | none | The name of the environment variable that holds the API key. `anthropic` requires it. |
| `api_key_header` | `openai_compatible` | none | The header that carries the key, for example `api-key`. Without it, the adapter sends `Authorization: Bearer <key>`. |
| `chat_model` | both | none | The chat model for a request and a route that name no model. |
| `embedding_model` | `openai_compatible` | none | The embedding model for a request and a route that name no model. |
| `timeout` | both | `60s` | The timeout of one request. For a stream, the timeout applies to each read. |
| `headers` | both | none | Headers for each request. Do not put a secret here. |
| `max_tokens_field` | `openai_compatible` | `max_tokens` | The field for the output limit: `max_tokens` or `max_completion_tokens`. |
| `max_output_tokens` | `anthropic` | `4096` | The output limit for a request that sets no limit. |

### Route and budget fields

| Field | Description |
| --- | --- |
| `routes.default` | The ordered routes for a task kind that has no list. |
| `routes.<task>` | The ordered routes for one task kind: `triage`, `analysis`, `planning`, `response_draft`, `reporting`, or `embedding`. |
| `provider` | The name of the provider of a route. |
| `model` | The model of a route. Without it, the provider uses its default model. |
| `budget.window` | The length of the budget window. The default is `1h`. |
| `budget.total_tokens` | The token limit for all task kinds together. Without it, there is no limit. |
| `budget.tasks.<task>` | The token limit for one task kind. |

`build_router` returns `Error::Config` in these conditions:

- The section has no providers.
- A key variable is not set or is empty. The message gives the name of the variable.
- `api_key_env` is not the name of an environment variable.
- `api_key_header` is set and `api_key_env` is not set.
- A route names a provider that the section does not have.
- A task kind has no routes and there is no default list.
- A setting of a provider is not valid.

## Security

- The configuration holds the name of a key variable. It does not hold the key.
- The crate keeps each key in a `SecretString`. `Debug` output does not show a key or a
  header value.
- The adapters do not follow a redirect. A redirect could send the prompt and the key to
  a different host.
- A provider on `localhost` does not use a proxy from the environment.
- The base URL must not hold a user name or a password. Do not put a secret in the
  query of the base URL. `Debug` output shows the base URL.
- The adapter writes a warning when a key goes to a remote host without TLS.
- An adapter reads 64 MiB or less of an answer, and 8 MiB or less of one stream event.

## Tests

Run the tests of this crate:

```sh
cargo test -p aegis-model --all-features
```

All tests are hermetic. The provider tests use `wiremock` and a local TCP server. The
router tests use `aegis_testkit::ScriptedModel`. No test calls a real provider.
