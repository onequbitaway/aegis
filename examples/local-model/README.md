# Example: a local model

This example gives AEGIS a model that runs on your own computer. The model server uses
the OpenAI chat-completions format. No data leaves the host, so the example also works
on a network with no internet.

Each response action is a dry run. The example changes nothing in your environment.

## Files

| File | Contents |
| --- | --- |
| `aegis.toml` | The configuration, with one model provider on the loopback address. |
| `data/` | The audit log and the checkpoints. AEGIS writes them. |

## What the model does

| Component | Use of the model | If the model fails or gives an answer that is not valid |
| --- | --- | --- |
| Detection tier 2 | Examines each tier 1 detection with the verdict `suspicious`. | The detection stays `suspicious`. |
| Analyst agent | Assesses each incident. | Deterministic triage. |
| Responder agent | Selects optional actions from a list that the code makes. | The baseline actions only. |
| Reporter agent | Writes the summary and the recommendations of a report. | A template. |
| Supervisor and Hunter agents | Plan tasks, and do a hunt that an operator requests. | The default plan and the deterministic hunts. |

The output of the model is not trusted. The code validates each answer. Each action that
the model selects still goes through the policy.

## What you need

A model server with the OpenAI chat-completions format on `http://localhost:11434/v1`.
That address is the default address of an Ollama server. A different server works too:
change `base_url` in `aegis.toml`.

The example names the model `qwen2.5:1.5b`. It is a small model, so that a first test is
fast. A small model gives weak analysis. For real work, set `chat_model` to a larger
model that your server has.

With Ollama, start the server. Keep it in operation.

```sh
ollama serve
```

Then get the model. Do this step in a second terminal.

```sh
ollama pull qwen2.5:1.5b
```

Make sure that the server has the model:

```sh
curl -s http://localhost:11434/v1/models
```

```json
{"object":"list","data":[{"id":"qwen2.5:1.5b","object":"model","created":1794985077,"owned_by":"library"},{"id":"qwen2.5:0.5b","object":"model","created":1794982975,"owned_by":"library"}]}
```

## Check the configuration

Do these steps in the root of the repository.

```sh
aegis config check --config examples/local-model/aegis.toml
```

```text
The configuration examples/local-model/aegis.toml is valid.
  agents_dry_run: true
  api: off
  bus: memory
  connectors: honeytokens, simulation
  dispatcher_dry_run: true
  model: true
  modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter
  playbook_mode: dry_run
  playbooks: block-password-spray-source, contain-compromised-user, contain-rogue-service-principal, isolate-compromised-host, respond-to-honeytoken-trip
  rule_pack: aegis-identity
  rules: 9
  sources:
  storage: memory
```

The line `model: true` shows that the configuration has a model. The check sends no
request to the model server.

The path in the line `File:` of the samples below is the path of the test checkout.

## Examine the recorded attack with the model

```sh
aegis replay --config examples/local-model/aegis.toml \
    --events fixtures/artex_style_attack.jsonl --dry-run
```

The first line shows that AEGIS used a model:

```text
AEGIS replay: 648 events, dry run, with a model
```

The detections and the incident are the same as in the demonstration. Each detection of
this log is `malicious`, so tier 2 does not run. The agents use the model.

In this run, the Responder agent proposed ten actions. Six are the baseline actions of
the demonstration. The model added four optional actions:

```text
  block_ip                    ip_address 203.0.113.50                         responder                                 executed: simulated (connector simulation)
  kill_session                user user-dana                                  responder                                 executed: simulated (connector simulation)
  disable_user                user user-dana                                  responder                                 executed: simulated (connector simulation)
  revoke_credential           application app-sync-helper                     responder                                 executed: simulated (connector simulation)
  disable_service_principal   service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
  revoke_credential           service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
  rotate_credential           service_principal sp-sync-helper                responder                                 executed: simulated (connector simulation)
  block_ip                    ip_address 203.0.113.51                         responder                                 executed: simulated (connector simulation)
  block_ip                    ip_address 192.0.2.77                           responder                                 executed: simulated (connector simulation)
  rotate_secret               secret kv-prod/legacy-admin-password            responder                                 executed: simulated (connector simulation)
```

The audit log records what the model did, and what AEGIS did with each answer. These
lines are summaries of audit records of this run:

```text
responder  The model added 1 optional actions for incident 508657f7-d921-8cb3-add4-c2bd62528abd. 0 selections were not in the list and were ignored.
responder  Response rationale of the model: The account user-dana is possibly compromised, and it is necessary to disable the user until a person examines the account to prevent further unauthorized access.
analyst    Incident 508657f7-d921-8cb3-add4-c2bd62528abd: The model assessed a false positive with the confidence 0.90. The incident has deterministic evidence of an attack, so it stays a true positive.
reporter   The model wrote no report text for incident 508657f7-d921-8cb3-add4-c2bd62528abd: the model call failed: timeout: provider local did not answer in 60s. The template applies.
reporter   Wrote the report for incident 508657f7-d921-8cb3-add4-c2bd62528abd on aegis.reports.508657f7-d921-8cb3-add4-c2bd62528abd. Text source: model.
```

What these records show:

- The small model said that the attack was a false positive. AEGIS did not accept that,
  because the incident has `malicious` detections of tier 1.
- One request for a report text got no answer in 60 seconds. AEGIS used the template.
- Each action that the model added is a dry run, as each other action.

To read these records after your run:

```sh
aegis audit show --path examples/local-model/data/audit.jsonl --limit 200
```

## See detection tier 2 and a weak model

The sample events of the device code example give one `suspicious` detection with the
detection pack of this example. Tier 2 thus sends that detection to the model.

```sh
aegis replay --config examples/local-model/aegis.toml \
    --events examples/device-code-phishing/events.jsonl --dry-run
```

```text
AEGIS replay: 6 events, dry run, with a model

Detections (2)
  2026-11-10T08:14:05.000Z  medium         suspicious  T1078.004               Principal acts from two places at an impossible speed  [aegis.velocity.impossible_speed]
  2026-11-10T08:14:05.000Z  medium         suspicious  T1078.004               Principal acts from two places at an impossible speed  [aegis.velocity.impossible_speed]

Incidents (1)
  1d61b0a9-c356-8953-8622-126595114f69  medium         false_positive  Principal acts from two places at an impossible speed
      Detections: 1
      Techniques: T1078.004
      Entities:   user user-lena; ip_address 198.51.100.21; ip_address 198.51.100.200

Actions (0)

Audit log
  Records: 8
  Records checked: 8
  Chain: valid
  File: /private/tmp/aegis-src/examples/local-model/data/audit.jsonl
```

The command also wrote this warning to the log:

```text
WARN aegis_detect::llm: tier 2 rejected a model answer; the detection stays suspicious rule_id=aegis.velocity.impossible_speed detection_id=c6c37890-bbf8-85e2-9135-8629e9f9f662 cause=the reasons in the model output are not a list of text
```

What the output shows:

- The first detection line is the tier 1 detection. The second line is the result of
  tier 2 for the same detection. The answer of the model was not valid, so the verdict
  stays `suspicious`.
- The Analyst agent then asked the model about the incident. The model said "false
  positive" with the confidence 0.90. The incident has no `malicious` detection, and the
  limit is 0.8. AEGIS thus closed the incident as a false positive.

This result is wrong: the events are an attack. It shows the risk of a weak model. A
model can close an incident that has only `suspicious` detections.

To make AEGIS keep such an incident for a person, increase the limit. This command sets
the limit with an environment override:

```sh
AEGIS__AGENTS__ANALYST__FALSE_POSITIVE_MIN_CONFIDENCE=0.95 \
    aegis replay --config examples/local-model/aegis.toml \
    --events examples/device-code-phishing/events.jsonl --dry-run
```

```text
Incidents (1)
  1d61b0a9-c356-8953-8622-126595114f69  medium         investigating   Principal acts from two places at an impossible speed
```

The audit log then has this record:

```text
analyst  Incident 1d61b0a9-c356-8953-8622-126595114f69: The model assessed a false positive with the confidence 0.90. The limit is 0.95. The incident stays open for a person.
```

Refer to [`docs/architecture.md`](../../docs/architecture.md#threat-model-of-aegis) for
what a model can do and what it cannot do.

## Settings for a slow computer

A model on a computer with no GPU can need minutes for one answer. Increase these three
time limits together:

| Key | Value in this example | Meaning |
| --- | --- | --- |
| `timeout` in `[model.providers.local]` | `"60s"` | The time limit for one request to the model server. |
| `detection.triage.timeout_seconds` | `60` | The time limit for one answer in tier 2. |
| `agents.limits.task_timeout_seconds` | `180` | The time limit for one agent task. |

If the model does not answer in time, AEGIS continues with the deterministic path, and
the audit log records the timeout.

## Limits

- The answers of a model are different in each run. Your output is different from the
  samples.
- The samples came from the model `qwen2.5:1.5b` on an Ollama server on macOS with Apple
  silicon. In that run, one model request did not complete in 60 seconds, and the model
  gave four answers that were not valid.
- This example has no source connector. Add a `[[sources]]` table and use `aegis run` for
  a service.
- No agent uses embeddings. The example configures no embedding model.
- The storage is in memory. Incidents do not continue after a stop.
