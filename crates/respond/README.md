# aegis-respond

Response and actuation for AEGIS.

This crate is the only path from a proposed action to a change in the environment of the
operator. Each action goes through policy, approval, a connector, and the audit log.

All actions are defensive. A connector changes only the environment of the operator, through
the administrative API of the product. It disables an account, revokes a credential, blocks an
address in the firewall of the operator, or opens a ticket. The crate contains no offensive
function.

## Contents

- [The path of an action](#the-path-of-an-action)
- [Public API](#public-api)
- [Use the dispatcher](#use-the-dispatcher)
- [Configure the connectors](#configure-the-connectors)
- [Playbooks](#playbooks)
- [Dynamic response](#dynamic-response)
- [Deception](#deception)
- [Safety properties](#safety-properties)
- [Test the crate](#test-the-crate)
- [Limits](#limits)

## The path of an action

```text
ActionRequest
  -> audit: action_proposed
  -> PolicyEngine          (an error is a denial)
  -> audit: policy_decision
       deny              -> ActionDisposition::Denied
       require_approval  -> ApprovalQueue, audit: approval_requested
                            -> ActionDisposition::PendingApproval
                            -> Dispatcher::resume, after a person approves
       allow             -> ActionRegistry -> ActionConnector
  -> audit: action_executed (the outcome or the error)
  -> bus: aegis.actions.results
```

Each audit record links the action, its incident, and the evidence of the request.

## Public API

| Item | Function |
| --- | --- |
| `ActionRegistry`, `Route` | The named connectors and the routing table. |
| `Dispatcher`, `DispatcherBuilder` | Implements `aegis_contracts::ActionDispatcher`. Adds `resume` and the global dry-run switch. |
| `GraphActionConnector`, `GraphConfig` | Actions in Microsoft Entra ID through Microsoft Graph. |
| `SecretSink`, `MemorySecretSink`, `RotatedSecret` | The receiver of the new secret of a credential rotation. |
| `WebhookConnector`, `WebhookConfig`, `WebhookEndpoint` | Signed JSON documents to HTTPS endpoints of the operator. |
| `connectors::webhook::{sign, verify_signature}` | The signature functions for a webhook receiver. |
| `Playbook`, `PlaybookEngine`, `PlaybookRun`, `RunMode`, `StepRun`, `StepResult` | The playbook format and the engine. |
| `draft_response`, `playbook::draft_response_with`, `DraftOptions`, `DraftError` | A response draft from a model, after strict validation. |
| `HoneytokenRegistry`, `HoneytokenStore`, `MemoryHoneytokenStore`, `Honeytoken` | Honeytokens and their storage. |
| `HoneytokenTripDetector` | Implements `aegis_contracts::Detector` for events that touch a honeytoken. |
| `HoneytokenConnector` | Implements `aegis_contracts::ActionConnector` for `deploy_honeytoken`. |

## Use the dispatcher

Make a registry, add the connectors, and build the dispatcher. The dispatcher needs a policy
engine, an approval queue, and an audit log. The incident store and the bus are optional.

```rust
use std::sync::Arc;

use aegis_contracts::action::{ActionDispatcher, ActionDisposition, ActionKind, ActionRequest};
use aegis_contracts::audit::AuditLog;
use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::policy::{ApprovalQueue, Principal, PrincipalKind};
use aegis_contracts::Error;
use aegis_respond::{ActionRegistry, Dispatcher};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};

#[tokio::main(flavor = "current_thread")]
async fn main() -> aegis_contracts::Result<()> {
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(RecordingConnector::new(
        "identity",
        vec![ActionKind::DisableServicePrincipal],
    )))?;

    let approvals = Arc::new(MemoryApprovals::default());
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::ByTier),
        approvals.clone(),
        audit.clone(),
    )
    .build();

    let request = ActionRequest::new(
        ActionKind::DisableServicePrincipal,
        EntityRef::new(EntityKind::ServicePrincipal, "sp-sync-helper"),
        "responder",
        "The service principal has a new credential and a privileged role.",
    );
    let responder = Principal::new("responder", PrincipalKind::Agent, &["agent"]);

    // The policy gates this action. The request waits in the approval queue.
    let ActionDisposition::PendingApproval { approval_id, .. } =
        dispatcher.dispatch(request, &responder).await?
    else {
        return Err(Error::InvalidInput("expected a pending approval".to_owned()));
    };

    // A person approves. The dispatcher then runs the action one time.
    let approver = Principal::new("alice@example.com", PrincipalKind::Human, &["approver"]);
    approvals.decide(approval_id, true, &approver, None).await?;
    let disposition = dispatcher.resume(approval_id).await?;
    assert!(matches!(disposition, ActionDisposition::Executed(_)));
    assert!(dispatcher.resume(approval_id).await.is_err());

    assert!(audit.verify().await?.valid);
    Ok(())
}
```

### Dispatcher rules

- **Fail closed.** An error from the policy engine or the incident store is a denial. The
  decision has the policy name `aegis.respond.fail_closed`, and the audit record holds the
  error.
- **Audit first.** A request that the audit log cannot record does not run.
- **Dry run.** `DispatcherBuilder::dry_run(true)` or `Dispatcher::set_dry_run(true)` sets
  `dry_run` on each request, also in `resume`. The audit records say that the action was a dry
  run. If a connector reports a change in a dry run, the audit record has
  `dry_run_violation: true`.
- **One approval, one action.** `resume` runs only a request that a person approved. It
  returns `Error::InvalidInput` for a pending request, `Error::Denied` for a rejected
  request, and `Error::InvalidInput` for a request that ran before. A connector failure also
  uses the approval. After a restart, the dispatcher finds an earlier run in the audit log.
- **Policy again.** `resume` evaluates the policy again. A new denial stops the action.
- **Time limit.** A connector call that does not complete in the execution timeout (default:
  120 seconds) returns `Error::Timeout`.
- **Connector errors.** The dispatcher writes the error to the audit log, publishes a result
  with the status `failed`, and returns the error to the caller.

### Routing

`ActionRegistry::select` uses the routing table first. If the table has no line for the
action type, the first registered connector that supports the type does the action. If no
connector supports the type, the result is `Error::Unsupported`.

`Route` implements `serde::Deserialize`. This is one line of a routing table, as JSON:

```json
{ "kind": "block_ip", "connector": "perimeter-firewall" }
```

For a custom action, write `"kind": { "custom": "quarantine_mailbox" }`.

## Configure the connectors

The configuration structures implement `serde::Deserialize` and reject unknown fields. The
examples show the field names as JSON. Each connector obeys `dry_run`: a dry run sends no HTTP
request.

Both HTTP connectors refuse a URL that does not use `https`. Plain `http` is permitted only
for a loopback host (`127.0.0.0/8`, `::1`, or `localhost`). The connectors do not follow
redirects.

| HTTP status | Error |
| --- | --- |
| 401, 403 | `Error::Unauthorized` |
| 404 | `Error::NotFound` |
| 408 | `Error::Timeout` |
| 429 | `Error::RateLimited` |
| Other 4xx | `Error::InvalidInput` |
| 5xx | `Error::Unavailable` |

### Microsoft Graph (`GraphActionConnector`)

The connector signs in with the OAuth 2.0 client credentials flow.

```json
{
  "name": "entra-prod",
  "tenant_id": "contoso.example",
  "tenant_aliases": ["tenant-contoso"],
  "client_id": "00000000-0000-0000-0000-000000000000",
  "client_secret": "<from your secret store>",
  "graph_base_url": "https://graph.microsoft.com/v1.0",
  "login_base_url": "https://login.microsoftonline.com",
  "scope": "https://graph.microsoft.com/.default",
  "timeout_seconds": 30
}
```

Only `tenant_id`, `client_id`, and `client_secret` are mandatory. `client_secret` is a
`secrecy::SecretString`. Do not put the secret in a file in the repository.

| Action | Request | Reversible |
| --- | --- | --- |
| `disable_service_principal` | `PATCH /servicePrincipals/{id}` with `accountEnabled: false` | Yes. `revert` sets `true`. |
| `disable_user` | `PATCH /users/{id}` with `accountEnabled: false` | Yes. `revert` sets `true`. |
| `kill_session` | `POST /users/{id}/revokeSignInSessions` | No |
| `revoke_credential` | `POST /{collection}/{id}/removePassword` | No |
| `rotate_credential` | `POST /{collection}/{id}/addPassword`, then `removePassword` | No |

`{collection}` is `servicePrincipals` or `applications`. The type of the target selects it.

Request parameters:

| Parameter | Use |
| --- | --- |
| `key_id` | The `keyId` of the password credential to remove. `revoke_credential` and `rotate_credential` need it. |
| `display_name` | The display name of the new credential of `rotate_credential`. Optional. |

The connector refuses a target that names a tenant that is not `tenant_id` and is not in
`tenant_aliases`.

**Credential rotation.** The new secret goes only to the `SecretSink` that you give to
`GraphActionConnector::new`. Implement `SecretSink` for your vault. The outcome holds the key
identifier and the reference that the sink returns. The secret is not in the outcome, the
audit log, an error, or a log line. If the sink fails, the connector removes the new
credential again.

Give the application registration only the permissions for the actions that you use:
`Application.ReadWrite.All` for service principals and credentials, and `User.ReadWrite.All`
(or `User.EnableDisableAccount.All` and `User.RevokeSessions.All`) for users.

### Webhook (`WebhookConnector`)

The connector sends one signed JSON document to the endpoint for the action type. Use it for
`notify` and `open_ticket`. Use it also as the bridge to your own automation for `block_ip`,
`isolate_host`, `rotate_secret`, `tag`, `enrich`, `snapshot_evidence`, and custom actions.
Point each endpoint only at a system that you own.

```json
{
  "name": "soc-bridge",
  "secret": "<16 bytes or more, from your secret store>",
  "timeout_seconds": 30,
  "endpoints": [
    { "kind": "notify", "url": "https://hooks.example.com/aegis/chat" },
    { "kind": "open_ticket", "url": "https://tickets.example.com/aegis" },
    { "kind": "block_ip", "url": "https://firewall.example.com/aegis/block", "reversible": true },
    { "kind": { "custom": "quarantine_mailbox" }, "url": "https://mail.example.com/aegis" }
  ]
}
```

Set `reversible` to `true` only if the endpoint can undo the action. `revert` then sends the
same document with the operation `revert`.

The document:

```json
{
  "schema": "aegis.webhook.v1",
  "operation": "execute",
  "action": { "id": "...", "kind": "block_ip", "target": { "kind": "ip_address", "id": "203.0.113.50" }, "reason": "..." },
  "sent_at": "2026-11-03T09:10:31Z"
}
```

`action` is the full `ActionRequest`. Each request has these headers:

| Header | Contents |
| --- | --- |
| `x-aegis-timestamp` | The send time, in seconds since the Unix epoch. |
| `x-aegis-signature` | `sha256=` and the HMAC-SHA256 of `{timestamp}.{body}` with the shared secret, in hexadecimal. |
| `x-aegis-delivery` | The identifier of the action request. |

The receiver must compute the same HMAC and compare the values in constant time. The receiver
must also refuse a timestamp that is too old. A receiver in Rust can call
`aegis_respond::connectors::webhook::verify_signature`.

If the endpoint answers with a JSON object, the connector copies only the fields `id` and
`url` to the outcome, for example the reference of a ticket.

## Playbooks

A playbook is a YAML file with a name, a description, a trigger, and ordered steps. The
`playbooks/` directory of the repository holds the samples. Its `README.md` describes them.

```yaml
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
  entity_kinds: [ip_address]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    parameters:
      duration_hours: 24
    reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
    continue_on_error: true
```

### Trigger

All conditions that the trigger has must be true. A trigger must have one condition or more.

| Field | Condition |
| --- | --- |
| `min_severity` | The incident has this severity or a larger one. |
| `techniques_any` | The incident has one or more of these ATT&CK techniques. |
| `techniques_all` | The incident has all of these ATT&CK techniques. |
| `entity_kinds` | The incident has an entity of each of these types. |
| `tenants` | The incident is in one of these tenants. |
| `statuses` | The incident has one of these states. The default is `open` and `investigating`. |

A technique without a sub-technique, for example `T1098`, also matches its sub-techniques.

### Steps

| Field | Contents |
| --- | --- |
| `id` | A name for the step. The default is `step-N`. |
| `action` | The action type, for example `disable_user`. For a custom action, `{custom: name}`. |
| `target` | `{each_entity: <type>}`, `{fixed: {kind: <type>, id: <id>}}`, or `incident_tenant`. |
| `parameters` | Parameters for the connector. Each string is a template. |
| `reason` | A template for the reason of the request. |
| `continue_on_error` | With `true`, a failure of this step does not stop the playbook. The default is `false`. |
| `max_targets` | The maximum number of targets. A step with more targets fails and sends no request. The default is 20. |

Template variables go between `{{` and `}}`: `playbook.name`, `incident.id`,
`incident.title`, `incident.severity`, `incident.status`, `incident.tenant`,
`incident.techniques`, `target.id`, `target.kind`, `target.name`, `target.tenant`, and
`detection.<key>`. `detection.<key>` is the first value of the attribute `<key>` in the
detections of the incident. A variable with no value makes the request fail before the engine
sends it.

### Run a playbook

```rust
use std::sync::Arc;

use aegis_contracts::action::ActionKind;
use aegis_contracts::common::{EntityKind, EntityRef, IncidentId, Severity};
use aegis_contracts::detection::AttackTechnique;
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_respond::{ActionRegistry, Dispatcher, Playbook, PlaybookEngine, RunMode};
use aegis_testkit::{MemoryApprovals, MemoryAuditLog, RecordingConnector, StaticPolicy};
use chrono::Utc;

const PLAYBOOK: &str = r#"
name: block-spray-source
description: Block the address that a password spray comes from.
trigger:
  min_severity: medium
  techniques_any: [T1110.003]
  entity_kinds: [ip_address]
steps:
  - id: block-address
    action: block_ip
    target:
      each_entity: ip_address
    reason: "Incident {{incident.id}}: block the spray address {{target.id}}."
"#;

#[tokio::main(flavor = "current_thread")]
async fn main() -> aegis_contracts::Result<()> {
    let firewall = Arc::new(RecordingConnector::new("firewall", vec![ActionKind::BlockIp]));
    let mut registry = ActionRegistry::new();
    registry.register(firewall.clone())?;
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        Arc::new(MemoryAuditLog::default()),
    )
    .build();

    let mut engine = PlaybookEngine::new(Arc::new(dispatcher));
    engine.add(Playbook::from_yaml("block-spray-source.yaml", PLAYBOOK)?)?;

    let incident = Incident {
        id: IncidentId::new(),
        title: "Password spray".to_owned(),
        summary: "Many failed sign-ins from one address.".to_owned(),
        severity: Severity::High,
        status: IncidentStatus::Open,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        tenant: Some("tenant-contoso".to_owned()),
        detections: Vec::new(),
        entities: vec![EntityRef::new(EntityKind::IpAddress, "203.0.113.50")],
        attack: vec![AttackTechnique::new(
            "credential-access",
            "T1110.003",
            "Password Spraying",
        )],
        timeline: Vec::new(),
    };

    // Run each matching playbook in dry-run mode first.
    let runs = engine.run_matching(&incident, RunMode::DryRun).await?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].failures(), 0);

    let calls = firewall.executed();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].dry_run);
    Ok(())
}
```

- `PlaybookEngine::load_dir(directory)` loads each `.yaml` and `.yml` file. A file that fails
  validation is not loaded. `LoadReport::rejected` holds the file name and the reason for
  each rejected file. Examine it.
- `PlaybookEngine::matching(incident)` selects the playbooks for an incident.
- `PlaybookEngine::run(playbook, incident, mode)` makes one request for each target of each
  step and sends each request through the dispatcher. `RunMode::DryRun` sets `dry_run` on each
  request. `RunMode::Live` permits changes, if policy permits them.
- The `PlaybookRun` report has one line for each request: the step, the target, the request
  identifier, and the disposition. A denial and a pending approval are not failures.
- Each request has `requested_by` set to `playbook:<name>`, the incident identifier, and
  evidence links to the incident and its detections. The principal is `playbook-engine`
  (type `system`).

## Dynamic response

For an incident that no playbook matches, `draft_response(&incident, model)` asks a
`ModelProvider` for a response plan. The request has the task `TaskKind::ResponseDraft` and
asks for JSON. The function validates the plan and returns it as a `Playbook` for this
incident only.

The function rejects the full plan if one part is not valid:

- Each action must be a known action type. A custom action is not permitted. By default,
  `deploy_honeytoken` is also not permitted. `DraftOptions::allowed_actions` sets the list.
- Each target must be an entity of the incident, of a type that the action can change.
- The plan must have 1 to `DraftOptions::max_steps` steps (default: 8) and no unknown fields.
- The only parameter is `key_id`, for `revoke_credential` and `rotate_credential`. Its value
  must be a credential identifier of the incident.

The incident text is untrusted data. It goes into the prompt as one JSON document between two
markers, and the text cannot close the data block. The text of a draft is never a template.

A draft changes nothing when the function returns it. Give it to `PlaybookEngine::run`. Each
step then goes through the dispatcher with the principal `response-draft` (type `agent`) and
`requested_by` set to `draft:<name>`. Thus the policy of the operator applies, and it can give
a model draft less authority than a playbook of the operator.

## Deception

A honeytoken is a passive decoy. The operator plants it in a place that no legitimate process
reads, for example a decoy secret in a vault. A decoy value is random text from the random
generator of the operating system. It is not a credential and it gives no access to a system.

- `HoneytokenRegistry::issue` makes a honeytoken: a random identifier, a random decoy value,
  and the description of the placement. `list` returns all honeytokens. `retire` stops a
  honeytoken.
- `HoneytokenStore` is the storage contract. `MemoryHoneytokenStore` keeps the data in
  memory. The store holds the decoy values, so protect it as you protect other security data.
- `HoneytokenTripDetector` is a tier 1 detector. It returns a `Malicious` detection when an
  event touches an active honeytoken. The severity is `High` or more.
- `HoneytokenConnector` does the action `deploy_honeytoken`. The target of the request is the
  placement. The connector issues the honeytoken in the registry. It does not plant the decoy.
  The outcome and the audit log never hold the decoy value. `revert` retires the honeytoken.

An event touches a honeytoken in one of these ways:

| Match | Condition | Severity |
| --- | --- | --- |
| `decoy_value` | An attribute of the event holds the decoy value. | `Critical` |
| `honeytoken_id` | The attribute `honeytoken_id` names the honeytoken. | `High` or the event severity |
| `target` | The target of the event is the honeytoken or its placement. | `High` or the event severity |
| `actor` | The actor of the event is the placement, for example a decoy application signs in. | `High` or the event severity |

`HoneytokenConnector` reads these request parameters: `kind` (`secret`, `credential`,
`application`, `user`, or `other`), `description`, and `id`. All are optional.

## Safety properties

- **Defensive only.** The crate has no function that acts on a system that the operator does
  not own.
- **Fail closed.** A policy error is a denial. A missing audit record stops the action.
- **Secrets.** Client secrets, webhook secrets, access tokens, and rotated secrets are
  `secrecy::SecretString` values. Error texts and outcomes do not contain secrets, response
  bodies, or webhook URLs.
- **No panics.** Library code returns errors. The workspace lints deny `unwrap`, `expect`, and
  `panic!`.

## Test the crate

All tests are hermetic. The HTTP tests use a `wiremock` server on a loopback address. No test
needs a real tenant, a real endpoint, or Docker.

```sh
cargo test -p aegis-respond --all-features
cargo clippy -p aegis-respond --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p aegis-respond --no-deps
```

| Test file | Subject |
| --- | --- |
| `tests/dispatcher.rs` | Policy, approval, `resume`, dry run, audit records, and the bus. |
| `tests/graph_connector.rs` | Each Microsoft Graph action, the token flow, error mapping, and secret handling. |
| `tests/webhook_connector.rs` | The signed document, endpoint mapping, error mapping, and configuration checks. |
| `tests/playbook_engine.rs` | A playbook run through the real dispatcher, failures, and the loader. |
| `tests/sample_playbooks.rs` | Each sample playbook in `playbooks/` loads and runs in dry-run mode. |
| `tests/draft_response.rs` | Validation of model drafts and the prompt. |
| `tests/deception.rs` | The honeytoken registry, the detector, and the connector. |

The examples in this file are documentation tests. `cargo test` compiles and runs them.

## Limits

- The dispatcher has no path for `ActionConnector::revert`. The frozen contracts do not let a
  policy or an approval request tell a revert from the initial action.
- The approval queue contract has no state for "this approval ran". The dispatcher keeps this
  state in memory and also reads it from the audit log. In the same process, the read starts
  at the record of the approval request. After a restart, the read starts at the first record
  of the audit log, so `resume` is slow for a large log.
- One approval permits one connector call. The dispatcher does not try a failed call again.
  After a failure, also a temporary one, send a new request.
- The component that calls `ApprovalQueue::decide` must write the `approval_decided` audit
  record. The dispatcher writes the identity of the approver in the records of `resume`.
- The Microsoft Graph connector removes password credentials only. It does not remove
  certificate credentials.
- The honeytoken detector also trips on the event that plants the decoy at its placement.
  Triage must expect one trip from the identity that planted the decoy.
- `MemoryHoneytokenStore` and `MemorySecretSink` do not keep data after a restart. Implement
  `HoneytokenStore` and `SecretSink` for a durable store.
