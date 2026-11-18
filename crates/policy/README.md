# aegis-policy

Policy, access control, approvals, and the file audit log of AEGIS.

Each response action goes through the policy of the operator, an optional approval by a
person, and the audit log. This crate has the implementations of those steps:

| Item | Function |
| --- | --- |
| `RegoPolicyEngine` | Implements `aegis_contracts::PolicyEngine`. Evaluates the Rego policy of the operator in the process. |
| `Rbac` | Checks that a principal has a `Permission`. |
| `ApprovalService` | Lists approval requests and records the decisions of persons. |
| `FileAuditLog` | Implements `aegis_contracts::AuditLog`. Keeps the hash chain in one JSON Lines file. |
| `explain` module | Returns the audit records that explain one action or one incident. |

The crate talks to other subsystems only through `aegis-contracts`. It has no network
client, no sidecar, and no database.

## Contents

- [Fail closed](#fail-closed)
- [Policy engine](#policy-engine)
- [Shipped policies](#shipped-policies)
- [Role-based access control](#role-based-access-control)
- [Approval service](#approval-service)
- [File audit log](#file-audit-log)
- [Explanations](#explanations)
- [Configuration](#configuration)
- [Public API](#public-api)
- [Tests](#tests)

## Fail closed

- The policy engine denies an action when the policy gives no valid decision.
- Role-based access control gives no permission to a role that it does not know.
- The approval service records no decision without an audit record.
- The file audit log does not append to a file that does not verify.

## Policy engine

`RegoPolicyEngine` evaluates [Rego](https://www.openpolicyagent.org/docs/policy-language)
with the `regorus` crate. The operator owns the policy. The engine has no rules of its own
about targets or actions. It enforces what the loaded policy says.

### The decision rule

The engine gives the `PolicyInput` to the policy as the `input` document. Then it reads one
rule. The default rule is `data.aegis.response.decision`. The rule must return an object:

| Field | Value |
| --- | --- |
| `effect` | `"allow"`, `"require_approval"`, or `"deny"`. Mandatory. |
| `tier` | `"auto"` or `"gated"`. Optional. The default is `input.default_tier`. |
| `reasons` | A list or a set of strings. Optional. The default is an empty list. |

The `input` document has these fields:

| Field | Contents |
| --- | --- |
| `input.action` | The request: `id`, `kind`, `target`, `parameters`, `incident_id`, `requested_by`, `reason`, `evidence`, `dry_run`, `requested_at`. |
| `input.action.kind` | The action, for example `"notify"` or `"disable_user"`. A plugin action is an object: `{"custom": "<name>"}`. |
| `input.default_tier` | `"auto"` for safe and reversible actions. `"gated"` for all other actions. |
| `input.principal` | The identity that makes the request: `id`, `kind`, `roles`. |
| `input.incident` | The incident, if there is one: `id`, `severity`, `status`. |
| `input.environment` | Data that the operator supplies, for example a maintenance window. |

### What the engine does when the policy gives no valid decision

The engine returns a decision with the effect `deny`. It does not return an error. Thus a
caller has one fail-closed result to handle. This occurs in each of these conditions:

- The rule is undefined for the request.
- The evaluation fails. An error in a built-in function is an evaluation failure.
- The evaluation takes more time than the limit. The default limit is 1 second.
- The result is not an object, or it has no `effect`, an unknown `effect`, an unknown
  `tier`, a `reasons` value that is not a list of strings, or an unknown field.
- The request cannot be encoded as the `input` document.

Such a decision has `aegis.policy.fail_closed` in its `policy` field and `gated` as its
tier. Its first reason tells the cause. A decision that the policy made has the name of the
rule in its `policy` field, for example `aegis.response.decision`.

### Load and reload

```rust,no_run
use aegis_policy::{PolicySources, RegoPolicyEngine};

fn load() -> aegis_contracts::Result<RegoPolicyEngine> {
    let engine = RegoPolicyEngine::load(
        PolicySources::new()
            .policy_file("policies/examples/protected_entities.rego")
            .data_file("policies/examples/protected_entities.yaml"),
    )?;
    // After the operator changes a file:
    let version = engine.reload()?;
    println!("policy {} is in use", version.digest);
    Ok(engine)
}
```

- `PolicySources` takes policy text, policy files, policy directories, data text, and data
  files (JSON or YAML). A directory gives its `*.rego` files in file name order. The engine
  does not read subdirectories.
- A source that does not load is `Error::Config`. The message names the file. A policy
  that does not have the decision rule does not load.
- `reload()` reads the same sources again. `replace(sources)` puts new sources in use. The
  change is atomic. If the new policy does not load, the engine returns `Error::Config` and
  the old policy stays in use.
- `version()` returns the names of the loaded files and the SHA-256 digest of their text.
  Write the digest to the audit log when you load or reload a policy.
- The engine is safe to share between tasks. Each evaluation uses its own copy of the
  prepared policy. No lock is held during an evaluation.

### What a policy can use

A policy can use the Rego built-in functions for strings, numbers, sets, objects, regular
expressions, glob patterns, time, and network address ranges (`net.cidr_contains`). A
policy cannot open a network connection and cannot read the environment of the process:
the functions `http.send`, `net.lookup_ip_addr`, and `opa.runtime` do not exist in this
engine. A policy that calls them gives no valid decision.

The output of a `print` call in a policy goes to the log at the debug level. Use it to
examine a policy. Do not print secrets.

## Shipped policies

The top-level `policies` directory has the default policy and three examples. Each file is
a complete policy. Load one of them, not two together.

| File | Behavior |
| --- | --- |
| `policies/default.rego` | Permits a dry run. Permits an action in the auto tier. Requires approval for an action in the gated tier. Denies all other requests. |
| `policies/examples/auto_contain_service_principals.rego` | The default behavior, and containment of a service principal runs with no approval when the incident is critical. |
| `policies/examples/maintenance_window.rego` | The default behavior, but each change is denied during the window in `input.environment.maintenance_window`. |
| `policies/examples/protected_entities.rego` | The default behavior, but only a person with the role `incident_commander` can request a change to an entity in `protected_entities.yaml`, and the change needs approval. |

The comments in each file tell the operator how to change it.

## Role-based access control

`Rbac` maps role names to permissions. A principal has the permissions of all its roles.

| Permission | Configuration name |
| --- | --- |
| `Permission::ViewIncidents` | `view_incidents` |
| `Permission::ViewAudit` | `view_audit` |
| `Permission::ApproveActions` | `approve_actions` |
| `Permission::ManagePolicy` | `manage_policy` |
| `Permission::ManageConnectors` | `manage_connectors` |
| `Permission::RunPlaybooks` | `run_playbooks` |
| `Permission::Administer` | `administer` |

- `Rbac::check(&principal, permission)` returns `Error::Unauthorized` if no role of the
  principal has the permission. The message names the principal and the missing
  permission. It does not show the role table.
- A role that the configuration does not name gives no permission. Role names are
  case-sensitive.
- No permission includes a different permission. For example, `administer` does not
  include `approve_actions`. Give each role each permission that it needs.

## Approval service

`ApprovalService` wraps an `ApprovalQueue`, an `Rbac`, and an `AuditLog`. It is the path by
which a person decides a gated action.

- `pending(&principal)` and `get(id, &principal)` need `view_incidents` or
  `approve_actions`.
- `decide(id, approve, &principal, note)` needs `approve_actions`. The steps are:
  1. Check the permission and the approval rules.
  2. Write an `AuditKind::ApprovalDecided` record. Its evidence links to the action, to the
     incident, and to the evidence of the action.
  3. Record the decision in the queue.
- If the audit log is not available, the request stays pending.
- If the queue refuses the decision after the audit record is written, the service writes
  a second record (`AuditKind::Other`) that says that the decision did not take effect.
- A second decision on the same request fails with `Error::InvalidInput`.

`ApprovalRules` has two rules. The two rules are on by default.

| Rule | Effect |
| --- | --- |
| `four_eyes` | The principal that requested an action cannot approve it. The principal can reject it. The comparison of identifiers ignores ASCII letter case. |
| `humans_only` | Only a principal of the kind `human` can decide. |

## File audit log

`FileAuditLog` is for a deployment that has no database. The log is one append-only file.
Each line is one audit record in canonical JSON form.

- `open(path)` reads the full file and checks the hash chain. If the chain is not correct,
  `open` returns `Error::Integrity` with the first invalid sequence, and it does not change
  the file.
- `append` seals the record with `aegis_contracts::audit::seal`, writes one line, and syncs
  it to the disk before it returns. Appends run one at a time.
- `read` reads from the disk and checks the chain of the records that it returns.
- `verify` reads the file from the disk again. It finds a changed byte, a removed line, a
  line in a different position, an incomplete last line, and bytes that a different
  program added.
- `FileAuditLog::verify_file(path)` checks a file that is not open, for example a log that
  `open` refuses.

### One writer

The log holds an exclusive operating system lock on the file `<path>.lock` while it is
open. On Unix, it also holds a lock on the log file itself. A second `open` of the same
file returns `Error::Unavailable`, in the same process and in a different process. A
symbolic link and a hard link to the file are refused too. The log does not remove the lock
file.

Before each write, the log checks that the file is the file that it opened and that it has
the length that this process wrote. If not, a different program changed the file. Then
the log returns `Error::Integrity` and accepts no more records.

### First invalid sequence

For a line that holds a record, the first invalid sequence is the value that
`aegis_contracts::audit::verify_chain` gives: the sequence number that the first incorrect
record states. For example, if the line of record 2 is removed, record 3 is the first
incorrect record. For a line that does not hold a record, it is the sequence number that
the position of the line must have.

### An incomplete last line

A failure during a write can leave a last line that is not complete. The log reports this
condition and does not repair the file. To continue:

1. Run `FileAuditLog::verify_file`. Make sure that the reason is an incomplete last line
   and that the first invalid sequence is the last line of the file.
2. Make a copy of the file. Keep the copy as evidence.
3. Remove the bytes after the last line feed from the file.
4. Open the log again.

### Limits

- After a restart, the log cannot find that the last lines of the file are gone, because a
  shorter chain is also a correct chain. To find this, keep the sequence number and the
  hash from `FileAuditLog::head()` in a different system, and compare them after a
  restart.
- The locks are advisory. They stop a second `FileAuditLog`, not a program that ignores
  the locks. The check before each write and `verify` find the changes of such a program.
- `open` and `verify` read the full file. Rotate a log by a stop of the writer and a start
  with a new path. Keep the old file: its last record is the end of that chain.

## Explanations

The `explain` module answers the question "why did AEGIS do this?".

```rust,no_run
use aegis_contracts::audit::AuditLog;
use aegis_contracts::common::ActionId;
use aegis_policy::explain_action;

async fn show(log: &dyn AuditLog, action: ActionId) -> aegis_contracts::Result<()> {
    let explanation = explain_action(log, action).await?;
    // One line for each record and one line for each evidence link.
    println!("{explanation}");
    Ok(())
}
```

- `explain_action` returns the records that link to one action, in sequence order: the
  proposal, the policy decision, the approval, and the execution.
- `explain_incident` returns the records of one incident and of each action of the
  incident.
- `Explanation::evidence()` returns the evidence links of all records with no duplicates.
- A record links to an action or an incident through an evidence link, or through a
  payload value that is the identifier. When you write an audit record for an action, add
  an evidence link to the action and to its incident.
- The functions return `Error::NotFound` if no record links to the subject.
- The functions do not check permissions. Call `Rbac::check` with
  `Permission::ViewAudit` before you show an explanation to a principal.

## Configuration

Each configuration type implements `serde::Deserialize`, so a program can read it from one
table of the AEGIS configuration file. The program selects the names of the tables. This
example uses `policy`, `rbac`, `approval`, and `audit_file`.

```toml
[policy]                                  # PolicyConfig
paths = ["policies/default.rego"]         # Files and directories. Mandatory.
data = []                                 # JSON and YAML data files.
rule = "data.aegis.response.decision"     # The decision rule.
evaluation_time_limit_ms = 1000           # Must be larger than 0.

[rbac.roles]                              # RbacConfig
analyst = ["view_incidents", "view_audit"]
approver = ["view_incidents", "approve_actions"]
admin = ["manage_policy", "manage_connectors", "run_playbooks", "administer"]

[approval]                                # ApprovalRules
four_eyes = true
humans_only = true

[audit_file]                              # FileAuditLogConfig
path = "/var/lib/aegis/audit.jsonl"       # The directory must exist.
```

- `RegoPolicyEngine::from_config(&PolicyConfig)` loads the policy.
- `Rbac::new(RbacConfig)` makes the access control check.
- `ApprovalService::new(queue, rbac, audit).with_rules(ApprovalRules)` makes the service.
- `FileAuditLog::from_config(&FileAuditLogConfig)` opens the log.

Each table rejects a key that it does not know. A relative path starts at the working
directory of the process.

## Public API

| Module | Items |
| --- | --- |
| `rego` | `RegoPolicyEngine` (`load`, `load_with`, `from_config`, `decide`, `reload`, `replace`, `version`, `rule`), `PolicySources`, `DataFormat`, `EngineOptions`, `PolicyConfig`, `PolicyVersion`, `DEFAULT_DECISION_RULE`, `DEFAULT_EVALUATION_TIME_LIMIT`, `FAIL_CLOSED_POLICY` |
| `rbac` | `Rbac` (`new`, `check`, `check_any`, `allows`, `permissions`), `RbacConfig`, `Permission` |
| `approval` | `ApprovalService` (`new`, `with_rules`, `rules`, `pending`, `get`, `decide`), `ApprovalRules`, `SERVICE_ACTOR` |
| `file_log` | `FileAuditLog` (`open`, `from_config`, `verify_file`, `path`, `head`, and the `AuditLog` functions), `FileAuditLogConfig` |
| `explain` | `explain_action`, `explain_incident`, `explain`, `Explanation` (`kinds`, `evidence`, `Display`), `Subject` |

The crate root exports all these items again, but not `SERVICE_ACTOR` and `explain`.

## Tests

Run the tests of this crate from the root of the repository:

```sh
cargo test -p aegis-policy --all-features
```

The tests use no network and no credentials. They write files only in temporary
directories.

| Test file | Subject |
| --- | --- |
| `tests/policy_engine.rs` | The policy engine with sample rules: each effect, tier changes, each part of the input, the fail-closed conditions, load errors, and hot reload. |
| `tests/shipped_policies.rs` | The behavior of the files in the `policies` directory. |
| `tests/file_audit_log.rs` | The file audit log: append, read, verify, each type of change to the file, reopen, and two writers. |
| `tests/second_process.rs` | A second process cannot open a log that has a writer. This test starts itself again as the second process. |
| `tests/approval_service.rs` | Permissions, the approval rules, decisions, and the audit records of the approval service. |
| `tests/explain.rs` | The chain of records for an action and for an incident. |
| `tests/config.rs` | The configuration types with a TOML file. |
