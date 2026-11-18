# Security

This document has two parts: the hardening checklist for an installation, and the
security properties of AEGIS with the tests that prove them.

To report a vulnerability, follow [`SECURITY.md`](../SECURITY.md). Do not open a public
issue.

AEGIS is defensive only. Use it only in an environment that you own or have
authorization to defend.

## Contents

- [Hardening checklist](#hardening-checklist)
- [Security properties and their tests](#security-properties-and-their-tests)
- [Run the tests](#run-the-tests)
- [Limits](#limits)

## Hardening checklist

### Before the first start

- [ ] Keep the dry run on until you examined the proposed actions: `response.dry_run`,
      `agents.dry_run`, and `response.playbooks = "dry_run"`.
- [ ] Run `aegis config check`. Read the lines `dispatcher_dry_run`, `agents_dry_run`, and
      `playbook_mode`.
- [ ] Enable only the modules that you need. With no `responder`, AEGIS proposes no
      action.

### The policy

- [ ] Read the policy before you permit changes. The policy decides which actions run
      with no person.
- [ ] Keep a `default decision` rule that denies.
- [ ] Load one complete policy. Two complete policies deny each request.
- [ ] Test each policy change with `aegis replay --dry-run` on recorded events.
- [ ] Record the digest of the approved policy. Compare it with the `config_change` audit
      record at each start.
- [ ] Keep the two approval rules on: `four_eyes` and `humans_only`.

### Files and the process

- [ ] Run AEGIS as a user of its own, with no administrator rights.
- [ ] Let only the operator write the configuration file, the policy, the detection
      pack, the playbooks, and the plugin directory. The AEGIS user needs only read
      access to them.
- [ ] Let only the AEGIS user read and write the data directory.
- [ ] Keep the configuration directory in version control.

### Secrets

- [ ] Put no secret in the configuration file. Use the paths in
      [configuration.md](configuration.md#secrets).
- [ ] Give each secret to the process from a secret store, as an environment variable.
- [ ] Make each API token with a random generator, 32 characters or more. Give each
      person a token of their own.
- [ ] Give each application registration the smallest permission. The Entra ID source
      needs only `AuditLog.Read.All`.
- [ ] Use two application registrations: one to read, and one for the response actions.

### The operator API

- [ ] Keep the listen address a loopback address. The server has no TLS.
- [ ] For access from a different host, put a proxy with TLS before the server. Then set
      `allow_non_loopback = true`.
- [ ] Add a rate limit in the proxy. The server has no rate limit for failed tokens.
- [ ] Keep the role that approves apart from the role that administers. No permission
      includes a different permission.
- [ ] Check each role name in `[[api.principals]]`. A role that `[rbac.roles]` does not
      name gives no permission, and the check does not report it.
- [ ] Remove the principal and its token when a person leaves.

### The audit log

- [ ] Run `aegis audit verify` at regular intervals, or read
      `GET /api/v1/audit/verification`.
- [ ] Record the sequence number and the hash of the last record in a different system.
- [ ] For the PostgreSQL audit log, give the application role only `INSERT` and `SELECT`
      on the audit table. Refer to the README of
      [`aegis-storage`](../crates/storage/README.md#roles-and-privileges).
- [ ] Make a backup of the audit log. Keep each old audit file.

### The bus and the database

- [ ] Use TLS for a NATS server that is not on the same host: a `tls://` URL, or
      `nats.tls.required = true`.
- [ ] Use `sslmode=verify-full` in the database URL for a server that is not on the same
      host.
- [ ] Give the NATS account and the database role only the rights that AEGIS needs.

### Models

- [ ] Decide which data can go to a hosted model. AEGIS sends detections, events, and
      incident data to the model.
- [ ] Use a local model for data that must not leave the host.
- [ ] Set a token budget in `[model.budget]`.
- [ ] Keep the important rules at the level `high` or `critical`. A model cannot change a
      `malicious` detection.
- [ ] Increase `analyst.false_positive_min_confidence` if the model is weak. Refer to
      [the local model example](../examples/local-model/README.md).

### Connectors and plugins

- [ ] Point each webhook endpoint only at a system that you own. Use HTTPS.
- [ ] Check the signature and the timestamp of each webhook request in the receiver.
- [ ] Pin each plugin with `sha256`, and set `plugins.limits.require_sha256 = true`.
- [ ] Give each plugin only the hosts that it needs in `allowed_hosts`.
- [ ] Run only native connectors that you trust. A native connector has all rights of
      the process.

## Security properties and their tests

Each property below has one or more tests in the repository. The test file is the path
after `crates/`. Each test name is the name of a test function.

### Each action goes through the policy, approval, and the audit log

| Property | Test file | Test |
| --- | --- | --- |
| An allowed action runs, and each step is in the audit log. | `respond/tests/dispatcher.rs` | `an_allowed_action_runs_and_each_step_is_in_the_audit_log` |
| A denied action does not reach a connector. | `respond/tests/dispatcher.rs` | `a_denied_action_does_not_reach_a_connector` |
| A gated action waits in the approval queue. | `respond/tests/dispatcher.rs` | `a_gated_action_waits_in_the_approval_queue` |
| An approved action runs one time. | `respond/tests/dispatcher.rs` | `resume_runs_an_approved_action_one_time` |
| An approval cannot run again after a restart. | `respond/tests/dispatcher.rs` | `an_approval_cannot_run_again_after_a_restart` |
| The policy decides again before an approved action runs. | `respond/tests/dispatcher.rs` | `resume_evaluates_the_policy_again` |
| A rejected action does not run. | `app/tests/approval.rs` | `a_rejection_does_not_run_the_action` |
| A response plan of a model also goes through the dispatcher. | `respond/tests/draft_response.rs` | `a_draft_runs_through_the_dispatcher_so_policy_applies` |

### Fail closed

| Property | Test file | Test |
| --- | --- | --- |
| An error of the policy engine is a denial. | `respond/tests/dispatcher.rs` | `a_policy_error_is_a_denial` |
| An error of the incident store is a denial. | `respond/tests/dispatcher.rs` | `an_incident_store_error_is_a_denial` |
| An action that the audit log cannot record does not run. | `respond/tests/dispatcher.rs` | `an_action_that_the_audit_log_cannot_record_does_not_run` |
| A policy result that is not a valid decision denies the action. | `policy/tests/policy_engine.rs` | `a_result_that_is_not_a_valid_decision_denies_the_action` |
| An evaluation error denies the action. | `policy/tests/policy_engine.rs` | `an_evaluation_error_denies_the_action_and_names_the_location` |
| An error in a deny rule does not let the default permit the action. | `policy/tests/policy_engine.rs` | `an_error_in_a_deny_rule_does_not_let_the_default_permit_the_action` |
| An evaluation that takes too much time denies the action. | `policy/tests/policy_engine.rs` | `an_evaluation_that_exceeds_the_time_limit_denies_the_action` |
| A policy with no decision rule does not load. | `policy/tests/policy_engine.rs` | `a_policy_without_the_decision_rule_does_not_load` |
| A policy cannot use the network or the environment of the process. | `policy/tests/policy_engine.rs` | `a_policy_cannot_use_the_network_or_the_process_environment` |
| No decision takes effect when the audit log is not available. | `policy/tests/approval_service.rs` | `no_decision_takes_effect_when_the_audit_log_is_not_available` |

### Dry run

| Property | Test file | Test |
| --- | --- | --- |
| The global switch forces a dry run. | `respond/tests/dispatcher.rs` | `the_global_dry_run_switch_forces_a_dry_run` |
| The global switch also applies to an approved action. | `respond/tests/dispatcher.rs` | `the_global_dry_run_switch_also_applies_to_resume` |
| A connector that ignores the dry-run flag is reported. | `respond/tests/dispatcher.rs` | `a_connector_that_ignores_the_dry_run_flag_is_reported` |
| The containment actions of the replay are dry runs. | `app/tests/replay.rs` | `the_containment_actions_go_through_the_dispatcher_as_dry_runs` |
| A forced dry run changes nothing with a configuration that permits changes. | `app/tests/build.rs` | `a_forced_dry_run_changes_nothing_with_a_configuration_that_is_live` |
| The Microsoft Graph connector sends no request in a dry run. | `respond/tests/graph_connector.rs` | `a_dry_run_sends_no_request` |
| The webhook connector sends no request in a dry run. | `respond/tests/webhook_connector.rs` | `a_dry_run_sends_no_request` |
| `aegis monitor` takes no action. | `cli/tests/cli.rs` | `monitor_prints_each_detection_and_incident_and_takes_no_action` |

### Approvals

| Property | Test file | Test |
| --- | --- | --- |
| A principal with no permission cannot decide. | `policy/tests/approval_service.rs` | `a_principal_without_the_permission_cannot_decide` |
| Only a person can decide. | `policy/tests/approval_service.rs` | `only_a_person_can_decide_unless_the_rules_permit_other_principals` |
| The requester cannot approve its own request. | `policy/tests/approval_service.rs` | `the_requester_cannot_approve_its_own_request` |
| A second decision fails and writes no audit record. | `policy/tests/approval_service.rs` | `a_second_decision_fails_and_writes_no_audit_record` |
| Two decisions at the same time write one decision record. | `policy/tests/approval_service.rs` | `two_decisions_at_the_same_time_write_one_decision_record` |
| A request that the time limit drops leaves no half-applied approval. | `app/tests/api.rs` | `a_request_that_the_time_limit_drops_leaves_no_half_applied_approval` |

### The audit log

| Property | Test file | Test |
| --- | --- | --- |
| A change to one byte is detected at its record. | `policy/tests/file_audit_log.rs` | `a_change_to_any_byte_is_detected_at_its_record` |
| A removed line is detected. | `policy/tests/file_audit_log.rs` | `a_removed_line_is_detected` |
| A line in a different position is detected. | `policy/tests/file_audit_log.rs` | `a_line_in_a_different_position_is_detected` |
| A log that was changed does not open for append. | `policy/tests/file_audit_log.rs` | `a_tampered_log_does_not_open_for_append` |
| A last line that is not complete is reported and not repaired. | `policy/tests/file_audit_log.rs` | `a_partial_last_line_is_reported_and_not_repaired` |
| A second writer is rejected. | `policy/tests/file_audit_log.rs` | `a_second_writer_is_rejected` |
| Bytes from a different writer stop the log. | `policy/tests/file_audit_log.rs` | `bytes_from_a_different_writer_stop_the_log` |
| `aegis audit verify` fails on a log with one changed byte. | `cli/tests/cli.rs` | `audit_verify_fails_on_a_log_with_one_changed_byte` |
| The audit log of the replay has each step, and its chain verifies from the file. | `app/tests/replay.rs` | `the_audit_log_has_each_step_and_its_chain_verifies_from_the_file` |
| The database rejects an update and a removal of an audit record. | `storage/tests/postgres/audit.rs` | `a_direct_update_or_delete_is_rejected_by_the_trigger` |
| A database role with only `INSERT` and `SELECT` cannot change a record. | `storage/tests/postgres/audit.rs` | `a_role_with_only_insert_and_select_can_append_and_cannot_change_a_record` |

### The operator API

| Property | Test file | Test |
| --- | --- | --- |
| Each route answers 401 with no token and with a token that is not known. | `api/tests/api/access.rs` | `each_route_answers_401_without_a_token_and_with_an_unknown_token` |
| Each route answers 403 to a principal with no permission. | `api/tests/api/access.rs` | `each_route_answers_403_to_a_principal_without_the_permission` |
| With no principals, each protected route answers 401. | `api/tests/api/access.rs` | `no_principals_means_that_each_protected_route_answers_401` |
| A token variable that is not set is a configuration error. | `api/tests/api/access.rs` | `a_missing_token_variable_is_a_configuration_error` |
| The server gives no cross-origin access. | `api/tests/api/limits.rs` | `the_server_gives_no_cross_origin_access` |
| A body that is larger than the limit is refused. | `api/tests/api/limits.rs` | `a_body_that_is_larger_than_the_limit_is_a_413` |
| No file of the console refers to a different origin. | `api/tests/api/console.rs` | `no_file_of_the_console_refers_to_a_different_origin` |
| The console page has no inline script and no inline style. | `api/tests/api/console.rs` | `the_page_has_no_inline_script_no_inline_style_and_no_inline_handler` |
| The console builds the page with no markup from text. | `api/tests/api/console.rs` | `the_scripts_build_the_page_without_markup_from_text` |
| A Slack request with a wrong signature is refused with no effect. | `api/tests/api/slack.rs` | `a_wrong_signature_is_refused_with_no_side_effect` |
| A Slack request with an old timestamp is refused. | `api/tests/api/slack.rs` | `an_old_timestamp_is_refused_with_no_side_effect` |
| A Teams request with a wrong signature is refused with no effect. | `api/tests/api/teams.rs` | `a_request_with_a_wrong_hmac_is_refused_with_no_side_effect` |
| Incident text with markup characters is escaped in chat. | `api/tests/api/slack.rs` | `incident_text_with_markup_characters_is_escaped` |
| The operator API needs its section, its secrets, and an agent. | `app/tests/api.rs` | `the_operator_api_needs_its_section_its_secrets_and_an_agent` |

### The model is not trusted

| Property | Test file | Test |
| --- | --- | --- |
| Instruction text in an event field does not change the outcome. | `agents/tests/integration/acceptance.rs` | `instruction_text_in_an_event_field_does_not_change_the_outcome` |
| Untrusted text is only in the data section of a prompt. | `agents/src/prompt.rs` | `untrusted_text_is_only_in_the_data_section_of_the_user_message` |
| Data cannot close its section or open a new one. | `agents/src/prompt.rs` | `data_cannot_close_its_section_or_open_a_new_one` |
| The model cannot close an incident that has `malicious` detections. | `agents/src/agents/analyst.rs` | `the_model_cannot_close_an_incident_that_has_malicious_detections` |
| A false positive with low confidence stays open for a person. | `agents/src/agents/analyst.rs` | `a_false_positive_with_low_confidence_stays_open_for_a_person` |
| The model can add only the optional actions of the list. | `agents/src/agents/responder.rs` | `the_model_can_add_only_the_optional_actions_of_the_list` |
| The agents complete their work when the model is not available. | `agents/tests/integration/acceptance.rs` | `the_loop_completes_with_the_deterministic_paths_when_the_model_is_not_available` |
| A detection that is not `suspicious` never reaches the model. | `detect/src/llm.rs` | `a_detection_that_is_not_suspicious_never_reaches_the_model` |
| A `benign` verdict with too little confidence stays `suspicious`. | `detect/src/llm.rs` | `a_benign_verdict_with_too_little_confidence_stays_suspicious` |
| A failure of tier 2 does not change the verdict. | `detect/src/llm.rs` | `a_triage_failure_is_recorded_and_does_not_change_the_verdict` |
| The replay of the attack log sends no request to the model. | `detect/tests/acceptance.rs` | `the_replay_sends_no_request_to_the_model` |
| A response plan with an action that is not known is rejected. | `respond/tests/draft_response.rs` | `a_plan_with_an_unknown_action_is_rejected` |
| A response plan with a target outside the incident is rejected. | `respond/tests/draft_response.rs` | `a_plan_with_a_target_outside_the_incident_is_rejected` |

### Guard rails of the agents

| Property | Test file | Test |
| --- | --- | --- |
| The step limit stops a loop of tasks. | `agents/tests/integration/guard_rails.rs` | `the_step_limit_stops_a_task_loop` |
| The depth limit stops a chain of tasks. | `agents/tests/integration/guard_rails.rs` | `the_depth_limit_stops_a_chain_of_tasks` |
| A role that is not enabled gets no task. | `agents/tests/integration/guard_rails.rs` | `a_role_that_is_not_enabled_gets_no_task` |
| A denial and a pending approval do not contain an incident. | `agents/tests/integration/acceptance.rs` | `a_denial_and_a_pending_approval_are_recorded_and_do_not_contain_the_incident` |

### The plugin sandbox

| Property | Test file | Test |
| --- | --- | --- |
| A plugin has no environment, no filesystem, and no sockets. | `plugin/tests/sandbox.rs` | `a_guest_has_no_environment_no_filesystem_and_no_sockets` |
| A plugin that loops returns a timeout and does not stop the host. | `plugin/tests/sandbox.rs` | `a_guest_that_loops_forever_returns_a_timeout_and_does_not_hang_the_host` |
| A plugin that uses too much memory fails cleanly. | `plugin/tests/sandbox.rs` | `a_guest_that_allocates_past_the_memory_limit_fails_cleanly` |
| A plugin that traps returns an error, and the host continues. | `plugin/tests/sandbox.rs` | `a_guest_that_traps_returns_an_error_and_the_host_continues` |
| A plugin cannot emit an event in the name of a different connector. | `plugin/tests/sandbox.rs` | `a_guest_cannot_emit_an_event_in_the_name_of_a_different_connector` |
| An action plugin that reports a change for a dry run gets an error. | `plugin/tests/sandbox.rs` | `an_action_guest_that_reports_a_change_for_a_dry_run_gets_an_error` |
| A host that is not in `allowed_hosts` is refused, and no request leaves. | `plugin/tests/action_plugin.rs` | `a_host_that_is_not_in_allowed_hosts_is_refused_and_no_request_leaves` |
| A plugin with no `allowed_hosts` has no network. | `plugin/tests/action_plugin.rs` | `a_plugin_with_no_allowed_hosts_has_no_network` |
| Plain HTTP to a host that is not a loopback address is refused. | `plugin/tests/action_plugin.rs` | `plain_http_to_a_host_that_is_not_loopback_is_refused` |
| A hash that does not match the manifest is an integrity error. | `plugin/tests/loading.rs` | `a_manifest_hash_mismatch_is_an_integrity_error` |
| A host that requires a hash refuses a manifest with no hash. | `plugin/tests/loading.rs` | `a_host_that_requires_a_hash_refuses_a_manifest_without_one` |

### Secrets and connectors

| Property | Test file | Test |
| --- | --- | --- |
| A secret from an override does not reach an error message. | `core/tests/config.rs` | `a_secret_from_an_override_does_not_reach_an_error_message` |
| A section error names the section and the key, and no value. | `core/tests/config.rs` | `an_invalid_section_error_names_the_section_and_the_key_but_not_a_value` |
| A connector setting that is not valid shows no secret. | `app/tests/build.rs` | `a_connector_setting_that_is_not_valid_names_its_section_and_shows_no_secret` |
| The API key and the prompt stay out of errors of the model layer. | `model/tests/openai.rs` | `key_and_prompt_stay_out_of_errors_and_debug_output` |
| The model layer does not follow a redirect. | `model/tests/openai.rs` | `redirect_is_a_configuration_error_and_the_target_gets_no_request` |
| A rotated secret is in no audit record and no bus message. | `respond/tests/graph_connector.rs` | `the_rotated_secret_is_in_no_audit_record_and_no_bus_message` |
| The Microsoft Graph connector refuses a target in a different tenant. | `respond/tests/graph_connector.rs` | `a_target_in_a_different_tenant_is_refused` |
| The webhook connector does not follow a redirect. | `respond/tests/webhook_connector.rs` | `a_redirect_is_not_followed` |
| The webhook signature verifies with the shared secret. | `respond/tests/webhook_connector.rs` | `the_signature_verifies_with_the_shared_secret` |
| The Entra ID source refuses a next-page link to a different host. | `ingest/tests/entra.rs` | `a_next_link_to_a_different_host_is_rejected_and_gets_no_request` |
| The Entra ID source does not follow a redirect. | `ingest/tests/entra.rs` | `a_redirect_is_not_followed` |
| A honeytoken action keeps the decoy value out of the records. | `respond/tests/deception.rs` | `deploy_honeytoken_issues_a_token_and_keeps_the_decoy_value_out_of_the_records` |

### Safe defaults and the detection of the recorded attack

| Property | Test file | Test |
| --- | --- | --- |
| The starter configuration starts no operator API. | `app/src/starter.rs` | `the_starter_configuration_starts_no_operator_api` |
| A reload with a file that is not valid keeps the old state. | `app/tests/build.rs` | `a_reload_with_a_broken_file_keeps_the_old_state_and_returns_the_error` |
| A reload by a principal needs the permission to manage the policy. | `app/tests/build.rs` | `reload_by_a_principal_needs_the_permission_to_manage_the_policy` |
| A rule pack that is not valid is rejected, and the old rules stay active. | `detect/tests/hot_reload.rs` | `a_broken_pack_is_rejected_and_the_old_rules_stay_active` |
| The replay finds the five expected techniques and the honeytoken. | `app/tests/replay.rs` | `the_replay_finds_the_five_techniques_and_the_honeytoken` |
| The normal events cause nothing. | `app/tests/replay.rs` | `the_normal_events_cause_nothing` |

## Run the tests

Run all tests that need no container:

```sh
cargo test --workspace --locked
```

Run the tests of one file, for example the dispatcher tests:

```sh
cargo test -p aegis-respond --test dispatcher
```

Run one test by its name:

```sh
cargo test -p aegis-policy --test file_audit_log a_change_to_any_byte_is_detected_at_its_record
```

The tests in `storage/tests/postgres/` need Docker and the Cargo feature `docker-tests`:

```sh
cargo test -p aegis-storage --features docker-tests
```

## Limits

- A test proves a property for the conditions of that test. It is not a formal proof.
- The repository had no external security audit.
- The operator API has no TLS and no rate limit for failed tokens.
- A native connector and the AEGIS process have the same rights. Only a plugin is in a
  sandbox.
- The hash chain finds a changed audit log. It does not prevent the change.
- A file audit log that lost its last records is still a correct chain. Keep the last
  hash in a different system.
- A model can close an incident that has only `suspicious` detections. Refer to
  [architecture.md](architecture.md#threat-model-of-aegis).
