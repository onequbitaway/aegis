# Detection packs

A detection pack is a directory of Sigma rules and indicators that detection tier 1
loads as one unit. This document describes the pack layout, the supported part of Sigma,
the event vocabulary, and how to write and test a rule.

## Contents

- [The pack layout](#the-pack-layout)
- [A rule](#a-rule)
- [The supported part of Sigma](#the-supported-part-of-sigma)
- [Field names](#field-names)
- [The event vocabulary](#the-event-vocabulary)
- [ATT&CK tags](#attck-tags)
- [Verdicts](#verdicts)
- [Indicators](#indicators)
- [Worked example: add a rule and test it](#worked-example-add-a-rule-and-test-it)
- [Apply a changed pack](#apply-a-changed-pack)
- [The pack that AEGIS ships](#the-pack-that-aegis-ships)
- [Limits](#limits)

## The pack layout

```text
detections/aegis-identity/
  pack.yml                 The manifest: name, version, description
  rules/*.yml              Sigma rules, one rule in each file
  indicators/*.yml         Indicator files, in YAML or JSON
```

The manifest `pack.yml` has three keys. All are necessary.

| Key | Contents |
| --- | --- |
| `name` | 1 to 64 lower case letters, digits, `-`, `_`, and `.`. |
| `version` | The version of the pack, for example `"1.2.0"`. |
| `description` | What the pack detects. |

Rules of a pack:

- The key `detection.pack` of the configuration names the directory. One process loads
  one pack.
- AEGIS validates the full directory. One file that is not valid rejects the pack, and
  AEGIS does not start.
- Two rules with one identifier reject the pack. One indicator in two files also rejects
  it.

## A rule

A rule is a Sigma rule in YAML. This is a rule of the pack that AEGIS ships:

```yaml
title: Privileged role assigned by a workload identity
id: a4d7e1b9-6c35-4f02-8e7a-1b9c0d5f2a63
status: stable
description: >-
  A service principal or an application assigned a privileged directory role or a
  privileged application permission. Workload identities do not usually manage
  privileged access. An attacker with a workload credential uses this step to get
  administrator rights.
author: AEGIS project
references:
  - https://attack.mitre.org/techniques/T1098/003/
logsource:
  category: user_access_management
detection:
  selection:
    action:
      - role.assign
      - app.permission_grant
    actor.kind:
      - service_principal
      - application
    privileged: true
  filter_failed:
    outcome: failure
  condition: selection and not filter_failed
falsepositives:
  - An approved automation that manages role assignments. Add a filter for its identifier.
level: high
tags:
  - attack.privilege-escalation
  - attack.t1098.003
```

A rule gives one detection for each event that matches. The detection has the title, the
description, the severity, and the ATT&CK techniques of the rule.

## The supported part of Sigma

| Part | Support |
| --- | --- |
| `title` | Necessary. |
| `id` | Optional. The default is `sigma.` and the title in lower case with `-`. |
| `status` | `stable`, `test`, `experimental`. A `deprecated` or `unsupported` rule never matches. |
| `description` | Optional. |
| `level` | `informational`, `low`, `medium`, `high`, `critical`. The default is `medium`. |
| `tags` | ATT&CK technique tags and tactic tags. Refer to [ATT&CK tags](#attck-tags). |
| `logsource` | `product`, `service`, and `category`. Refer to the table below. |
| `detection` | Named selections and one `condition`. |
| `aegis.verdict` | `malicious` or `suspicious`. An AEGIS extension. Refer to [Verdicts](#verdicts). |

The engine ignores all other top-level keys, for example `author` and `references`.

### Log source

| Key | The rule applies to an event if |
| --- | --- |
| `product` | The value is the product or the vendor of the event source. |
| `service` | The value is the product or the connector of the event source. |
| `category` | The value is the class of the event, for example `authentication`. |

A rule with no `logsource` applies to each event.

### Selections

A selection is a map of fields, or a list of such maps.

- All fields of a map must match. One map of a list must match.
- A field with a list of values matches if one value matches.
- Text comparison ignores case.
- `*` matches zero or more characters. `?` matches one character.
- A field that holds a list matches if one item of the list matches.
- The value `null` matches a field that is absent.

| Modifier | Meaning |
| --- | --- |
| `contains`, `startswith`, `endswith` | The value is a part, the start, or the end of the text. |
| `re` | The value is a regular expression. It keeps the case. |
| `cidr` | The value is a network. The field is an address in that network. |
| `gt`, `gte`, `lt`, `lte` | A numeric comparison. |
| `exists` | With `true`, the event has the field. With `false`, it does not. |
| `all` | Each value of the list must match, not only one. |

Write a modifier after the field name: `actor.user_agent|contains: curl/`.

### Conditions

A condition can use `and`, `or`, `not`, and parentheses. It can also use
`1 of selection*`, `all of selection*`, a number before `of`, `1 of them`, and
`all of them`.

### Parts that are not supported

Keyword lists, aggregation (`| count()`, `timeframe`), correlation rules, and all other
modifiers are errors. The engine does not ignore them, because a rule that loses a part
can match too many events. These are real messages:

```text
the selection "keywords" is a list of keywords; use a list of maps
the condition uses "|"; aggregation is not supported
the field "action" has the modifier "base64", which is not supported; the modifiers are contains, startswith, endswith, re, cidr, all, gt, gte, lt, lte, exists
```

For a count in a time window, use the velocity detectors of the engine. Refer to
[configuration.md](configuration.md#detection).

## Field names

| Field name | Value |
| --- | --- |
| `action`, `outcome`, `severity`, `class` | The top-level fields of the event. |
| `actor.id`, `actor.kind`, `actor.name`, `actor.tenant`, `actor.ip`, `actor.user_agent`, `actor.session_id` | The principal that did the activity. |
| `target.id`, `target.kind`, `target.name`, `target.tenant` | The entity that the activity changed or accessed. |
| `source.connector`, `source.vendor`, `source.product`, `source.tenant` | The connector and the product that supplied the event. |
| `attributes.<key>` | One attribute. A path such as `attributes.geo.city` goes into objects. |
| `raw.<path>` | A path into the original record of the source system. |
| Each other name | The attribute with that name. `app_id` is the same as `attributes.app_id`. |

## The event vocabulary

All source connectors convert their records to one normalized event. A rule reads the
names of this vocabulary, so one rule works for all sources. The definitions are in
[`crates/contracts/src/event.rs`](../crates/contracts/src/event.rs).

### The event

This is one event of the recorded attack log, in its JSON form:

```json
{
  "id": "01930000-0000-7000-8000-00000000026a",
  "time": "2026-11-03T09:10:46Z",
  "source": { "connector": "fixture", "vendor": "microsoft", "product": "entra_id", "tenant": "tenant-contoso" },
  "class": "user_access_management",
  "action": "role.assign",
  "outcome": "success",
  "severity": "informational",
  "actor": { "kind": "service_principal", "id": "sp-sync-helper", "name": "Sync Helper", "tenant": "tenant-contoso", "ip": "203.0.113.51", "user_agent": "python-httpx/0.27.0" },
  "target": { "kind": "service_principal", "id": "sp-sync-helper", "name": "Sync Helper", "tenant": "tenant-contoso" },
  "attributes": { "app_id": "app-sync-helper", "privileged": true, "role_id": "62e90394-69f5-4237-9190-012177145e10", "role_name": "Global Administrator" }
}
```

| Field | Necessary | Values |
| --- | --- | --- |
| `id` | Yes | A UUID. |
| `time` | Yes | An RFC 3339 time. |
| `source` | Yes | `connector`, `vendor`, `product`, and an optional `tenant`. |
| `class` | Yes | Refer to the list below. |
| `action` | Yes | Refer to the table below. |
| `outcome` | No | `success`, `failure`, or `unknown`. The default is `unknown`. |
| `severity` | No | `informational`, `low`, `medium`, `high`, or `critical`. The default is `informational`. |
| `actor` | Yes | `kind` and `id`. Optional: `name`, `tenant`, `ip`, `user_agent`, `session_id`. |
| `target` | No | `kind` and `id`. Optional: `name`, `tenant`. |
| `attributes` | No | A map of more data. |
| `raw` | No | The original record. |

The event classes are `authentication`, `account_change`, `user_access_management`,
`entity_management`, `api_activity`, `network_activity`, `process_activity`,
`file_activity`, `detection_finding`, and `other`.

The entity types for `actor.kind` and `target.kind` are `user`, `service_principal`,
`application`, `device`, `host`, `ip_address`, `domain`, `tenant`, `session`, `secret`,
`role`, `resource`, and `other`.

### Actions

| `action` | Activity |
| --- | --- |
| `sign_in` | An interactive or non-interactive sign-in. |
| `sign_out` | The end of a session. |
| `oauth.consent_grant` | A user or an administrator consents to permissions for an application. |
| `app.create` | A new application registration. |
| `app.credential_add` | A new secret or certificate on an application or a service principal. |
| `app.credential_remove` | The removal of a secret or certificate. |
| `app.permission_grant` | A grant of an application permission to a service principal. |
| `service_principal.create` | A new service principal. |
| `service_principal.disable` | A change that disables a service principal. |
| `role.assign` | The assignment of a directory role to a principal. |
| `role.remove` | The removal of a directory role from a principal. |
| `user.create` | A new user account. |
| `user.update` | A change to a user account. |
| `user.password_reset` | A password reset or a password change. |
| `mfa.method_change` | A change to a multi-factor authentication method. |
| `api.call` | A call to a cloud control-plane or data-plane API. |
| `secret.read` | A read of a secret from a vault. |
| `network.connect` | A network connection. |
| `process.start` | The start of a process. |
| `honeytoken.trip` | A read or a use of a honeytoken. |

A connector can emit an action that is not in this table. The form is lower case, with
`.` between the object and the verb.

### Attributes

| Key | Contents |
| --- | --- |
| `app_id`, `app_name` | The application that the event refers to. |
| `role_id`, `role_name` | The directory role or the application permission. |
| `privileged` | `true` if the role or the permission gives privileged access. |
| `credential_type`, `credential_id` | The type and the identifier of a credential. |
| `scopes` | The permission scopes in a grant, as a list. |
| `resource_tenant`, `home_tenant` | The tenant of the resource, and the home tenant of the actor. |
| `country`, `city`, `latitude`, `longitude` | The place of the actor. |
| `failure_reason`, `error_code` | The reason and the code that the source system gives for a failure. |
| `auth_protocol` | The authentication protocol or the client application type. |
| `mfa_satisfied` | `true` if the sign-in satisfied multi-factor authentication. |
| `operation` | The name of the API operation. |
| `destination_ip`, `destination_port`, `destination_domain` | The destination of a network connection. |
| `honeytoken_id` | The identifier of a honeytoken. |

A connector can add keys that are not in this table. The form is lower case, with `_`
between words.

## ATT&CK tags

- A tag `attack.t1110.003` names the technique T1110.003.
- A tag `attack.credential-access` names a tactic. It sets the tactic of the techniques
  of the rule.
- The engine has a catalog with the names of the techniques that it knows. For a
  technique that is not in the catalog, the name is the identifier.
- The engine ignores a tag that is not an ATT&CK tag.

The techniques of a detection go to its incident. A playbook trigger reads them. The
correlator makes an incident `critical` at three different techniques.

## Verdicts

| Level of the rule | Verdict of its detections | What follows |
| --- | --- | --- |
| `high` or `critical` | `malicious` | No more analysis. The Analyst agent confirms the incident also with no model. |
| `informational`, `low`, or `medium` | `suspicious` | With a model, tier 2 examines the detection. With no model, the incident stays `open` for a person. |

The top-level key `aegis.verdict` replaces this default. Use it for a rule that has a
moderate severity and no legitimate cause:

```yaml
level: medium
aegis.verdict: malicious
```

A model can make a `suspicious` detection `benign`. A model cannot change a `malicious`
detection, because such a detection never goes to the model. Give a rule the verdict
`malicious` only if a match needs no more analysis.

## Indicators

An indicator file is YAML or JSON in the directory `indicators` of the pack.

```yaml
indicators:
  - type: ip
    value: 192.0.2.200/29
    description: Example network of a relay that an attacker uses for sign-in attempts.
    severity: high
    tags:
      - attack.command-and-control
      - attack.t1090.003
```

| Key | Necessary | Contents |
| --- | --- | --- |
| `type` | Yes | `ip`, `domain`, `user_agent`, or `app_id`. |
| `value` | Yes | For `ip`: an address or a network in CIDR form, IPv4 or IPv6. |
| `description` | Yes | What the indicator is. |
| `severity` | Yes | `informational`, `low`, `medium`, `high`, or `critical`. |
| `tags` | No | ATT&CK tags. |
| `verdict` | No | `malicious` or `suspicious`. The default comes from the severity. |
| `id` | No | The rule identifier of the detections. The default is `ioc:{type}:{value}`. |

An event that matches an indicator gives a detection with the title
`Indicator match: {type} {value}`. The cost of the lookup for one event does not grow
with the number of indicators.

The indicator file of the shipped pack holds examples only. All its addresses are in
documentation ranges. Replace the file with indicators from your threat intelligence
source.

## Worked example: add a rule and test it

This example adds a rule for a sign-in by an emergency access account. Such an account
is only for an emergency, so each sign-in needs an examination.

Build the program first. Refer to [quickstart.md](quickstart.md). Do these steps in the
root of the repository.

1. Make a starter directory.

   ```sh
   aegis init --dir /tmp/aegis-pack
   ```

2. Write the file
   `/tmp/aegis-pack/detections/aegis-identity/rules/emergency_account_sign_in.yml`:

   ```yaml
   title: Sign-in by an emergency access account
   id: 806d0e8b-870f-42b5-a78f-ef2f96f0ac32
   status: test
   description: >-
     An emergency access account signed in. This account is only for an emergency. Each
     sign-in needs an examination by a person.
   logsource:
     category: authentication
   detection:
     selection:
       action: sign_in
       outcome: success
       actor.name|startswith: 'emergency-access'
     condition: selection
   falsepositives:
     - A planned test of the emergency access account.
   level: medium
   aegis.verdict: malicious
   tags:
     - attack.initial-access
     - attack.t1078.004
   ```

   Give each rule a new identifier. The command `uuidgen` makes one.

3. Check the configuration. The check loads the pack and reports a rule that is not
   valid.

   ```sh
   aegis config check --config /tmp/aegis-pack/aegis.toml
   ```

   The summary shows one more rule than before:

   ```text
     rule_pack: aegis-identity
     rules: 10
   ```

4. Write test events to the file `/tmp/aegis-pack/test-events.jsonl`, one event in each
   line. Include events that must match and events that must not match.

   ```json
   {"id":"01960000-0000-7000-8000-000000000001","time":"2026-11-12T03:00:00Z","source":{"connector":"example","vendor":"example","product":"directory","tenant":"tenant-example"},"class":"authentication","action":"sign_in","outcome":"success","actor":{"kind":"user","id":"user-ines","name":"ines@example.com","ip":"198.51.100.21"}}
   {"id":"01960000-0000-7000-8000-000000000002","time":"2026-11-12T03:05:00Z","source":{"connector":"example","vendor":"example","product":"directory","tenant":"tenant-example"},"class":"authentication","action":"sign_in","outcome":"success","actor":{"kind":"user","id":"user-emergency","name":"emergency-access@example.com","ip":"203.0.113.90"}}
   {"id":"01960000-0000-7000-8000-000000000003","time":"2026-11-12T03:06:00Z","source":{"connector":"example","vendor":"example","product":"directory","tenant":"tenant-example"},"class":"authentication","action":"sign_in","outcome":"failure","actor":{"kind":"user","id":"user-emergency","name":"emergency-access@example.com","ip":"203.0.113.90"}}
   ```

   The first event is a different user. The second event must match. The third event is
   a failed sign-in, which the rule does not select.

5. Examine the events with the pack. `aegis monitor` takes no action.

   ```sh
   aegis monitor --config /tmp/aegis-pack/aegis.toml \
       --events /tmp/aegis-pack/test-events.jsonl
   ```

   ```text
   DETECTION  2026-11-12T03:05:00.000Z  medium         malicious   T1078.004               Sign-in by an emergency access account  [806d0e8b-870f-42b5-a78f-ef2f96f0ac32]
   INCIDENT   8ebedb72-47b6-8195-bd07-f10e4e533138  medium         open            Sign-in by an emergency access account
              Detections: 1
              Techniques: T1078.004
              Entities:   user user-emergency; ip_address 203.0.113.90

   Monitoring session complete: 3 events, 1 detections, 1 incident states. Actions taken: 0.
   ```

   One event of three gives a detection. The verdict is `malicious`, because the rule
   sets `aegis.verdict`.

6. To see the full response to the events as a dry run, use `aegis replay`:

   ```sh
   aegis replay --config /tmp/aegis-pack/aegis.toml \
       --events /tmp/aegis-pack/test-events.jsonl --dry-run
   ```

For machine-readable output, add `--format json` to `monitor` or `replay`. Each line of
`monitor` is then one JSON value with a `type` field.

The directory [`examples/device-code-phishing`](../examples/device-code-phishing/README.md)
is a complete pack of its own, with a playbook and sample events.

## Apply a changed pack

The `aegis` program loads the pack at the start. To apply a changed pack:

1. Run `aegis config check`. Correct each problem.
2. Stop the service, and start it again.

If the pack is not valid, the service does not start, and the message names the file.

The detection engine itself can change its pack with no restart. A program that uses the
library calls `App::reload` or `DetectionEngine::reload_from_dir`. The change is atomic:
each event uses one pack from start to end, and no event is lost. If the new pack is not
valid, the old pack stays active. The state of the velocity detectors and the incidents
stay. The `aegis` program has no command that calls these functions.

## The pack that AEGIS ships

The pack `detections/aegis-identity` has nine rules for attacks on identity systems.

| Rule file | Level | ATT&CK | Finds |
| --- | --- | --- | --- |
| `account_locked_after_failed_sign_ins.yml` | low | T1110 | An account that the identity system locked after failed sign-ins. |
| `consent_to_privileged_permissions.yml` | high | T1528 | A consent to permissions with wide access. |
| `honeytoken_used.yml` | critical | T1552 | A read or a use of a honeytoken. |
| `legacy_mail_protocol_sign_in.yml` | medium | T1078.004 | A sign-in that succeeds with a legacy mail protocol. |
| `mfa_method_changed_by_script_client.yml` | medium | T1556.006 | A change of a multi-factor authentication method by a script client. |
| `mfa_request_denied.yml` | medium | T1621 | A multi-factor authentication request that the user denied. |
| `privileged_application_permission_granted.yml` | medium | T1098.003 | A privileged application permission that a person granted. |
| `privileged_role_assigned_by_workload_identity.yml` | high | T1098.003 | A privileged role that a workload identity assigned. |
| `user_created_by_workload_identity.yml` | medium | T1136.003 | A user account that a workload identity created. |

The velocity detectors and the honeytoken detector are a part of the engine, not of the
pack. Refer to [architecture.md](architecture.md#the-two-detection-tiers).

## Limits

- Sigma keyword lists, aggregation, and correlation rules are not supported.
- A rule gives one detection for each event that matches. The engine has no suppression
  for a rule that matches many events.
- A rule cannot compare two fields of one event.
- Tier 2 gets the event that completed a detection. It does not get older events.
- The state of the velocity detectors and of the correlator is in memory. It does not
  continue after a restart.
- The rule `legacy_mail_protocol_sign_in.yml` compares `auth_protocol` with a list of
  exact values. It matches the values `imap4` and `pop3` of the Entra ID source. It does
  not match the value `authenticated_smtp` of that source.
