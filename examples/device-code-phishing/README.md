# Example: a detection pack and a playbook for device code phishing

This example adds a detection pack and a playbook for one more identity threat. It shows
how to write, test, and run your own pack and playbook.

Each response action is a dry run. The example changes nothing in your environment.

## The threat

In device code phishing, an attacker starts a sign-in with the device code flow and sends
the code to a user. The user enters the code and completes multi-factor authentication.
The attacker then gets the tokens of the user. Frequently, the attacker registers a
device to keep the access after a password change.

This pack finds the two steps. The playbook stops the sessions of the user, which makes
the stolen tokens invalid.

## Files

| File | Contents |
| --- | --- |
| `aegis.toml` | The configuration. It loads the pack and the playbook of this example. |
| `detections/device-code-phishing/pack.yml` | The manifest of the pack. |
| `detections/device-code-phishing/rules/device_code_sign_in.yml` | Sigma rule: a sign-in with the device code flow. ATT&CK T1566.002. |
| `detections/device-code-phishing/rules/device_registered_by_user.yml` | Sigma rule: a user registers a device. ATT&CK T1098.005. |
| `detections/device-code-phishing/indicators/examples.yml` | One example indicator: a relay network in a documentation range. |
| `playbooks/contain-device-code-phishing.yaml` | The playbook. |
| `events.jsonl` | Six sample events: four normal sign-ins and the two attack steps. |

The two rules have the level `medium`. Their detections thus have the verdict
`suspicious`. With a model, detection tier 2 examines each `suspicious` detection.

## Check the configuration

```sh
aegis config check --config examples/device-code-phishing/aegis.toml
```

```text
The configuration examples/device-code-phishing/aegis.toml is valid.
  agents_dry_run: true
  api: off
  bus: memory
  connectors: honeytokens, simulation
  decoy: off
  dispatcher_dry_run: true
  evidence_archive: off
  model: false
  modules: ingest, detection, monitor, hunter, analyst, responder, deception, reporter
  playbook_mode: dry_run
  playbooks: contain-device-code-phishing
  rule_pack: device-code-phishing
  rules: 2
  sources: 
  storage: memory
  timed_revert: off
```

The check loads the pack and the playbook. A rule or a playbook that is not valid is a
problem that names the file.

## Test the rules against the sample events

`aegis monitor` examines an event file and takes no action. Use it to test rules.

```sh
aegis monitor --config examples/device-code-phishing/aegis.toml \
    --events examples/device-code-phishing/events.jsonl
```

```text
DETECTION  2026-11-10T08:14:05.000Z  medium         suspicious  T1566.002               Sign-in with the device code flow  [5fa29e3f-71e7-4c11-aca3-3341cf6f34f4]
DETECTION  2026-11-10T08:14:05.000Z  medium         suspicious  T1090.003               Indicator match: ip 198.51.100.192/28  [ioc:ip:198.51.100.192/28]
DETECTION  2026-11-10T08:14:05.000Z  medium         suspicious  T1078.004               Principal acts from two places at an impossible speed  [aegis.velocity.impossible_speed]
INCIDENT   bf3017ea-73d9-8312-8b40-c9c8bb87ef1e  critical       open            Multi-stage attack: 3 ATT&CK techniques in 3 detections
           Detections: 3
           Techniques: T1566.002, T1090.003, T1078.004
           Entities:   user user-lena; ip_address 198.51.100.200; ip_address 198.51.100.21
DETECTION  2026-11-10T08:14:45.000Z  medium         suspicious  T1098.005               Device registered by a user  [75f41c37-bc10-4ebe-a7ea-12144da07d2a]
DETECTION  2026-11-10T08:14:45.000Z  medium         suspicious  T1090.003               Indicator match: ip 198.51.100.192/28  [ioc:ip:198.51.100.192/28]
INCIDENT   bf3017ea-73d9-8312-8b40-c9c8bb87ef1e  critical       open            Multi-stage attack: 4 ATT&CK techniques in 5 detections
           Detections: 5
           Techniques: T1566.002, T1090.003, T1078.004, T1098.005
           Entities:   user user-lena; ip_address 198.51.100.200; ip_address 198.51.100.21; device device-7f3a

Monitoring session complete: 6 events, 5 detections, 2 incident states. Actions taken: 0.
```

What the output shows:

- The two rules of the pack match the two attack steps. The four normal sign-ins give
  no detection.
- The indicator matches the address of the attacker in the two events.
- The built-in velocity detector `impossible_speed` also fires. The user signed in from
  two countries in fewer than nine minutes. The velocity detectors operate with each pack.
- The correlator puts all detections in one incident, because they share the user.
- The incident is `critical`, because it has three or more ATT&CK techniques.

## Run the playbook as a dry run

`aegis replay` examines the same events with all modules, and prints the actions.

```sh
aegis replay --config examples/device-code-phishing/aegis.toml \
    --events examples/device-code-phishing/events.jsonl --dry-run
```

The command prints the same five detections and the incident, and then these parts:

```text
Actions (3)
  kill_session                user user-lena                                  playbook:contain-device-code-phishing     executed: simulated (connector simulation)
  notify                      other security-operations                       playbook:contain-device-code-phishing     executed: simulated (connector simulation)
  open_ticket                 other identity-team                             playbook:contain-device-code-phishing     executed: simulated (connector simulation)
  No action changed the environment.

Playbooks (1)
  contain-device-code-phishing: 3 requests, 0 failures

Audit log
  Records: 24
  Records checked: 24
  Chain: valid
```

What the output shows:

- The trigger of the playbook needs the two techniques T1566.002 and T1098.005 and a
  user entity. The incident has them after the second attack step.
- Each request went through the policy, a connector, and the audit log. The connector is
  the simulation connector, because the example configures no real connector.
- The incident stays `open`. No detection has the verdict `malicious`, and the example
  has no model. Thus the Analyst agent does not confirm the incident, and the Responder
  agent proposes no action. A playbook does not wait for the Analyst agent.

## Use the pack and the playbook in your installation

1. Copy the directory `detections/device-code-phishing` to your configuration directory.
2. Copy `playbooks/contain-device-code-phishing.yaml` to your playbook directory.
3. Replace the example indicators with indicators from your threat intelligence source,
   or remove the file.
4. One process loads one pack. To use these rules with the rules of `aegis-identity`,
   copy the rule files into one pack directory.
5. Run `aegis config check`, and then test with `aegis monitor` on your own events.

## Limits

- The rule `device_code_sign_in` matches each completed device code sign-in. A device
  with no keyboard also uses this flow. Add a filter for the applications that you
  permit.
- The rule `device_registered_by_user` reads the action `device.register` or
  `register.device`. A source connector must give one of these names for a device
  registration.
- The sample events are examples in the normalized event format. They did not come from
  a real tenant.

Refer to [`docs/detection-packs.md`](../../docs/detection-packs.md) and
[`docs/playbooks.md`](../../docs/playbooks.md) for the formats.
