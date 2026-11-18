# aegis-share

`aegis-share` turns what AEGIS saw into documents that the operator can send to other
defenders. It makes an abuse report package for one incident, and it exports indicators as
STIX 2.1 and as CSV. It has no offensive function.

**The crate makes documents only.** It opens no connection, it writes no file, and it
sends nothing. The operator reads each document and decides if it leaves the organization,
to whom, and on which channel. AEGIS never sends a document itself.

The crate depends only on `aegis-contracts` and on small utility crates.

## The outputs

| Output | Function | For |
| --- | --- | --- |
| `report.md` | `AbuseReport::to_markdown` | The body of a message to an abuse desk. |
| `report.json` | `AbuseReport::to_json_string` | The same report for a program. It holds the evidence and the manifest. |
| `evidence.jsonl` | `AbuseReport::evidence_jsonl` | The evidence: one minimized log record in each line. Attach it to the message. |
| `manifest.json` | `EvidenceManifest::to_json_string` | The SHA-256 of each evidence item and of the evidence file. The receiver uses it to check integrity. |
| STIX 2.1 bundle | `IndicatorSet::to_stix_string` | Indicators for a threat intelligence platform or a sharing community. |
| CSV | `IndicatorSet::to_csv` | The same indicators for a block list, a spreadsheet, or a script. |

`AbuseReport::files` returns the four report files as text.

## Abuse reports

`AbuseReport::build(incident, events, audit_records, options)` returns an
`AbuseReportPackage`:

- one report for each attacker address;
- one more report for each hosting network, if `options.networks` maps addresses to
  networks. The crate does no lookup. The caller finds the network of each address;
- notes for the operator that say what the builder left out, and why. Do not send the
  notes.

Each report is a complete document for one receiver. It holds only the records of its own
addresses.

```rust
use aegis_share::{AbuseReport, AbuseReportOptions, HostingNetwork, NetworkMap};

# fn example(
#     incident: &aegis_contracts::Incident,
#     events: &[aegis_contracts::Event],
#     audit_records: &[aegis_contracts::AuditRecord],
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut options = AbuseReportOptions::new(chrono::Utc::now());
options.addresses.operator_networks = vec!["198.51.100.0/24".parse()?];
options.networks = NetworkMap::new().with_prefix(
    "203.0.113.0/24".parse()?,
    HostingNetwork::new("AS64500 Example Hosting").with_abuse_contact("abuse@hosting.example"),
);

let package = AbuseReport::build(incident, events, audit_records, &options)?;
for report in &package.reports {
    for file in report.files()? {
        // Show the file to the operator. The operator decides if it is sent.
        println!("{} ({} bytes)", file.name, file.content.len());
    }
}
for note in &package.notes {
    eprintln!("left out: {note:?}");
}
# Ok(())
# }
```

### What a report contains

- **What occurred, in plain words.** A report is a list of claims. An activity claim says
  what the log records show, for example "The log records show 600 sign-in attempts from
  the address 203.0.113.50. All 600 failed." A detection claim says that a detection rule
  classified the activity.
- **The times in UTC**, with milliseconds.
- **The addresses and the destination ports.**
- **The user agents and the client fingerprints.** A fingerprint is a heuristic.
- **A short log excerpt for each claim**, and the identifiers of all evidence items of
  the claim.
- **The ATT&CK techniques** of the detections that have evidence.
- **The manifest.**

### Which address is an attacker address

An address is an attacker address if a detection of the incident links to it. The
detection must have the verdict `malicious`. A detection links to an address in two ways:

- it names the address as an entity;
- it cites a record from the address.

Set `include_suspicious` to use `suspicious` detections also. A `benign` detection is never
used. An incident in the state `false_positive` gives an error and no report.

The report holds the records from the address in a time range. The default range starts
one hour before the first detection evidence and ends one hour after the last. Set
`activity_margin` or `window` to change it. `max_evidence_items` limits the records for
one address. The default is 1,000. If the limit cuts records, the claim says so.

### Rules that the builder always obeys

- **No claim without evidence.** The builder drops a claim that has no evidence item and
  writes a note. `AbuseReport::check` fails for a report that breaks the rule.
- **No attribution.** A report never says who did the activity. All sentences come from
  templates in this crate. The builder copies no title, summary, timeline, or description
  from the incident or its detections, because a model or an analyst can write those
  texts. It keeps an ATT&CK technique identifier only if it has the correct form. It
  keeps a technique name only from a deterministic rule. Each report says: "This report
  gives log data of the reporter. It does not identify a person or a group."
- **A changed audit log is not evidence.** An audit record that does not have the hash
  of its contents stops the build with an error.

## Privacy rules

The defaults keep the least data. Each option that keeps more data is off.

### What the builder masks

| Data | Default | To keep it |
| --- | --- | --- |
| Identifier of a user, a service principal, or an other actor | A label such as `masked-3`. One entity has one label in one report. | `Field::ActorId` |
| Identifier of a target (application, secret, role, and so on) | A label such as `masked-4` | `Field::TargetId` |
| Display names | Removed | `Field::ActorName`, `Field::TargetName` |
| Tenant identifiers | Removed | `Field::Tenant` |
| Session identifiers | Removed | `Field::Session` |
| Connector name, vendor, product | Removed | `Field::Connector`, `Field::Product` |
| Event attributes | Only the keys in `DEFAULT_ATTRIBUTES` stay | `AllowList::with_attribute` |
| The original record (`raw`) | Removed | Not possible |
| Secrets in kept text | Replaced with `[secret removed]` | Not possible |
| The query of an HTTP path | Replaced with `[query removed]` | Not possible |
| That a service or a credential is a decoy | Not said. The action gets a neutral name. | `disclose_decoys` |
| The name of the reporter | Not in the report | `reporter` |

`DEFAULT_ATTRIBUTES` are `auth_protocol`, `bytes_received`, `client_fingerprint`,
`destination_port`, `error_code`, `failure_reason`, `http_method`, `http_path`,
`http_status`, `operation`, and `source_port`. They describe what the remote client did.

A label is a counter, not a hash. A hash of a user name lets a receiver test a guess.

The builder also finds each masked value in the text that stays, for example in a
failure reason, and replaces it with `[masked]`. It replaces each other IP address in
that text with `[address removed]`. A masked value with five characters or fewer is
replaced only as a full word.

### Secrets

The allow list is the first control. The second control examines the text that stays. It
replaces:

- the value of a key with a secret name, for example `password=`, `api_key=`, `token:`;
- the credential after `Bearer` or `Basic`;
- the user and the password in a URL;
- JSON Web Tokens, and tokens with a known prefix;
- long runs of letters and digits, and long base64 runs;
- PEM blocks.

This check uses shapes and names. It cannot find each possible secret. **Read each
document before you send it.**

### Addresses

`AddressPolicy` applies to the reports and to the indicator export:

- An address in `operator_networks` is never a report subject and never an indicator.
  Put all public networks of the operator in this list. The crate cannot know them.
- A private address, a shared carrier address, a loopback, link-local, multicast, or
  other special-purpose address is never a report subject and never an indicator.
- An address in a documentation range (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`) is left out by default.
  `permit_documentation_ranges` permits these ranges. The recorded attack log of AEGIS
  uses them, so the tests and the demonstration set this option. Do not set it for a
  document that you send.
- An IPv4 address in the IPv6-mapped form gets the rules of the IPv4 address.

### Text from an attacker

A user agent, a path, and each other event field is untrusted text.

- In Markdown, such text appears only in code spans and code blocks. Markup, links,
  images, and HTML in the text have no effect.
- In the JSON outputs, each character that is not printable ASCII is a `\uXXXX` escape.
  The characters `<`, `>`, `&`, and the backtick are escapes also.
- A control character or an invisible character, for example a direction override,
  becomes visible text such as `{U+202E}`.
- Long text is cut and ends with `...[cut]`.

## Integrity: the manifest

An evidence item is one line of JSON in printable ASCII. The manifest holds the SHA-256
and the length of each line, and the SHA-256 of `evidence.jsonl`.

The receiver checks one item with standard tools:

```sh
sed -n '3p' evidence.jsonl | tr -d '\n' | shasum -a 256
shasum -a 256 evidence.jsonl
```

A receiver that uses this crate calls `EvidenceManifest::verify_file`.

The manifest shows that an item did not change after the builder made it. It does not
show who made the package. To show the origin, sign the manifest, or send it on a second
channel. This crate does not sign.

An audit record becomes an evidence item with its sequence number, its time, and its
chain hash. The item holds no text of the record. The hash commits the reporter to the
full record, which stays in the audit log of the reporter.

## Indicator export

`IndicatorSet::collect(detections, events, options)` finds addresses, domains, and user
agents. A value becomes an indicator only if evidence links it to an attack:

- a `malicious` detection names it as an entity, or cites an event that shows it;
- or a decoy event shows it (`decoy.contact`, `decoy.canary_hit`, `honeytoken.trip`).

The export never gives:

- an address that only normal activity shows;
- a private or reserved address, or an address or a domain of the operator
  (`operator_networks`, `operator_domains`);
- a domain for private use or for infrastructure (`.local`, `.internal`, `.arpa`, and so
  on), and by default a documentation domain;
- a user agent or a domain that a client with no link to the attack also shows;
- a user agent that is shorter than four characters, that has a control character, or
  that holds a secret;
- a value from the operator side of an event. If the actor has a public address, the
  actor is the remote side. If the actor has a private, reserved, or operator address,
  or no address, the destination is the remote side.

`IndicatorSet::skipped` lists what the export left out, and why. It is for the operator.

An indicator from a decoy contact has the basis `anomalous_activity`. A scanner with no
bad intent also contacts a decoy. An indicator from a `malicious` detection or from the
use of a decoy credential has the basis `malicious_activity`.

A detection that comes from an indicator match gives back an indicator from a different
source. Obey the sharing terms of that source.

### STIX 2.1

```rust
use aegis_share::{IndicatorOptions, IndicatorSet, StixOptions, Tlp};

# fn example(
#     detections: &[aegis_contracts::Detection],
#     events: &[aegis_contracts::Event],
# ) -> Result<(), Box<dyn std::error::Error>> {
let mut options = IndicatorOptions::new().with_operator_domain("operator.example.org");
options.addresses.operator_networks = vec!["198.51.100.0/24".parse()?];
let indicators = IndicatorSet::collect(detections, events, &options)?;

// The caller must select the TLP level. There is no default.
let stix = indicators.to_stix_string(&StixOptions::new(Tlp::Amber, chrono::Utc::now()))?;
let csv = indicators.to_csv(Tlp::Amber);
# let _ = (stix, csv);
# Ok(())
# }
```

The bundle holds:

- the TLP marking definition of the STIX 2.1 specification;
- one `indicator` object for each indicator;
- one `identity` object, only if `StixOptions::producer` has a name.

| Indicator | Pattern |
| --- | --- |
| IPv4 address | `[ipv4-addr:value = '203.0.113.50']` |
| IPv6 address | `[ipv6-addr:value = '2001:db8::1']` |
| Domain | `[domain-name:value = 'bad.example']` |
| User agent | `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = 'curl/8.4.0']` |

- `valid_from` is the time of the first evidence. `valid_until` is 30 days after the
  last evidence by default. An address can get a new user, so keep an end.
- `indicator_types` is `malicious-activity` or `anomalous-activity`.
- `kill_chain_phases` and `external_references` give the ATT&CK tactics and technique
  identifiers. An indicator holds no free text from a detection.
- `object_marking_refs` gives the TLP level. STIX 2.1 defines `white`, `green`, `amber`,
  and `red`. `white` is the level that TLP 2.0 names `CLEAR`.
- **The identifiers are stable.** An identifier is a version 5 UUID of the type and the
  pattern, in the namespace `StixOptions::namespace`. The same indicator has the same
  identifier in each export. STIX recommends version 4 UUIDs, so a validator gives a
  warning for these identifiers. Set a namespace of your own if you want identifiers
  that only your organization makes.

### CSV

The columns are `type`, `value`, `basis`, `first_seen`, `last_seen`, `events`,
`detections`, `techniques`, and `tlp`. The file follows RFC 4180.

A spreadsheet program runs a cell that starts with `=`, `+`, `-`, or `@` as a formula.
A user agent is text from an attacker. The writer puts an apostrophe before such a
value. A program that reads the file must remove that apostrophe.

## Limits

- The crate does no lookup of an address owner or an abuse contact.
- The crate does not sign a document and does not encrypt it.
- The check for secrets uses shapes and names. It does not find each secret.
- An internationalized domain name must be in its ASCII form. The export leaves out a
  name with other characters.
- The export gives no client fingerprint as an indicator. STIX has no standard property
  for it. The abuse report shows the fingerprints.
- The STIX export supports the four TLP levels of STIX 2.1. It does not make the
  `AMBER+STRICT` marking of TLP 2.0.

## Tests

```sh
cargo test -p aegis-share
```

The tests replay the recorded attack log through `aegis-detect` to make the incident.
`aegis-detect` and `aegis-testkit` are development dependencies only.

The tests check the STIX output against the rules of the format. The parser of the tests
is independent of the writer. A second parser checks the CSV output against RFC 4180.
