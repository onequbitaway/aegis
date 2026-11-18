# Sharing

This document describes the commands that write documents for other defenders: abuse
reports and indicators. It also describes the evidence archive that the commands read.

**AEGIS sends nothing.** The commands write files. You read each file, and you decide if
it leaves your organization, to whom, and on which channel.

## Contents

- [The evidence archive](#the-evidence-archive)
- [The `[share]` section](#the-share-section)
- [Write an abuse report](#write-an-abuse-report)
- [Export indicators](#export-indicators)
- [Indicators for a rule pack](#indicators-for-a-rule-pack)
- [What the commands read](#what-the-commands-read)
- [Privacy rules](#privacy-rules)
- [Limits](#limits)

## The evidence archive

The detection engine keeps no event after it examined the event. The archive keeps the
data that a document needs:

| Record | Contents |
| --- | --- |
| `event` | One normalized event that a detection names. |
| `detection` | One detection. |
| `incident` | One state of an incident, with the identifiers of its detections. |

The archive is one JSON Lines file. Turn it on with the `[evidence]` section. The starter
configuration has the section.

```toml
[evidence]
path = "data/evidence.jsonl"
max_bytes = 67108864
```

- The archive keeps `max_bytes` at most, in the file and in one older file with the
  suffix `.1`. The oldest half goes first.
- The archive holds only the events that caused a detection, and 256 events for one
  detection at most. It does not hold all events of an address.
- The file holds raw log records. On Unix, only the owner can read it. Protect it as you
  protect your logs.
- The archive is not the audit log. A write that fails does not stop a detection.
  `GET /api/v1/status` shows the counts in the field `evidence`.
- `aegis replay --audit-file` and `aegis monitor` write no archive.

## The `[share]` section

The commands need all public networks of your organization. A document for a different
organization must not name an address of your own, and only you know your networks.

```toml
[share]
operator_networks = ["198.51.100.0/24"]
operator_domains = ["operator.example.org"]
```

With no `operator_networks`, each command refuses and writes no file:

```text
error: configuration error: the section `share` has no `operator_networks`. A document for a different organization must not name an address of your organization, and only you know your networks. Add all public networks of your organization, for example: [share] operator_networks = ["198.51.100.0/24"]. AEGIS wrote no document
```

Refer to [configuration.md](configuration.md#share) for each key.

## Write an abuse report

This procedure uses the recorded attack log. Its addresses are in the documentation
ranges, which a real document never names. Thus the procedure sets
`permit_documentation_ranges`. Do not set this key for a document that you send.

1. Run the demonstration in a directory.

   ```sh
   aegis demo --dir /tmp/aegis-share
   ```

   The output shows the identifier of the incident:
   `508657f7-d921-8cb3-add4-c2bd62528abd`.

2. Add the `[share]` section to `/tmp/aegis-share/aegis.toml`:

   ```toml
   [share]
   operator_networks = ["198.51.100.0/24"]
   permit_documentation_ranges = true
   ```

3. Write the reports.

   ```sh
   aegis report abuse --config /tmp/aegis-share/aegis.toml \
       --incident 508657f7-d921-8cb3-add4-c2bd62528abd --out /tmp/aegis-share/reports
   ```

   ```text
   Wrote 3 reports for the incident 508657f7-d921-8cb3-add4-c2bd62528abd to /tmp/aegis-share/reports:
     /tmp/aegis-share/reports/address-192.0.2.77/report.md
     /tmp/aegis-share/reports/address-192.0.2.77/report.json
     /tmp/aegis-share/reports/address-192.0.2.77/evidence.jsonl
     /tmp/aegis-share/reports/address-192.0.2.77/manifest.json
     /tmp/aegis-share/reports/address-203.0.113.50/report.md
     /tmp/aegis-share/reports/address-203.0.113.50/report.json
     /tmp/aegis-share/reports/address-203.0.113.50/evidence.jsonl
     /tmp/aegis-share/reports/address-203.0.113.50/manifest.json
     /tmp/aegis-share/reports/address-203.0.113.51/report.md
     /tmp/aegis-share/reports/address-203.0.113.51/report.json
     /tmp/aegis-share/reports/address-203.0.113.51/evidence.jsonl
     /tmp/aegis-share/reports/address-203.0.113.51/manifest.json

   Evidence that the command had:
     The incident comes from the evidence archive: the incident store of this configuration is in the memory of the service.
     The evidence archive gave 9 detections and 18 log records. The archive holds only the events that caused a detection, not all events of an address.
     The audit log has 156 records, and its hash chain verifies. 9 of them seal a detection of this document.

   Each report directory has a manifest. Check the evidence file against it:
     shasum -a 256 <directory>/evidence.jsonl

   AEGIS sent nothing. Read each document before you send it.
   ```

4. Check one evidence file against its manifest.

   ```sh
   cd /tmp/aegis-share/reports/address-203.0.113.50
   shasum -a 256 evidence.jsonl
   grep -o '"file_sha256": *"[0-9a-f]*"' manifest.json
   ```

   ```text
   15b2eec7cc5912c4e196403e34d76d939277369db32fbe3f6d9f8430aa40669a  evidence.jsonl
   "file_sha256": "15b2eec7cc5912c4e196403e34d76d939277369db32fbe3f6d9f8430aa40669a"
   ```

   The two hashes are the same. The hash is different in your run, because the audit
   records of your run have other times.

5. Read `report.md`. Send it only if each sentence is correct for your organization.

The command makes one directory for each attacker address:

| File | Contents |
| --- | --- |
| `report.md` | The body of a message to an abuse desk. |
| `report.json` | The same report for a program. |
| `evidence.jsonl` | The evidence: one minimized log record in each line. |
| `manifest.json` | The SHA-256 of each evidence item and of the evidence file. |

With `[[share.networks]]`, the command also makes one directory `network-N` for each
hosting network. The command replaces no file.

The report says "10 sign-in attempts" for the password spray of the recorded log, which
had 600 attempts. The archive holds the 10 events that the detection names. The output
of the command says so. A report states only what its evidence shows.

## Export indicators

`aegis indicators export` writes the indicators of the archive to one file. `--format`
selects the document, and `--tlp` sets its Traffic Light Protocol marking. The level has
no default.

```sh
aegis indicators export --config /tmp/aegis-share/aegis.toml \
    --format stix --tlp amber --out /tmp/aegis-share/indicators.json
```

```text
Wrote 4 indicators to /tmp/aegis-share/indicators.json (format stix, TLP:AMBER).

Evidence that the command had:
  The evidence archive gave 9 detections and 18 log records. The archive holds only the events that caused a detection, not all events of an address.
  The audit log has 156 records, and its hash chain verifies. 9 of them seal a detection of this document.

AEGIS sent nothing. Read each document before you send it.
```

```sh
aegis indicators export --config /tmp/aegis-share/aegis.toml \
    --format csv --tlp green --out /tmp/aegis-share/indicators.csv
```

The CSV file of the recorded attack log:

```text
type,value,basis,first_seen,last_seen,events,detections,techniques,tlp
ipv4,192.0.2.77,malicious_activity,2026-11-03T09:10:52.000Z,2026-11-03T09:10:52.000Z,1,2,T1059.009;T1078.004,TLP:GREEN
ipv4,203.0.113.50,malicious_activity,2026-11-03T09:10:00.000Z,2026-11-03T09:10:40.000Z,13,4,T1078;T1098.001;T1110.003;T1528,TLP:GREEN
ipv4,203.0.113.51,malicious_activity,2026-11-03T09:10:43.000Z,2026-11-03T09:11:15.000Z,4,5,T1059.009;T1078.004;T1098.003;T1552,TLP:GREEN
user_agent,python-httpx/0.27.0,malicious_activity,2026-11-03T09:10:00.000Z,2026-11-03T09:11:15.000Z,18,9,T1059.009;T1078;T1078.004;T1098.001;T1098.003;T1110.003;T1528;T1552,TLP:GREEN
```

| Option | Meaning |
| --- | --- |
| `--format stix` | One STIX 2.1 bundle: the TLP marking and one indicator for each value. |
| `--format csv` | CSV text with the TLP label in each row. |
| `--format pack` | An indicator file for your own rule pack. Refer to the next section. |
| `--tlp white`, `green`, `amber`, `red` | The level of a STIX or CSV document. `white` is the level that TLP 2.0 names `CLEAR`. |
| `--incident <id>` | Use only the detections of one incident. |

- A value is an indicator only if a `malicious` detection links it to an attack, or a
  decoy event shows it.
- The export never names an address in `operator_networks`, a private address, or a
  domain in `operator_domains`.
- The detections of an incident with the state `false_positive` give no indicator.
- With `[share.reporter]`, the STIX bundle names the reporter as its producer.
- The command replaces no STIX file and no CSV file.

## Indicators for a rule pack

`--format pack` uses only the detections of decoys. It writes the address, the client
fingerprint, and the user agent of each decoy client as an indicator file for the
detection engine. The file is for your own rule pack, so it has no TLP marking.

This example uses the directory of the test procedure in
[deception.md](deception.md#test-the-decoy), after the service stopped. Add the `[share]`
section to `/tmp/aegis-decoy/aegis.toml`:

```toml
[share]
operator_networks = ["198.51.100.0/24"]
```

```sh
aegis indicators export --config /tmp/aegis-decoy/aegis.toml \
    --format pack --out /tmp/aegis-decoy/decoy.yml
```

```text
Wrote 3 indicators to /tmp/aegis-decoy/decoy.yml (format pack, no TLP marking: the file is for your own rule pack).

Evidence that the command had:
  The evidence archive gave 5 detections and 4 log records. The archive holds only the events that caused a detection, not all events of an address.
  The audit log has 43 records, and its hash chain verifies. 5 of them seal a detection of this document.

Examine the file before you add it to a rule pack. A decoy shows what a client did. It does not show who the client is.

AEGIS sent nothing. Read each document before you send it.
```

The first indicator of the file:

```yaml
indicators:
- type: user_agent
  value: curl/8.7.1
  description: >-
    A client with this user agent contacted a decoy. The source made 5 detections
    for it.
  severity: low
  tags:
  - attack.reconnaissance
  - attack.t1595
  first_seen: "2026-11-18T19:57:54.750067Z"
  last_seen: "2026-11-18T19:57:54.774538Z"
  source: aegis decoy detections
  suppress_seconds: 3600
```

The client of this test was on the loopback address, so the file has no address
indicator. In an installation, the file also has the address of each remote client.

- If the file exists, it keeps its indicators and gets the new ones.
- No indicator has a severity above `medium`, so a match is `suspicious`.
- A user agent that starts with `Mozilla/` is not in the file.
- The file never names an address in `operator_networks`, and never a loopback address.
- Examine the file before you add it to a pack. A decoy shows what a client did. It does
  not show who the client is.

The recorded attack log has no decoy, so this format gives no file for it. Refer to
[deception.md](deception.md) for the decoy service, and to
[detection-packs.md](detection-packs.md#indicators) for indicator files.

## What the commands read

| Data | Source |
| --- | --- |
| The incident | The incident store, if `storage.kind` is `postgres`. If not, the last state in the evidence archive. |
| The log records | The evidence archive. |
| The audit records | The audit log of the configuration. |

- The commands open each file only to read. They are safe while the service runs.
- The commands check the hash chain of the audit log first. A log that does not verify
  is not evidence, and the command stops.
- The output of each command says which evidence the command had.
- An incident with the state `false_positive` gives no report.

## Privacy rules

The crate [`aegis-share`](../crates/share/README.md) has the full rules. In short:

- A report masks the identifiers of users, service principals, and targets. It removes
  display names, tenant identifiers, session identifiers, and the original record.
- A report says no name of a person or a group. It gives log data only.
- A report does not say that a service or a credential is a decoy.
- Text from an attacker, for example a user agent, is in code spans only.
- The check for secrets uses shapes and names. It cannot find each secret. Read each
  document before you send it.
- On Unix, only the owner can read a file that a command wrote.

## Limits

- AEGIS sends no document. It has no mail function and no connection to a sharing
  platform.
- AEGIS does no lookup of an address owner or an abuse contact. Give the hosting networks
  in `[[share.networks]]`.
- A report holds only the log records of the archive. For the full activity of an
  address, add the records of your log platform by hand.
- The archive holds no normal activity. The export thus cannot find that a legitimate
  client of your environment shows the same user agent or the same domain as an attacker.
  Examine each user agent and each domain before you send the document.
- With `storage.kind = "memory"` and no `[evidence]` section, the commands find no
  incident.
- The archive holds 256 events for one detection at most. The service finds the events
  of a detection in its memory of the 1024 newest events. A detection that names an older
  event has that event only in your log platform. The output of each command gives the
  number of events that the archive does not hold.
- The STIX export and the CSV export give no client fingerprint. Only the format `pack`
  gives it.
- The commands do not sign a document and do not encrypt it.
