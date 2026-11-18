# aegis-bus

The message bus of AEGIS. This crate has the production implementation of the
`aegis_contracts::MessageBus` contract on NATS JetStream. It also has an in-process bus for
a deployment that is one binary with no NATS server.

Kafka is an optional follow-up. This crate does not have a Kafka bus.

## Use

```rust
use aegis_bus::BusConfig;
use aegis_contracts::bus::{publish_json, subject};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `kind = "nats"` connects to NATS JetStream. `kind = "memory"` needs no server.
    let config: BusConfig = toml::from_str(r#"kind = "memory""#)?;
    let bus = aegis_bus::connect(&config).await?;

    publish_json(bus.as_ref(), subject::AUDIT, &"record").await?;

    let mut records = bus.subscribe("aegis.audit", Some("archive")).await?;
    if let Some(item) = records.next().await {
        let record: String = item?.decode()?;
        assert_eq!(record, "record");
    }
    Ok(())
}
```

## Public API

| Item | Function |
| --- | --- |
| `connect(&BusConfig)` | Makes the bus that `kind` selects, as `Arc<dyn MessageBus>`. For NATS, it connects and then calls `ensure_stream`. |
| `BusConfig` | The configuration. It implements `serde::Deserialize` and `Default`. `validate()` checks it. |
| `BusKind` | `Nats` (default) or `Memory`. |
| `NatsConfig`, `NatsAuth`, `TlsConfig` | The connection, the credentials, and the TLS settings. |
| `SecretString` | The type of the passwords and the tokens in `NatsAuth` (from the `secrecy` crate). |
| `StreamConfig`, `StorageKind` | The stream that stores the messages. |
| `ConsumerConfig` | The settings of durable subscriptions on NATS. |
| `NatsBus::connect(&BusConfig)` | Connects to NATS. It does not create the stream. |
| `NatsBus::ensure_stream()` | Creates or updates the stream. Returns `StreamStatus` (`Created`, `Updated`, `Unchanged`). |
| `InProcessBus::new(&BusConfig)` | Makes the in-process bus. It uses only the `stream` section. |

`NatsBus` and `InProcessBus` implement `MessageBus` (`publish` and `subscribe`).

## Configuration

All settings have defaults. This example shows all settings with their default values.
A key that the crate does not know is an error.

```toml
kind = "nats"                        # "nats" or "memory"

[nats]
urls = ["nats://127.0.0.1:4222"]     # "nats://" or "tls://". Do not put credentials in a URL.
connection_name = "aegis"
connect_timeout = "5s"               # The time limit for the first connection.
request_timeout = "5s"               # The time limit for one request and for a publish acknowledgement.

[nats.auth]
method = "none"                      # "none", "user_password", "token", or "credentials_file"

[nats.tls]
required = false                     # Refuse a connection that has no TLS.

[stream]
name = "AEGIS"
subjects = ["aegis.>"]
max_age = "7days"                    # "0s" means no age limit.
max_bytes = 1073741824               # 0 means no size limit.
storage = "file"                     # "file" or "memory"
replicas = 1                         # 1 to 5
manage = true                        # Let AEGIS create and update the stream.

[consumer]
ack_wait = "30s"
pull_batch = 1
pull_expires = "10s"
```

Credentials (select one method):

```toml
[nats.auth]
method = "user_password"
user = "aegis"
password = "..."
```

```toml
[nats.auth]
method = "token"
token = "..."
```

```toml
[nats.auth]
method = "credentials_file"          # A NATS credentials file: a user JWT and an NKey seed.
path = "/run/secrets/aegis.creds"
```

TLS:

```toml
[nats.tls]
required = true
ca_file = "/etc/aegis/nats-ca.pem"             # Trust only these certificate authorities.
client_cert_file = "/etc/aegis/nats-client.pem" # For mutual TLS. Set the two client files together.
client_key_file = "/etc/aegis/nats-client.key"
```

- TLS is mandatory when `required` is `true`, when a file is set, or when a URL has the
  scheme `tls://`. The bus then refuses a server that has no TLS.
- Without `ca_file`, the bus trusts the certificate authorities of the operating system.
- The bus always checks the certificate and the name of the server. You cannot switch off
  this check.
- When TLS is not mandatory, the bus uses TLS only if the server demands it. The bus writes
  a warning to the log if a password or a token can go over a connection without TLS.

The in-process bus (`kind = "memory"`) uses only `stream.subjects`, `stream.max_age`, and
`stream.max_bytes`. It ignores the `nats` and `consumer` sections.

### Secrets

- Passwords and tokens are `secrecy::SecretString` values. The `Debug` output of the
  configuration does not show them. It also hides credentials in a URL.
- `BusConfig` has no `Serialize` implementation.
- Error messages and log lines of this crate do not contain credentials or payloads.
- The bus rejects a URL that contains credentials. Use `nats.auth`.

### Stream settings

`ensure_stream` compares the stream on the server with the `stream` section:

- If the stream is missing, it creates the stream (retention policy `Limits`, discard policy
  `Old`).
- If `subjects`, `max_age`, `max_bytes`, or `replicas` are different, it updates the stream.
  The update keeps the stored messages.
- If the settings are equal, it changes nothing. You can call it again at any time.
- JetStream cannot change `storage`. A different value is an `Error::Config`.

Set `manage = false` if the NATS account of AEGIS has no permission to change streams. An
administrator must then create the stream. The bus only checks that the stream exists and
stores the configured subjects.

### NATS permissions

With NATS permissions, the account of AEGIS needs these subjects. Replace `AEGIS` with the
stream name and `aegis.>` with the stream subjects.

| Direction | Subjects |
| --- | --- |
| Publish | `aegis.>`, `$JS.API.STREAM.INFO.AEGIS`, `$JS.API.CONSUMER.INFO.AEGIS.*`, `$JS.API.CONSUMER.CREATE.AEGIS.>`, `$JS.API.CONSUMER.DELETE.AEGIS.*`, `$JS.API.CONSUMER.MSG.NEXT.AEGIS.*`, `$JS.ACK.AEGIS.>` |
| Publish, only with `manage = true` | `$JS.API.STREAM.CREATE.AEGIS`, `$JS.API.STREAM.UPDATE.AEGIS` |
| Subscribe | `_INBOX.>` |

## Subjects, patterns, and durable names

- A subject has tokens with `.` between them. Empty tokens, whitespace, and control
  characters are not permitted. The maximum length is 255 bytes.
- `publish` accepts only a subject with no wildcards (`*`, `>`). The subject must be in
  `stream.subjects`. If not, `publish` returns `Error::InvalidInput` and stores nothing.
- A subscription pattern can use `*` for one token and `>` for all remaining tokens. `>`
  is permitted only as the last token. A pattern that cannot match a stored subject is an
  `Error::InvalidInput`.
- A durable name has 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `-`, and `_`.
- One durable name reads one pattern. If a durable name already reads a different pattern,
  `subscribe` returns `Error::InvalidInput`. Use a different durable name for a different
  pattern. To change the pattern of a name on NATS, delete the consumer first
  (`nats consumer rm AEGIS <name>`).

## Delivery rules

### Publish

`publish` returns `Ok` only after the bus stored the message. On NATS, it waits for the
acknowledgement of JetStream.

If `publish` returns a retryable error (`Unavailable`, `Timeout`, `RateLimited`), the server
possibly stored the message. If you publish again, the stream can have the message two
times.

### Subscription with no durable name

- The subscription gets only the messages that the bus stores after `subscribe` returns.
- It gets each message one time, in the sequence of the stream.
- The bus keeps no position for it. When the stream object or the process goes away, the
  position is lost.
- A message that the retention limits remove before delivery is not delivered.

### Subscription with a durable name

The guarantee is **at least once**.

- A new durable name starts at the first message that the stream holds.
- The bus keeps the position of the name. A consumer that starts again with the same name
  continues after its last acknowledged message.
- Consumers that use the same durable name share the messages. Each message goes to one of
  them.
- **The bus acknowledges a message when the caller polls the stream for the next message.**
  Thus, complete the work on a message before you poll again.
- If the caller drops the stream before that poll, the bus gives the message back. The bus
  then delivers the message again, to any consumer with the same name.

A consumer can get a message more than one time in these conditions:

1. The consumer stopped (the stream object or the process went away) after it got a message
   and before it polled again. The message that was in work arrives again. This is one
   message for each consumer that stopped.
2. The time between two polls was longer than `consumer.ack_wait`. The server then sends the
   message again while the first copy is in work.
3. The acknowledgement did not get to the server, for example because the connection or the
   server stopped at that moment.
4. A publisher stored the message two times (refer to "Publish").

No condition loses a message that the stream holds. Make the handlers idempotent, for
example with the identifier of the event.

The retention limits of the stream apply to all subscriptions. If a consumer is so far
behind that the stream removed a message (`max_age`, `max_bytes`), the consumer does not
get that message.

A message that the bus delivers again can arrive after newer messages. All other messages
arrive in the sequence of the stream.

The bus has no limit for the number of deliveries and no dead-letter subject. If a handler
cannot process a message, the handler must record the failure and poll again. If the handler
drops the stream each time, the same message arrives each time.

### `consumer` settings (NATS)

- `ack_wait`: the server sends a message again when it gets no acknowledgement in this
  time. This is how a message leaves a consumer that stopped with no warning. Set the value
  larger than the longest time between two polls. If the caller needs more than
  `pull_expires` + 5 seconds for one message, the client can take one or two messages
  ahead. Their time starts when the client takes them. For such slow handlers, set
  `ack_wait` to three times the longest handling time or more. A change of `ack_wait`
  applies to an existing durable name at the next `subscribe`.
- `pull_batch`: the number of messages that a durable subscription takes from the server in
  one request. With the default of 1, a consumer asks for one message at a time. A larger
  value increases the throughput. But a consumer then holds messages that other consumers
  with the same name cannot get, and these messages wait for `ack_wait` if the consumer
  stops.
- `pull_expires`: the life of one pull request. The server sends a heartbeat at half of this
  interval. After two missed heartbeats, the subscription reports an outage.

## Errors

| Condition | Error |
| --- | --- |
| A subject, a pattern, or a durable name that is not valid; a message that is too large | `InvalidInput` |
| A setting that is not valid; a file that is not readable; a TLS handshake that failed (for example a server certificate that is not trusted); stream settings that the server refuses; JetStream not enabled for the account | `Config` |
| The server rejected the user, the password, the token, the credentials file, or the TLS client certificate; the account has no permission for the request | `Unauthorized` |
| No server answers; the connection is lost; JetStream gives no answer; the stream or the durable consumer does not exist; the server has no capacity | `Unavailable` (retryable) |
| The server did not answer in `connect_timeout` or `request_timeout` | `Timeout` (retryable) |
| The server limits the request rate | `RateLimited` (retryable) |

Notes:

- `NatsBus::connect` makes one attempt for each URL. It does not wait for a server that is
  down. The error is retryable, so the caller can try again.
- A NATS server gives no answer to a request that it does not permit. Thus, the bus reports
  a permission error only after `request_timeout`.
- The bus does not connect again after a TLS failure or an authorization failure at the
  start. These errors are not retryable.

### Errors in a subscription stream

An item of a subscription stream is a message or an error.

- After an error item, poll the stream again. The stream continues if it can.
- When the stream cannot continue, it gives one last error item and then ends (`None`).
  Subscribe again. A durable name continues at its position.

## Connection loss and server restart

The NATS client connects again with no time limit. The bus object and the subscription
streams stay valid.

- A subscription stream **continues** after a restart of the server or a network outage. You
  do not have to subscribe again.
- During the outage, the stream gives retryable error items (`Unavailable` or `Timeout`),
  one for each `pull_expires` interval approximately.
- A durable subscription loses no message. A message with no acknowledgement can arrive
  again.
- A subscription with no durable name continues at its position in the stream. It gets
  each message one time, in sequence. After a restart of the server, it continues
  approximately `pull_expires` after the server is back.
- `publish` returns `Timeout` or `Unavailable` during the outage.
- A durable subscription ends, with a last `Unavailable` item, only if the server no longer
  has its consumer (for example, an administrator deleted it) or the connection is closed.
  Subscribe again.

A stream with `storage = "memory"` does not survive a restart of a single NATS server. Use
`storage = "file"` (the default) in production.

## The in-process bus

`kind = "memory"` makes `InProcessBus`. It has the same rules as the NATS bus: the same
checks of subjects, patterns, and durable names, the same subscription semantics, and
delivery at least once for durable names. The same test cases run against the two buses.

Differences:

- All messages and positions go away when the process stops.
- The messages use the memory of the process, up to `stream.max_bytes` (default 1 GiB).
  Set a smaller value on a small host.
- The bus has no `ack_wait`. It delivers a message again only when the consumer drops the
  stream before the next poll.
- The retention limits use the length of the subject plus the length of the payload as the
  size of a message. A message that is larger than `stream.max_bytes` is an
  `Error::InvalidInput`.
- A subscription stream ends (`None`) when the bus object goes away. It gives no error
  items.

## Test

```sh
# The in-process bus, the configuration, and the error mapping. No server is necessary.
cargo test -p aegis-bus

# Also the tests against a real NATS server.
cargo test -p aegis-bus --features docker-tests
```

The `docker-tests` feature needs Docker. The tests start `nats:2.12-alpine` containers with
JetStream on random free ports of the local host. The container names start with
`aegis-test-bus-`. The tests remove the containers. A container also stops itself after 15
minutes.

- `AEGIS_TEST_NATS_URL`: the URL of an existing NATS server with JetStream. The tests that
  can share a server then use this server and start no container for it. Each test uses its
  own stream (`AEGIS_TEST_...`) and deletes it. The tests that restart the server, or that
  need special server settings (credentials, TLS), always start their own containers.
- `AEGIS_TEST_NATS_IMAGE`: a different NATS image.

If the feature is on and the tests find no Docker and no `AEGIS_TEST_NATS_URL`, they fail
with a message that tells you what to do.

The TLS tests and the credentials test make new keys and certificates for each run. The
repository has no key material.
