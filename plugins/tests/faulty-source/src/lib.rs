//! A source connector plugin that misbehaves on request.
//!
//! Only the tests of the plugin host use this plugin. It proves that the sandbox contains
//! a plugin that has a fault. It does nothing to a system outside the sandbox.
//!
//! The configuration value `mode` selects the behavior of `poll`:
//!
//! | Mode | Behavior |
//! | --- | --- |
//! | `loop` | Computes without end. |
//! | `sleep` | Sleeps for one hour. |
//! | `trap` | Panics. |
//! | `alloc` | Allocates memory without end. |
//! | `bad-json` | Returns text that is not JSON. |
//! | `wrong-shape` | Returns JSON that is not an event batch. |
//! | `spoof` | Returns an event that names a different connector. |
//! | `probe` | Tries to use the environment, the filesystem, and the network, and reports. |
//! | `log-flood` | Writes many log messages. |
//! | `http-flood` | Sends many HTTP requests to the URL in `flood_url`, and reports. |
//! | `big-output` | Returns text with the number of bytes in `output_bytes`. |
//! | `hold-timers` | Makes WASI timers without end and keeps them all. |
//! | `random` | Gets the number of random bytes in `random_bytes` in one WASI call, and reports. |
//! | `echo-cursor` | Returns one event that shows the cursor of the call, and no next cursor. |
//! | `many-events` | Returns the number of events in `event_count`. |
//!
//! With the mode `bad-info`, `info` returns text that is not JSON. With the mode
//! `odd-info`, `info` returns labels that are long or have control characters. `fetch`
//! returns the error that its cursor names.

/// The Rust form of the `source-connector` world in the `wit` directory.
mod bindings {
    wit_bindgen::generate!({
        path: "../../../wit",
        world: "source-connector",
    });
}

use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use bindings::aegis::plugin::host::{self, LogLevel, Request};
use bindings::aegis::plugin::types::Error;
use bindings::exports::aegis::plugin::source::Guest;
use serde_json::{Value, json};
use wasip2::clocks::monotonic_clock;
use wasip2::random::random;

const NAME: &str = "faulty-source";
/// The number of requests that the `http-flood` mode sends.
const FLOOD_REQUESTS: u32 = 1000;
/// One hour in nanoseconds.
const ONE_HOUR_NANOS: u64 = 3_600_000_000_000;

struct FaultySource;

impl Guest for FaultySource {
    fn info() -> String {
        match mode().as_str() {
            "bad-info" => return "This text is not JSON.".to_owned(),
            "odd-info" => {
                return json!({
                    "name": NAME,
                    "vendor": "v".repeat(5000),
                    "product": "faulty\nERROR forged line",
                    "version": "0.0.0",
                })
                .to_string();
            }
            _ => {}
        }
        json!({ "name": NAME, "vendor": "aegis", "product": "faulty", "version": "0.0.0" })
            .to_string()
    }

    fn check() -> Result<(), Error> {
        Ok(())
    }

    fn poll(cursor: Option<String>) -> Result<String, Error> {
        match mode().as_str() {
            "loop" => spin(),
            "sleep" => {
                std::thread::sleep(Duration::from_secs(3600));
                Ok(batch(Vec::new(), cursor))
            }
            "trap" => panic!("The faulty source panics on request."),
            "alloc" => exhaust_memory(),
            "bad-json" => Ok("{\"events\": [".to_owned()),
            "wrong-shape" => Ok(json!({ "events": [{ "id": 7 }] }).to_string()),
            "spoof" => Ok(batch(vec![event("entra-prod", json!({}))], cursor)),
            "probe" => Ok(batch(vec![event(NAME, probe())], cursor)),
            "log-flood" => {
                for index in 0..10_000 {
                    host::log(LogLevel::Info, &format!("Flood message {index}."));
                }
                Ok(batch(Vec::new(), cursor))
            }
            "http-flood" => Ok(batch(vec![event(NAME, flood_http())], cursor)),
            "big-output" => {
                let bytes = host::config_get("output_bytes")
                    .and_then(|text| text.parse().ok())
                    .unwrap_or_default();
                Ok("x".repeat(bytes))
            }
            "hold-timers" => hold_timers(),
            "many-events" => {
                let count: u32 = host::config_get("event_count")
                    .and_then(|text| text.parse().ok())
                    .unwrap_or_default();
                let events = (0..count)
                    .map(|index| event(NAME, json!({ "index": index })))
                    .collect();
                Ok(batch(events, cursor))
            }
            "echo-cursor" => Ok(batch(vec![event(NAME, json!({ "cursor": cursor }))], None)),
            "random" => {
                let bytes = host::config_get("random_bytes")
                    .and_then(|text| text.parse().ok())
                    .unwrap_or_default();
                let received = random::get_random_bytes(bytes).len();
                Ok(batch(
                    vec![event(NAME, json!({ "received": received }))],
                    cursor,
                ))
            }
            _ => Ok(batch(Vec::new(), cursor)),
        }
    }

    fn fetch(_start: String, _end: String, cursor: Option<String>) -> Result<String, Error> {
        let message = "The faulty source returns this error on request.".to_owned();
        match cursor.as_deref() {
            Some("invalid-input") => Err(Error::InvalidInput(message)),
            Some("not-found") => Err(Error::NotFound(message)),
            Some("unauthorized") => Err(Error::Unauthorized(message)),
            Some("unsupported") => Err(Error::Unsupported(message)),
            Some("unavailable") => Err(Error::Unavailable(message)),
            Some("rate-limited") => Err(Error::RateLimited(message)),
            Some("timeout") => Err(Error::Timeout(message)),
            Some("other") => Err(Error::Other(message)),
            _ => Ok(batch(Vec::new(), None)),
        }
    }
}

fn mode() -> String {
    host::config_get("mode").unwrap_or_default()
}

fn spin() -> ! {
    let mut counter: u64 = 0;
    loop {
        counter = std::hint::black_box(counter).wrapping_add(1);
    }
}

fn exhaust_memory() -> ! {
    const BLOCK_BYTES: usize = 1 << 20;
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    loop {
        blocks.push(vec![1; BLOCK_BYTES]);
        std::hint::black_box(&blocks);
    }
}

/// Sends many requests to one URL and reports how the host answered them.
fn flood_http() -> Value {
    let url = host::config_get("flood_url").unwrap_or_default();
    let (mut unauthorized, mut other, mut sent) = (0_u32, 0_u32, 0_u32);
    for _ in 0..FLOOD_REQUESTS {
        let request = Request {
            method: "GET".to_owned(),
            url: url.clone(),
            headers: Vec::new(),
            body: None,
        };
        match host::http_request(&request) {
            Ok(_) => sent += 1,
            Err(Error::Unauthorized(_)) => unauthorized += 1,
            Err(_) => other += 1,
        }
    }
    json!({ "sent": sent, "unauthorized": unauthorized, "other_errors": other })
}

/// Makes timers and keeps them. Each timer is a resource in the memory of the host.
fn hold_timers() -> ! {
    let mut timers = Vec::new();
    loop {
        timers.push(monotonic_clock::subscribe_duration(ONE_HOUR_NANOS));
        host::log(
            LogLevel::Info,
            &format!("The plugin holds {} timers.", timers.len()),
        );
    }
}

/// Tries each path out of the sandbox and reports which paths are open.
fn probe() -> Value {
    let address = host::config_get("probe_address").unwrap_or_default();
    json!({
        "env_count": std::env::vars_os().count(),
        "args_count": std::env::args_os().count(),
        "directory_listed": std::fs::read_dir("/").is_ok(),
        "file_read": std::fs::read("/etc/hosts").is_ok(),
        "file_written": std::fs::write("/tmp/aegis-faulty-source-probe", b"probe").is_ok(),
        "tcp_connected": TcpStream::connect(address.as_str()).is_ok(),
        "udp_bound": UdpSocket::bind("127.0.0.1:0").is_ok(),
        "name_resolved": ("localhost", 80).to_socket_addrs().is_ok(),
    })
}

fn batch(events: Vec<Value>, next_cursor: Option<String>) -> String {
    let mut batch = json!({ "events": events });
    if let Some(cursor) = next_cursor {
        batch["next_cursor"] = Value::String(cursor);
    }
    batch.to_string()
}

fn event(connector: &str, attributes: Value) -> Value {
    json!({
        "id": "018f0000-0000-7000-8000-0000000000aa",
        "time": "2026-01-02T03:00:00Z",
        "source": { "connector": connector, "vendor": "aegis", "product": "faulty" },
        "class": "other",
        "action": "sandbox.probe",
        "actor": { "kind": "other", "id": NAME },
        "attributes": attributes,
    })
}

bindings::export!(FaultySource with_types_in bindings);
