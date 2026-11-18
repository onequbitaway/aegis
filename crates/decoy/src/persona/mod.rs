//! The personas of a decoy: what the decoy answers to a request.
//!
//! The functions of this module only plan an answer. They do no input or output. The
//! connection code sends the planned answer and applies the time and size limits.

pub(crate) mod maze;
pub(crate) mod model_api;
pub(crate) mod tarpit;
pub(crate) mod words;

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::canary::{Canaries, CanaryHit, IssuedCanary};
use crate::config::{
    DecoyConfig, MODEL_API_ROOT, MazeConfig, ModelApiConfig, PersonaKind, TarpitConfig,
    path_is_within,
};
use crate::http::{self, RequestHead};
use crate::seed::Seed;

pub(crate) use model_api::KeyRing;

pub(crate) const HTML: &str = "text/html; charset=utf-8";
pub(crate) const JSON: &str = "application/json";
pub(crate) const TEXT: &str = "text/plain; charset=utf-8";
pub(crate) const EVENT_STREAM: &str = "text/event-stream";

/// One request, as the personas see it.
pub(crate) struct RequestView<'a> {
    /// The request line and the headers.
    pub(crate) head: &'a RequestHead,
    /// The path of the request target, without the query.
    pub(crate) path: &'a str,
    /// The query of the request target.
    pub(crate) query: &'a str,
    /// The request body.
    pub(crate) body: &'a [u8],
    /// The address of the client.
    pub(crate) client: IpAddr,
    /// The fingerprint of the client.
    pub(crate) fingerprint: &'a str,
}

/// A source of body pieces that the decoy makes on demand.
///
/// The decoy sends one piece at each interval. Thus a long body needs little memory.
pub(crate) trait PieceSource: Send {
    /// Returns the next piece, or `None` when the body is complete.
    fn next_piece(&mut self) -> Option<Vec<u8>>;
}

/// The body of a planned answer.
pub(crate) enum Body {
    /// One buffer that the decoy sends at one time, after `delay`.
    Full {
        /// The bytes of the body.
        bytes: Vec<u8>,
        /// The wait before the decoy sends the answer.
        delay: Duration,
    },
    /// One buffer that arrives in pieces: `piece_bytes` at each `interval`.
    ///
    /// The answer has a `Content-Length` header. At the hold limit, the decoy sends the
    /// remaining bytes at one time, so the body is always complete.
    Paced {
        /// The bytes of the body.
        bytes: Vec<u8>,
        /// The number of bytes in one piece.
        piece_bytes: usize,
        /// The time between two pieces.
        interval: Duration,
    },
    /// Pieces that the decoy makes on demand, one at each `interval`.
    ///
    /// When the decoy ends the body early, it sends `closing`. Thus the content is
    /// complete at each limit.
    Stream {
        /// The source of the pieces.
        source: Box<dyn PieceSource>,
        /// The bytes that complete the content at an early end.
        closing: Vec<u8>,
        /// The time between two pieces.
        interval: Duration,
    },
}

/// One planned answer.
pub(crate) struct Reply {
    /// The status code.
    pub(crate) status: u16,
    /// The value of the `Content-Type` header.
    pub(crate) content_type: &'static str,
    /// More headers. The decoy makes each value.
    pub(crate) headers: Vec<(&'static str, String)>,
    /// The body.
    pub(crate) body: Body,
}

impl Reply {
    /// Makes an answer that the decoy sends at one time.
    pub(crate) fn full(status: u16, content_type: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            headers: Vec::new(),
            body: Body::Full {
                bytes,
                delay: Duration::ZERO,
            },
        }
    }

    /// Makes a short text answer that names the status.
    pub(crate) fn plain(status: u16) -> Self {
        let text = format!("{status} {}\n", http::reason(status));
        Self::full(status, TEXT, text.into_bytes())
    }

    /// Makes a JSON answer.
    pub(crate) fn json(status: u16, value: &Value) -> Self {
        Self::full(status, JSON, value.to_string().into_bytes())
    }

    /// Adds one header.
    pub(crate) fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Sets the wait before the decoy sends an answer of the type [`Body::Full`].
    pub(crate) fn with_delay(mut self, wait: Duration) -> Self {
        if let Body::Full { delay, .. } = &mut self.body {
            *delay = wait;
        }
        self
    }
}

/// A signal that the decoy reports immediately, before the connection ends.
pub(crate) enum Signal {
    /// The request is a canary hit.
    CanaryHit(CanaryHit),
    /// The request used a planted decoy key.
    HoneytokenTrip {
        /// The identifier of the key.
        key_id: String,
        /// The clean text of the request body, for [`Event::raw`](aegis_contracts::Event).
        captured: Map<String, Value>,
    },
}

/// What the decoy does with one request.
pub(crate) struct Planned {
    /// The persona that handles the request.
    pub(crate) kind: Option<PersonaKind>,
    /// The answer.
    pub(crate) reply: Reply,
    /// The signal to report immediately.
    pub(crate) signal: Option<Signal>,
    /// The identifier of the canary that the answer carries.
    pub(crate) planted_canary: Option<String>,
}

impl Planned {
    fn of(kind: PersonaKind, reply: Reply) -> Self {
        Self {
            kind: Some(kind),
            reply,
            signal: None,
            planted_canary: None,
        }
    }
}

/// The personas of one decoy and the secrets that they use.
pub(crate) struct Personas {
    seed: Seed,
    canaries: Canaries,
    keys: KeyRing,
    tarpit: Option<TarpitConfig>,
    maze: Option<MazeConfig>,
    model_api: Option<ModelApiConfig>,
}

impl Personas {
    /// Makes the personas of a valid configuration.
    pub(crate) fn new(config: &DecoyConfig, seed: Seed, keys: KeyRing) -> Self {
        Self {
            seed,
            canaries: Canaries::new(&config.id, &config.canary),
            keys,
            tarpit: config
                .has_persona(PersonaKind::Tarpit)
                .then(|| config.tarpit.clone()),
            maze: config
                .has_persona(PersonaKind::Maze)
                .then(|| config.maze.clone()),
            model_api: config
                .has_persona(PersonaKind::ModelApi)
                .then(|| config.model_api.clone()),
        }
    }

    /// Plans the answer to one request.
    ///
    /// `remaining` is the time until the decoy must close the connection.
    ///
    /// The first rule that matches the path selects the answer:
    ///
    /// 1. A valid canary path is a canary hit.
    /// 2. A path below `/v1` goes to the model API.
    /// 3. A path below the page root or the API root goes to the maze.
    /// 4. Each other path goes to the tarpit.
    /// 5. With no tarpit, `/` sends the client to the maze, and each other path is 404.
    pub(crate) fn plan(&self, view: &RequestView<'_>, remaining: Duration) -> Planned {
        if let Some(hit) = self.canaries.verify(&self.seed, view.path) {
            return Planned {
                kind: Some(hit.planted_by),
                reply: Reply::full(200, TEXT, b"ok\n".to_vec()),
                signal: Some(Signal::CanaryHit(hit)),
                planted_canary: None,
            };
        }
        if let Some(config) = &self.model_api
            && path_is_within(view.path, MODEL_API_ROOT)
        {
            return model_api::plan(self, config, view, remaining);
        }
        if let Some(config) = &self.maze {
            if path_is_within(view.path, &config.page_root) {
                return maze::page(self, config, view);
            }
            if path_is_within(view.path, &config.api_root) {
                return maze::api(self, config, view);
            }
        }
        if let Some(config) = &self.tarpit {
            return tarpit::plan(self, config, view);
        }
        if let Some(config) = &self.maze
            && view.path == "/"
        {
            let reply = Reply::plain(302).with_header("Location", config.page_root.clone());
            return Planned::of(PersonaKind::Maze, reply);
        }
        Planned {
            kind: None,
            reply: Reply::plain(404),
            signal: None,
            planted_canary: None,
        }
    }

    /// Makes the canary that the persona `kind` puts into its answer to this client.
    fn canary(&self, kind: PersonaKind, view: &RequestView<'_>) -> Option<IssuedCanary> {
        self.canaries
            .issue(&self.seed, kind, view.client, view.fingerprint)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Helpers for the unit tests of the personas.

    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::config::DecoyKeyConfig;
    use crate::http::parse_head;

    pub(crate) const SECRET_A: &[u8] = b"seed-a-0123456789abcdef0123456789abcdef";
    pub(crate) const SECRET_B: &[u8] = b"seed-b-0123456789abcdef0123456789abcdef";
    pub(crate) const DECOY_KEY: &str = "decoy-key-0123456789abcdefABCDEF";
    pub(crate) const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef";

    pub(crate) fn config(personas: &[PersonaKind]) -> DecoyConfig {
        let mut config = DecoyConfig::new(
            "decoy-a",
            SocketAddr::from(([127, 0, 0, 1], 0)),
            personas.iter().copied(),
            "AEGIS_DECOY_SEED",
        );
        config.model_api.keys = vec![DecoyKeyConfig::new("ht-decoy-key", "AEGIS_DECOY_KEY")];
        config
    }

    pub(crate) fn personas_with(config: &DecoyConfig, secret: &[u8]) -> Personas {
        let keys = KeyRing::new(vec![("ht-decoy-key".to_owned(), DECOY_KEY.to_owned())]).unwrap();
        Personas::new(config, Seed::new(secret).unwrap(), keys)
    }

    pub(crate) fn personas(kinds: &[PersonaKind]) -> Personas {
        personas_with(&config(kinds), SECRET_A)
    }

    pub(crate) fn client(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    /// A request with its body, for a call of [`Personas::plan`].
    pub(crate) struct Request {
        pub(crate) head: RequestHead,
        pub(crate) body: Vec<u8>,
        pub(crate) client: IpAddr,
    }

    impl Request {
        pub(crate) fn new(method: &str, target: &str) -> Self {
            Self::with_headers(method, target, "", b"")
        }

        pub(crate) fn with_headers(method: &str, target: &str, headers: &str, body: &[u8]) -> Self {
            let text = format!("{method} {target} HTTP/1.1\r\nHost: decoy\r\n{headers}\r\n");
            let (head, _) = parse_head(text.as_bytes(), 32).unwrap();
            Self {
                head,
                body: body.to_vec(),
                client: client(1),
            }
        }

        pub(crate) fn from(mut self, last: u8) -> Self {
            self.client = client(last);
            self
        }

        pub(crate) fn view(&self) -> RequestView<'_> {
            RequestView {
                head: &self.head,
                path: self.head.path(),
                query: self.head.query(),
                body: &self.body,
                client: self.client,
                fingerprint: FINGERPRINT,
            }
        }
    }

    pub(crate) fn plan_for(personas: &Personas, request: &Request) -> Planned {
        personas.plan(&request.view(), Duration::from_secs(120))
    }

    /// Returns the bytes and the wait of an answer that the decoy sends at one time.
    pub(crate) fn full_body(reply: &Reply) -> (&[u8], Duration) {
        match &reply.body {
            Body::Full { bytes, delay } => (bytes, *delay),
            Body::Paced { .. } => panic!("the body is paced"),
            Body::Stream { .. } => panic!("the body is a stream"),
        }
    }

    pub(crate) fn full_text(reply: &Reply) -> &str {
        std::str::from_utf8(full_body(reply).0).unwrap()
    }

    pub(crate) fn header<'a>(reply: &'a Reply, name: &str) -> Option<&'a str> {
        reply
            .headers
            .iter()
            .find(|(found, _)| *found == name)
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    const ALL: &[PersonaKind] = &[
        PersonaKind::Tarpit,
        PersonaKind::Maze,
        PersonaKind::ModelApi,
    ];

    fn kind_of(personas: &Personas, method: &str, target: &str) -> Option<PersonaKind> {
        plan_for(personas, &Request::new(method, target)).kind
    }

    #[test]
    fn the_path_selects_the_persona() {
        let personas = personas(ALL);
        for (target, expected) in [
            ("/v1/models", PersonaKind::ModelApi),
            ("/v1", PersonaKind::ModelApi),
            ("/v1/chat/completions", PersonaKind::ModelApi),
            ("/docs", PersonaKind::Maze),
            ("/docs/runbooks/x", PersonaKind::Maze),
            ("/api", PersonaKind::Maze),
            ("/api/accounts?cursor=0", PersonaKind::Maze),
            ("/", PersonaKind::Tarpit),
            ("/admin", PersonaKind::Tarpit),
            ("/v10", PersonaKind::Tarpit),
            ("/docs-old", PersonaKind::Tarpit),
            ("/ref/not-a-canary", PersonaKind::Tarpit),
            ("*", PersonaKind::Tarpit),
        ] {
            assert_eq!(
                kind_of(&personas, "GET", target),
                Some(expected),
                "{target}"
            );
        }
    }

    #[test]
    fn a_persona_that_is_off_does_not_answer() {
        let only_tarpit = personas(&[PersonaKind::Tarpit]);
        for target in ["/v1/models", "/docs", "/api/accounts", "/"] {
            assert_eq!(
                kind_of(&only_tarpit, "GET", target),
                Some(PersonaKind::Tarpit),
                "{target}"
            );
        }
        let only_model = personas(&[PersonaKind::ModelApi]);
        for target in ["/", "/docs", "/api", "/admin"] {
            let planned = plan_for(&only_model, &Request::new("GET", target));
            assert_eq!(planned.kind, None, "{target}");
            assert_eq!(planned.reply.status, 404, "{target}");
            assert_eq!(full_text(&planned.reply), "404 Not Found\n");
            assert!(planned.signal.is_none());
            assert_eq!(planned.planted_canary, None);
        }
    }

    #[test]
    fn with_no_tarpit_the_root_sends_the_client_to_the_maze() {
        let only_maze = personas(&[PersonaKind::Maze]);
        let planned = plan_for(&only_maze, &Request::new("GET", "/"));
        assert_eq!(planned.kind, Some(PersonaKind::Maze));
        assert_eq!(planned.reply.status, 302);
        assert_eq!(header(&planned.reply, "Location"), Some("/docs"));
        assert_eq!(full_text(&planned.reply), "302 Found\n");
        let missing = plan_for(&only_maze, &Request::new("GET", "/admin"));
        assert_eq!(missing.kind, None);
        assert_eq!(missing.reply.status, 404);
    }

    #[test]
    fn a_canary_path_is_a_hit_before_each_persona() {
        let personas = personas(ALL);
        let request = Request::new("GET", "/docs/a");
        let issued = personas.canary(PersonaKind::Maze, &request.view()).unwrap();
        let planned = plan_for(&personas, &Request::new("GET", &issued.path).from(77));
        assert_eq!(planned.kind, Some(PersonaKind::Maze));
        assert_eq!(planned.reply.status, 200);
        assert_eq!(
            full_body(&planned.reply),
            (b"ok\n".as_slice(), Duration::ZERO)
        );
        assert_eq!(planned.planted_canary, None);
        match planned.signal {
            Some(Signal::CanaryHit(hit)) => {
                assert_eq!(hit.id, issued.id);
                assert_eq!(hit.planted_by, PersonaKind::Maze);
            }
            _ => panic!("expected a canary hit"),
        }
        // A query does not change the hit.
        let with_query = format!("{}?x=1", issued.path);
        assert!(matches!(
            plan_for(&personas, &Request::new("GET", &with_query)).signal,
            Some(Signal::CanaryHit(_))
        ));
    }

    #[test]
    fn a_plain_answer_names_the_status() {
        let reply = Reply::plain(431).with_delay(Duration::from_secs(1));
        assert_eq!(reply.status, 431);
        assert_eq!(reply.content_type, TEXT);
        assert_eq!(
            full_body(&reply),
            (
                b"431 Request Header Fields Too Large\n".as_slice(),
                Duration::from_secs(1)
            )
        );
        let json = Reply::json(200, &serde_json::json!({"a": 1}));
        assert_eq!(json.content_type, JSON);
        assert_eq!(full_text(&json), r#"{"a":1}"#);
    }
}
