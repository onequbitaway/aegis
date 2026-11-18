//! The model API persona: an OpenAI-compatible decoy.
//!
//! The decoy accepts only API keys that the operator planted as honeytokens. Each other
//! key gets the status 401. A planted key gets a slow filler answer. The decoy records
//! the prompt up to a limit. It never calls a real model: the answer is generated text
//! from a fixed word list.

use std::fmt;
use std::time::Duration;

use aegis_contracts::{Error, Result};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{ModelApiConfig, PersonaKind, REPLY_BUFFER_BYTES, is_model_name};
use crate::http::RequestHead;
use crate::persona::words::Filler;
use crate::persona::{
    Body, EVENT_STREAM, JSON, Personas, PieceSource, Planned, Reply, RequestView, Signal,
};
use crate::seed::Generator;
use crate::text;

/// The path of the model list.
const MODELS_PATH: &str = "/v1/models";
/// The path of the chat completions.
const CHAT_PATH: &str = "/v1/chat/completions";
/// The creation time that the model list shows for each model.
const MODEL_CREATED: i64 = 1_700_000_000;
/// The largest number of messages of one request that the decoy reads for the prompt.
const MAX_MESSAGES: usize = 64;
/// The largest number of characters of a model name or a role that the decoy records.
const MAX_NAME_CHARACTERS: usize = 64;
/// The end of a stream of server-sent events.
const STREAM_DONE: &str = "data: [DONE]\n\n";
/// The largest number of bytes in the text of one complete answer.
const MAX_ANSWER_BYTES: usize = REPLY_BUFFER_BYTES / 2;
/// The smallest and the largest number of characters in a decoy key.
const KEY_LENGTH: std::ops::RangeInclusive<usize> = 16..=512;

/// One planted decoy key. The decoy keeps only the SHA-256 digest of the key.
struct PlantedKey {
    id: String,
    digest: [u8; 32],
}

/// The planted decoy keys of one decoy. The `Debug` output shows only the identifiers.
#[derive(Default)]
pub(crate) struct KeyRing {
    keys: Vec<PlantedKey>,
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.keys.iter().map(|key| key.id.as_str()))
            .finish()
    }
}

impl KeyRing {
    /// Makes the key ring from pairs of an identifier and a key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a key does not have 16 to 512 visible ASCII
    /// characters, or if two identifiers have the same key. The message names the
    /// identifier and never shows a key.
    pub(crate) fn new(keys: Vec<(String, String)>) -> Result<Self> {
        let mut ring = Self::default();
        for (id, value) in keys {
            let is_valid = KEY_LENGTH.contains(&value.len())
                && value.bytes().all(|byte| byte.is_ascii_graphic());
            if !is_valid {
                return Err(Error::Config(format!(
                    "the decoy key {id} must have {} to {} visible ASCII characters",
                    KEY_LENGTH.start(),
                    KEY_LENGTH.end()
                )));
            }
            let digest: [u8; 32] = Sha256::digest(value.as_bytes()).into();
            if let Some(known) = ring.keys.iter().find(|known| known.digest == digest) {
                return Err(Error::Config(format!(
                    "the decoy keys {} and {id} have the same value",
                    known.id
                )));
            }
            ring.keys.push(PlantedKey { id, digest });
        }
        Ok(ring)
    }

    /// Returns the identifier of the planted key that is equal to `presented`.
    ///
    /// The function compares digests, and it examines each planted key. Thus the time
    /// does not show which key is near to `presented`.
    pub(crate) fn find(&self, presented: &[u8]) -> Option<&str> {
        let digest: [u8; 32] = Sha256::digest(presented).into();
        let mut found = None;
        for key in &self.keys {
            if bool::from(key.digest.ct_eq(&digest)) {
                found = Some(key.id.as_str());
            }
        }
        found
    }
}

/// Returns the API key of a request.
///
/// The key is the token of `Authorization: Bearer`, or the value of `x-api-key` or
/// `api-key`.
fn presented_key(head: &RequestHead) -> Option<&[u8]> {
    if let Some(value) = head.header("authorization") {
        let mut parts = value.trim_ascii().splitn(2, |byte| *byte == b' ');
        let scheme = parts.next()?;
        let token = parts.next()?.trim_ascii();
        return (scheme.eq_ignore_ascii_case(b"bearer") && !token.is_empty()).then_some(token);
    }
    head.header("x-api-key")
        .or_else(|| head.header("api-key"))
        .map(<[u8]>::trim_ascii)
        .filter(|key| !key.is_empty())
}

/// Makes an error answer in the format of the API.
fn error(status: u16, message: &str, code: Option<&str>) -> Reply {
    Reply::json(
        status,
        &json!({
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "param": null,
                "code": code,
            }
        }),
    )
}

/// Plans the answer to a request below `/v1`.
///
/// `remaining` is the time until the decoy must close the connection.
pub(crate) fn plan(
    personas: &Personas,
    config: &ModelApiConfig,
    view: &RequestView<'_>,
    remaining: Duration,
) -> Planned {
    let presented = presented_key(view.head);
    let Some(key_id) = presented.and_then(|key| personas.keys.find(key)) else {
        let message = if presented.is_some() {
            "Incorrect API key provided."
        } else {
            "You did not provide an API key."
        };
        let reply =
            error(401, message, Some("invalid_api_key")).with_header("WWW-Authenticate", "Bearer");
        return Planned::of(PersonaKind::ModelApi, reply);
    };
    let mut captured = Map::new();
    let mut planted_canary = None;
    let reply = match (view.head.method.as_str(), view.path) {
        ("GET" | "HEAD", MODELS_PATH) => models(config),
        ("POST", CHAT_PATH) => {
            let canary = personas.canary(PersonaKind::ModelApi, view);
            let lead = canary.as_ref().map(|canary| canary.instruction.clone());
            planted_canary = canary.map(|canary| canary.id);
            let reply = chat(personas, config, view, remaining, lead, &mut captured);
            if reply.status != 200 {
                // An error answer carries no instruction.
                planted_canary = None;
            }
            reply
        }
        (_, MODELS_PATH) => {
            error(405, "This method is not allowed for this URL.", None).with_header("Allow", "GET")
        }
        (_, CHAT_PATH) => error(405, "This method is not allowed for this URL.", None)
            .with_header("Allow", "POST"),
        _ => error(404, "The requested resource does not exist.", None),
    };
    Planned {
        kind: Some(PersonaKind::ModelApi),
        reply,
        signal: Some(Signal::HoneytokenTrip {
            key_id: key_id.to_owned(),
            captured,
        }),
        planted_canary,
    }
}

/// Makes the list of the configured model names.
fn models(config: &ModelApiConfig) -> Reply {
    let data: Vec<Value> = config
        .models
        .iter()
        .map(|model| {
            json!({
                "id": model,
                "object": "model",
                "created": MODEL_CREATED,
                "owned_by": "organization",
            })
        })
        .collect();
    Reply::json(200, &json!({"object": "list", "data": data}))
}

/// Returns the text of one message content: a string, or the text parts of an array.
fn content_text(content: &Value, limit: usize, text: &mut String) {
    match content {
        Value::String(found) => push_limited(text, found, limit),
        Value::Array(parts) => {
            for part in parts {
                if let Some(found) = part.get("text").and_then(Value::as_str) {
                    push_limited(text, found, limit);
                    push_limited(text, " ", limit);
                }
            }
        }
        _ => {}
    }
}

/// Adds `more` to `text`, but stops when `text` has `limit` bytes.
fn push_limited(text: &mut String, more: &str, limit: usize) {
    let space = limit.saturating_sub(text.len());
    if more.len() <= space {
        text.push_str(more);
        return;
    }
    let mut end = space;
    while end > 0 && !more.is_char_boundary(end) {
        end -= 1;
    }
    text.push_str(more.get(..end).unwrap_or_default());
}

/// Returns the prompt of a request as one clean text with `max_characters` at most.
///
/// Each message becomes `role: content`. The second value is `true` if the limit
/// removed text.
fn prompt_text(messages: &[Value], max_characters: usize) -> (String, bool) {
    // One character has four bytes at most. More raw text cannot add to the result.
    let raw_limit = max_characters.saturating_mul(4).saturating_add(64);
    let mut raw = String::new();
    let mut cut = messages.len() > MAX_MESSAGES;
    for message in messages.iter().take(MAX_MESSAGES) {
        if raw.len() >= raw_limit {
            cut = true;
            break;
        }
        if !raw.is_empty() {
            push_limited(&mut raw, "\n", raw_limit);
        }
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        push_limited(
            &mut raw,
            &text::clean(role, MAX_NAME_CHARACTERS).text,
            raw_limit,
        );
        push_limited(&mut raw, ": ", raw_limit);
        if let Some(content) = message.get("content") {
            content_text(content, raw_limit, &mut raw);
        }
    }
    let cleaned = text::clean(&raw, max_characters);
    (cleaned.text, cleaned.truncated || cut)
}

/// Plans the answer to a chat completion request and records the prompt in `captured`.
fn chat(
    personas: &Personas,
    config: &ModelApiConfig,
    view: &RequestView<'_>,
    remaining: Duration,
    lead: Option<String>,
    captured: &mut Map<String, Value>,
) -> Reply {
    let Ok(body) = serde_json::from_slice::<Value>(view.body) else {
        let cleaned = text::clean_bytes(view.body, config.max_prompt_chars);
        captured.insert("body_text".to_owned(), json!(cleaned.text));
        captured.insert("body_text_truncated".to_owned(), json!(cleaned.truncated));
        return error(400, "The request body is not valid JSON.", None);
    };
    let requested_model = body.get("model").and_then(Value::as_str);
    if let Some(model) = requested_model {
        captured.insert(
            "model".to_owned(),
            json!(text::clean(model, MAX_NAME_CHARACTERS).text),
        );
    }
    let Some(messages) = body
        .get("messages")
        .and_then(Value::as_array)
        .filter(|messages| !messages.is_empty())
    else {
        return error(400, "The request needs the property 'messages'.", None);
    };
    let (prompt, truncated) = prompt_text(messages, config.max_prompt_chars);
    let prompt_characters = prompt.chars().count();
    captured.insert("prompt".to_owned(), json!(prompt));
    captured.insert("prompt_truncated".to_owned(), json!(truncated));
    captured.insert("message_count".to_owned(), json!(messages.len()));
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    captured.insert("stream".to_owned(), json!(stream));

    // The answer shows a model name of the request only if the name is clean.
    let model = requested_model
        .filter(|model| is_model_name(model))
        .or_else(|| config.models.first().map(String::as_str))
        .unwrap_or("assistant")
        .to_owned();
    let digest = Sha256::digest(view.body);
    let mut generator = personas
        .seed
        .generator("model-answer", &[digest.as_slice(), model.as_bytes()]);
    let answer = Answer {
        id: format!("chatcmpl-{}", generator.hex(24)),
        created: chrono::Utc::now().timestamp(),
        model,
    };
    if stream {
        let closing = format!("{}{STREAM_DONE}", answer.event(&json!({}), Some("length")));
        let source = ChatStream {
            answer,
            lead,
            filler: Filler::new(generator),
            words_sent: 0,
            words: config.answer_words,
            state: StreamState::Role,
        };
        return Reply {
            status: 200,
            content_type: EVENT_STREAM,
            headers: Vec::new(),
            body: Body::Stream {
                source: Box::new(source),
                closing: closing.into_bytes(),
                interval: config.interval,
            },
        };
    }
    let content = answer_text(generator, lead.as_deref(), config.answer_words);
    let bytes = answer
        .complete(&content, prompt_characters, config.answer_words)
        .to_string()
        .into_bytes();
    let piece_bytes = piece_size(bytes.len(), config.answer_words, config.interval, remaining);
    Reply {
        status: 200,
        content_type: JSON,
        headers: Vec::new(),
        body: Body::Paced {
            bytes,
            piece_bytes,
            interval: config.interval,
        },
    }
}

/// Returns the number of bytes in one piece of a paced body.
///
/// The body arrives in `wanted_pieces` pieces if the time permits. With less time, the
/// pieces are larger, so the body is complete one interval before the hold limit.
fn piece_size(
    length: usize,
    wanted_pieces: usize,
    interval: Duration,
    remaining: Duration,
) -> usize {
    let ticks = remaining.as_millis() / interval.as_millis().max(1);
    let available = usize::try_from(ticks.saturating_sub(1)).unwrap_or(usize::MAX);
    let pieces = wanted_pieces.min(available).max(1);
    length.div_ceil(pieces).max(1)
}

/// Makes the text of a complete answer: the canary instruction and then filler words.
fn answer_text(generator: Generator, lead: Option<&str>, words: usize) -> String {
    let mut filler = Filler::new(generator);
    let mut content = String::new();
    if let Some(lead) = lead {
        content.push_str(lead);
        content.push_str("\n\n");
    }
    for index in 0..words {
        let word = filler.next_word();
        if content.len() + word.len() + 1 > MAX_ANSWER_BYTES {
            break;
        }
        if index > 0 {
            content.push(' ');
        }
        content.push_str(&word);
    }
    content
}

/// The values that all parts of one answer share.
struct Answer {
    id: String,
    created: i64,
    model: String,
}

impl Answer {
    /// Makes one server-sent event of a streamed answer.
    fn event(&self, delta: &Value, finish_reason: Option<&str>) -> String {
        let chunk = json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        });
        format!("data: {chunk}\n\n")
    }

    /// Makes the JSON of an answer that is not streamed.
    fn complete(&self, content: &str, prompt_characters: usize, words: usize) -> Value {
        // The token counts are estimates, as a client expects them.
        let prompt_tokens = prompt_characters / 4 + 1;
        json!({
            "id": self.id,
            "object": "chat.completion",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": words,
                "total_tokens": prompt_tokens + words,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// The next event names the role.
    Role,
    /// The next event carries the canary instruction, if there is one.
    Lead,
    /// The next event carries one filler word.
    Words,
    /// The stream is complete.
    Done,
}

/// Makes the server-sent events of a streamed answer, one event for each call.
///
/// The source makes each word on demand. Thus a long answer needs little memory.
struct ChatStream {
    answer: Answer,
    lead: Option<String>,
    filler: Filler,
    words_sent: usize,
    words: usize,
    state: StreamState,
}

impl PieceSource for ChatStream {
    fn next_piece(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.state {
                StreamState::Role => {
                    self.state = StreamState::Lead;
                    let delta = json!({"role": "assistant", "content": ""});
                    return Some(self.answer.event(&delta, None).into_bytes());
                }
                StreamState::Lead => {
                    self.state = StreamState::Words;
                    if let Some(lead) = self.lead.take() {
                        let delta = json!({"content": format!("{lead}\n\n")});
                        return Some(self.answer.event(&delta, None).into_bytes());
                    }
                }
                StreamState::Words if self.words_sent < self.words => {
                    let word = self.filler.next_word();
                    let content = if self.words_sent == 0 {
                        word
                    } else {
                        format!(" {word}")
                    };
                    self.words_sent += 1;
                    let delta = json!({"content": content});
                    return Some(self.answer.event(&delta, None).into_bytes());
                }
                StreamState::Words => {
                    self.state = StreamState::Done;
                    let last = self.answer.event(&json!({}), Some("stop"));
                    return Some(format!("{last}{STREAM_DONE}").into_bytes());
                }
                StreamState::Done => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::CANARY_INSTRUCTION_PREFIX;
    use crate::persona::testing::*;

    const MODEL: &[PersonaKind] = &[PersonaKind::ModelApi];
    const BODY: &str = r#"{"model":"assistant-large","messages":[{"role":"system","content":"You are a helper."},{"role":"user","content":"List the files."}]}"#;

    fn authorized(method: &str, target: &str, body: &str) -> Request {
        let headers = format!(
            "Authorization: Bearer {DECOY_KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        Request::with_headers(method, target, &headers, body.as_bytes())
    }

    fn chat_request(body: &str) -> Request {
        authorized("POST", CHAT_PATH, body)
    }

    fn trip(planned: &Planned) -> (&str, &Map<String, Value>) {
        match &planned.signal {
            Some(Signal::HoneytokenTrip { key_id, captured }) => (key_id.as_str(), captured),
            _ => panic!("expected a honeytoken trip"),
        }
    }

    fn json_body(reply: &Reply) -> Value {
        serde_json::from_str(full_text(reply)).unwrap()
    }

    /// Returns all pieces of a streamed answer and its closing bytes.
    fn stream_pieces(planned: &mut Planned) -> (Vec<String>, String, Duration) {
        let Body::Stream {
            source,
            closing,
            interval,
        } = &mut planned.reply.body
        else {
            panic!("the body is not a stream");
        };
        let mut pieces = Vec::new();
        while let Some(piece) = source.next_piece() {
            pieces.push(String::from_utf8(piece).unwrap());
            assert!(pieces.len() < 10_000, "the stream has no end");
        }
        (
            pieces,
            String::from_utf8(closing.clone()).unwrap(),
            *interval,
        )
    }

    /// Reads the JSON of each server-sent event of `text`. `[DONE]` gives no value.
    fn events(text: &str) -> Vec<Value> {
        text.split("\n\n")
            .filter(|event| !event.is_empty())
            .filter_map(|event| {
                let data = event
                    .strip_prefix("data: ")
                    .expect("an event has a data line");
                (data != "[DONE]").then(|| serde_json::from_str(data).unwrap())
            })
            .collect()
    }

    fn paced(reply: &Reply) -> (Value, usize, Duration) {
        match &reply.body {
            Body::Paced {
                bytes,
                piece_bytes,
                interval,
            } => (
                serde_json::from_slice(bytes).unwrap(),
                *piece_bytes,
                *interval,
            ),
            _ => panic!("the body is not paced"),
        }
    }

    #[test]
    fn a_key_must_have_16_to_512_visible_ascii_characters() {
        let ring = |value: &str| KeyRing::new(vec![("ht-1".to_owned(), value.to_owned())]);
        assert!(ring(&"k".repeat(16)).is_ok());
        assert!(ring(&"k".repeat(512)).is_ok());
        for value in [
            "k".repeat(15),
            "k".repeat(513),
            format!("{} space", "k".repeat(16)),
            format!("{}\n", "k".repeat(16)),
            format!("{}é", "k".repeat(16)),
            String::new(),
        ] {
            let error = ring(&value).unwrap_err();
            assert!(
                matches!(&error, Error::Config(message)
                    if message == "the decoy key ht-1 must have 16 to 512 visible ASCII characters"),
                "{error:?}"
            );
        }
    }

    #[test]
    fn two_identifiers_cannot_have_the_same_key() {
        let error = KeyRing::new(vec![
            ("ht-1".to_owned(), DECOY_KEY.to_owned()),
            ("ht-2".to_owned(), DECOY_KEY.to_owned()),
        ])
        .unwrap_err();
        assert!(
            matches!(&error, Error::Config(message)
                if message == "the decoy keys ht-1 and ht-2 have the same value"),
            "{error:?}"
        );
        assert!(!error.to_string().contains(DECOY_KEY));
    }

    #[test]
    fn the_key_ring_finds_only_an_exact_key_and_never_shows_a_key() {
        let other = "other-key-0123456789abcdefABCDEF";
        let ring = KeyRing::new(vec![
            ("ht-1".to_owned(), DECOY_KEY.to_owned()),
            ("ht-2".to_owned(), other.to_owned()),
        ])
        .unwrap();
        assert_eq!(ring.find(DECOY_KEY.as_bytes()), Some("ht-1"));
        assert_eq!(ring.find(other.as_bytes()), Some("ht-2"));
        assert_eq!(
            ring.find(&DECOY_KEY.as_bytes()[..DECOY_KEY.len() - 1]),
            None
        );
        assert_eq!(ring.find(format!("{DECOY_KEY}x").as_bytes()), None);
        assert_eq!(ring.find(DECOY_KEY.to_lowercase().as_bytes()), None);
        assert_eq!(ring.find(b""), None);
        assert_eq!(KeyRing::default().find(DECOY_KEY.as_bytes()), None);
        assert_eq!(format!("{ring:?}"), r#"["ht-1", "ht-2"]"#);
    }

    #[test]
    fn the_key_comes_from_the_bearer_token_or_an_api_key_header() {
        let key = |headers: &str| {
            let request = Request::with_headers("GET", MODELS_PATH, headers, b"");
            presented_key(&request.head).map(<[u8]>::to_vec)
        };
        let expected = Some(b"abc".to_vec());
        assert_eq!(key("Authorization: Bearer abc\r\n"), expected);
        assert_eq!(key("authorization: bearer   abc  \r\n"), expected);
        assert_eq!(key("x-api-key: abc\r\n"), expected);
        assert_eq!(key("Api-Key: abc\r\n"), expected);
        assert_eq!(key(""), None);
        assert_eq!(key("Authorization: Basic abc\r\n"), None);
        assert_eq!(key("Authorization: Bearer\r\n"), None);
        assert_eq!(key("Authorization: Bearer \r\n"), None);
        assert_eq!(key("Authorization: abc\r\n"), None);
        assert_eq!(key("Authorization: Bearerabc\r\n"), None);
        assert_eq!(key("x-api-key: \r\n"), None);
        // The Authorization header wins, and a wrong scheme does not fall back.
        assert_eq!(key("Authorization: Basic x\r\nx-api-key: abc\r\n"), None);
    }

    #[test]
    fn an_unknown_key_or_no_key_gets_401_and_no_trip() {
        let personas = personas(MODEL);
        for (headers, message) in [
            ("", "You did not provide an API key."),
            (
                "Authorization: Bearer wrong-key-0123456789abcdef\r\n",
                "Incorrect API key provided.",
            ),
        ] {
            for (method, target) in [("GET", MODELS_PATH), ("POST", CHAT_PATH), ("GET", "/v1/x")] {
                let request = Request::with_headers(method, target, headers, BODY.as_bytes());
                let planned = plan_for(&personas, &request);
                assert_eq!(planned.kind, Some(PersonaKind::ModelApi));
                assert_eq!(planned.reply.status, 401);
                assert!(planned.signal.is_none());
                assert_eq!(planned.planted_canary, None);
                assert_eq!(header(&planned.reply, "WWW-Authenticate"), Some("Bearer"));
                assert_eq!(
                    json_body(&planned.reply),
                    json!({"error": {
                        "message": message,
                        "type": "invalid_request_error",
                        "param": null,
                        "code": "invalid_api_key",
                    }})
                );
                assert_eq!(full_body(&planned.reply).1, Duration::ZERO);
            }
        }
    }

    #[test]
    fn a_planted_key_gets_the_model_list_and_a_trip() {
        let personas = personas(MODEL);
        let planned = plan_for(&personas, &authorized("GET", MODELS_PATH, ""));
        assert_eq!(planned.reply.status, 200);
        assert_eq!(
            json_body(&planned.reply),
            json!({"object": "list", "data": [
                {"id": "assistant-large", "object": "model", "created": 1_700_000_000, "owned_by": "organization"},
                {"id": "assistant-small", "object": "model", "created": 1_700_000_000, "owned_by": "organization"},
            ]})
        );
        let (key_id, captured) = trip(&planned);
        assert_eq!(key_id, "ht-decoy-key");
        assert!(captured.is_empty());
        assert_eq!(planned.planted_canary, None);
    }

    #[test]
    fn a_planted_key_on_an_unknown_path_or_a_wrong_method_is_still_a_trip() {
        let personas = personas(MODEL);
        for (method, target, status, allow) in [
            ("GET", "/v1/embeddings", 404, None),
            ("GET", "/v1", 404, None),
            ("GET", CHAT_PATH, 405, Some("POST")),
            ("POST", MODELS_PATH, 405, Some("GET")),
        ] {
            let planned = plan_for(&personas, &authorized(method, target, ""));
            assert_eq!(planned.reply.status, status, "{method} {target}");
            assert_eq!(header(&planned.reply, "Allow"), allow);
            assert_eq!(trip(&planned).0, "ht-decoy-key");
            assert_eq!(
                json_body(&planned.reply)["error"]["type"],
                "invalid_request_error"
            );
        }
    }

    #[test]
    fn a_chat_request_records_the_prompt_and_the_model() {
        let personas = personas(MODEL);
        let planned = plan_for(&personas, &chat_request(BODY));
        assert_eq!(planned.reply.status, 200);
        let (key_id, captured) = trip(&planned);
        assert_eq!(key_id, "ht-decoy-key");
        assert_eq!(
            Value::Object(captured.clone()),
            json!({
                "model": "assistant-large",
                "prompt": "system: You are a helper. user: List the files.",
                "prompt_truncated": false,
                "message_count": 2,
                "stream": false,
            })
        );
    }

    #[test]
    fn the_prompt_stops_at_the_limit_and_has_no_control_characters() {
        let messages = |content: &str| vec![json!({"role": "user", "content": content})];
        assert_eq!(
            prompt_text(&messages("abcdefghij"), 10),
            ("user: abcd".to_owned(), true)
        );
        assert_eq!(
            prompt_text(&messages("abcd"), 10),
            ("user: abcd".to_owned(), false)
        );
        assert_eq!(
            prompt_text(&messages("a\u{0}b\u{1b}[2J\r\nc\u{202E}d\u{E0041}"), 100),
            ("user: ab[2J cd".to_owned(), false)
        );
        assert_eq!(prompt_text(&messages("abc"), 0), (String::new(), true));
        // A very long prompt is cut before the clean step reads all of it.
        let long = "x".repeat(200_000);
        let (text, truncated) = prompt_text(&messages(&long), 50);
        assert_eq!(text.chars().count(), 50);
        assert!(truncated);
        let wide = "é".repeat(1000);
        let (text, truncated) = prompt_text(&messages(&wide), 20);
        assert_eq!(text, format!("user: {}", "é".repeat(14)));
        assert!(truncated);
    }

    #[test]
    fn the_prompt_reads_text_parts_and_ignores_other_content() {
        let messages = vec![
            json!({"role": "user", "content": [
                {"type": "text", "text": "first"},
                {"type": "image_url", "image_url": {"url": "http://192.0.2.1/x"}},
                {"type": "text", "text": "second"},
            ]}),
            json!({"content": "no role"}),
            json!({"role": "tool", "content": 42}),
            json!("not an object"),
            json!({"role": "a\nb", "content": null}),
        ];
        assert_eq!(
            prompt_text(&messages, 1000),
            (
                "user: first second unknown: no role tool: unknown: a b:".to_owned(),
                false
            )
        );
        let many: Vec<Value> = (0..MAX_MESSAGES + 1)
            .map(|_| json!({"role": "u", "content": "x"}))
            .collect();
        let (text, truncated) = prompt_text(&many, 100_000);
        assert_eq!(text.matches("u: x").count(), MAX_MESSAGES);
        assert!(truncated);
    }

    #[test]
    fn the_configured_limit_cuts_the_recorded_prompt() {
        let mut config = config(MODEL);
        config.model_api.max_prompt_chars = 12;
        let personas = personas_with(&config, SECRET_A);
        let planned = plan_for(&personas, &chat_request(BODY));
        let (_, captured) = trip(&planned);
        assert_eq!(captured["prompt"], "system: You");
        assert_eq!(captured["prompt_truncated"], true);
    }

    #[test]
    fn a_body_that_is_not_a_chat_request_gets_400_and_the_text_is_recorded() {
        let personas = personas(MODEL);
        let planned = plan_for(&personas, &chat_request("not json\u{7} at all"));
        assert_eq!(planned.reply.status, 400);
        assert_eq!(planned.planted_canary, None);
        assert_eq!(
            json_body(&planned.reply)["error"]["message"],
            "The request body is not valid JSON."
        );
        let (key_id, captured) = trip(&planned);
        assert_eq!(key_id, "ht-decoy-key");
        assert_eq!(
            Value::Object(captured.clone()),
            json!({"body_text": "not json at all", "body_text_truncated": false})
        );

        for body in [
            r#"{"model":"m"}"#,
            r#"{"model":"m","messages":[]}"#,
            r#"{"messages":"x"}"#,
            "[]",
        ] {
            let planned = plan_for(&personas, &chat_request(body));
            assert_eq!(planned.reply.status, 400, "{body}");
            assert_eq!(
                json_body(&planned.reply)["error"]["message"],
                "The request needs the property 'messages'."
            );
            assert!(!trip(&planned).1.contains_key("prompt"));
        }
    }

    #[test]
    fn a_deeply_nested_body_is_an_error_and_not_a_crash() {
        let personas = personas(MODEL);
        let body = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
        let planned = plan_for(&personas, &chat_request(&body));
        assert_eq!(planned.reply.status, 400);
    }

    #[test]
    fn a_complete_answer_is_a_paced_chat_completion_with_filler_text() {
        let mut config = config(MODEL);
        config.model_api.answer_words = 40;
        config.model_api.interval = Duration::from_millis(200);
        config.canary.enabled = false;
        let personas = personas_with(&config, SECRET_A);
        let planned = plan_for(&personas, &chat_request(BODY));
        assert_eq!(planned.reply.content_type, JSON);
        assert_eq!(planned.planted_canary, None);
        let (answer, piece_bytes, interval) = paced(&planned.reply);
        assert_eq!(interval, Duration::from_millis(200));
        assert_eq!(answer["object"], "chat.completion");
        assert_eq!(answer["model"], "assistant-large");
        let id = answer["id"].as_str().unwrap();
        assert!(id.starts_with("chatcmpl-") && id.len() == 33, "{id}");
        let choices = answer["choices"].as_array().unwrap();
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0]["finish_reason"], "stop");
        assert_eq!(choices[0]["message"]["role"], "assistant");
        let content = choices[0]["message"]["content"].as_str().unwrap();
        assert_eq!(content.split(' ').count(), 40);
        assert!(!content.contains("Automated agents"));
        assert!(
            content
                .chars()
                .all(|c| c.is_ascii_alphabetic() || matches!(c, ' ' | '.')),
            "{content}"
        );
        assert_eq!(
            answer["usage"],
            json!({"prompt_tokens": 12, "completion_tokens": 40, "total_tokens": 52})
        );
        // 40 pieces in 120 seconds: each piece is one fortieth of the body.
        let length = answer.to_string().len();
        assert_eq!(piece_bytes, length.div_ceil(40));
    }

    #[test]
    fn the_answer_is_the_same_for_one_seed_and_one_request() {
        let content = |secret: &[u8], body: &str| {
            let personas = personas_with(&config(MODEL), secret);
            let planned = plan_for(&personas, &chat_request(body));
            let (answer, _, _) = paced(&planned.reply);
            (
                answer["id"].as_str().unwrap().to_owned(),
                answer["choices"][0]["message"]["content"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };
        let other_body = BODY.replace("List the files.", "List the users.");
        assert_eq!(content(SECRET_A, BODY), content(SECRET_A, BODY));
        assert_ne!(content(SECRET_A, BODY), content(SECRET_B, BODY));
        assert_ne!(content(SECRET_A, BODY), content(SECRET_A, &other_body));
    }

    #[test]
    fn the_answer_shows_a_requested_model_name_only_if_the_name_is_clean() {
        let personas = personas(MODEL);
        let model_of = |requested: &str| {
            let body = json!({"model": requested, "messages": [{"role": "user", "content": "x"}]});
            let planned = plan_for(&personas, &chat_request(&body.to_string()));
            let (answer, _, _) = paced(&planned.reply);
            let recorded = trip(&planned).1["model"].as_str().unwrap().to_owned();
            (answer["model"].as_str().unwrap().to_owned(), recorded)
        };
        assert_eq!(
            model_of("custom-model:v1.2"),
            (
                "custom-model:v1.2".to_owned(),
                "custom-model:v1.2".to_owned()
            )
        );
        assert_eq!(
            model_of("<script>\nx</script>"),
            (
                "assistant-large".to_owned(),
                "<script> x</script>".to_owned()
            )
        );
        let long = "m".repeat(200);
        assert_eq!(
            model_of(&long),
            ("assistant-large".to_owned(), "m".repeat(64))
        );
    }

    #[test]
    fn the_canary_instruction_is_the_start_of_a_complete_answer() {
        let personas = personas(MODEL);
        let planned = plan_for(&personas, &chat_request(BODY));
        let id = planned.planted_canary.clone().unwrap();
        let (answer, _, _) = paced(&planned.reply);
        let content = answer["choices"][0]["message"]["content"].as_str().unwrap();
        let (first, rest) = content.split_once("\n\n").unwrap();
        let url = first.strip_prefix(CANARY_INSTRUCTION_PREFIX).unwrap();
        assert!(url.starts_with(&format!("/ref/{id}")), "{url}");
        assert_eq!(url.len(), "/ref/".len() + 32);
        assert!(!rest.contains("Automated agents"));
        assert_eq!(rest.split(' ').count(), 160);
    }

    #[test]
    fn a_streamed_answer_is_one_event_for_each_word_and_then_the_end() {
        let mut config = config(MODEL);
        config.model_api.answer_words = 25;
        config.model_api.interval = Duration::from_millis(300);
        let personas = personas_with(&config, SECRET_A);
        let body = BODY.replacen('{', r#"{"stream":true,"#, 1);
        let mut planned = plan_for(&personas, &chat_request(&body));
        assert_eq!(planned.reply.status, 200);
        assert_eq!(planned.reply.content_type, EVENT_STREAM);
        assert_eq!(trip(&planned).1["stream"], true);
        let canary_id = planned.planted_canary.clone().unwrap();
        let (pieces, closing, interval) = stream_pieces(&mut planned);
        assert_eq!(interval, Duration::from_millis(300));
        // The role, the instruction, 25 words, and the end.
        assert_eq!(pieces.len(), 28);
        let all = events(&pieces.concat());
        assert_eq!(all.len(), 28);
        let ids: std::collections::BTreeSet<&str> = all
            .iter()
            .map(|event| event["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 1);
        for event in &all {
            assert_eq!(event["object"], "chat.completion.chunk");
            assert_eq!(event["model"], "assistant-large");
            assert_eq!(event["choices"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            all[0]["choices"][0]["delta"],
            json!({"role": "assistant", "content": ""})
        );
        let instruction = all[1]["choices"][0]["delta"]["content"].as_str().unwrap();
        let url = instruction
            .strip_prefix(CANARY_INSTRUCTION_PREFIX)
            .unwrap()
            .strip_suffix("\n\n")
            .unwrap();
        assert!(url.starts_with(&format!("/ref/{canary_id}")), "{url}");
        let words: String = all[2..27]
            .iter()
            .map(|event| event["choices"][0]["delta"]["content"].as_str().unwrap())
            .collect();
        assert_eq!(words.split(' ').count(), 25);
        assert!(!words.starts_with(' '));
        for event in &all[..27] {
            assert_eq!(event["choices"][0]["finish_reason"], Value::Null);
        }
        assert_eq!(all[27]["choices"][0]["delta"], json!({}));
        assert_eq!(all[27]["choices"][0]["finish_reason"], "stop");
        assert!(
            pieces[27].ends_with("\n\ndata: [DONE]\n\n"),
            "{}",
            pieces[27]
        );
        // Each piece is one complete event, so a slow client never gets half an event.
        for piece in &pieces[..27] {
            assert!(
                piece.starts_with("data: {") && piece.ends_with("}\n\n"),
                "{piece}"
            );
            assert_eq!(piece.matches("\n\n").count(), 1);
        }

        // An early end is also a complete stream.
        let closing_events = events(&closing);
        assert_eq!(closing_events.len(), 1);
        assert_eq!(closing_events[0]["choices"][0]["finish_reason"], "length");
        assert_eq!(closing_events[0]["id"], all[0]["id"]);
        assert!(closing.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn with_canaries_off_a_streamed_answer_has_only_filler_words() {
        let mut config = config(MODEL);
        config.model_api.answer_words = 30;
        config.canary.enabled = false;
        let personas = personas_with(&config, SECRET_A);
        let stream_body = BODY.replacen('{', r#"{"stream":true,"#, 1);
        let mut streamed = plan_for(&personas, &chat_request(&stream_body));
        assert_eq!(streamed.planted_canary, None);
        let (pieces, _, _) = stream_pieces(&mut streamed);
        // The role, 30 words, and the end.
        assert_eq!(pieces.len(), 32);
        let streamed_words: String = events(&pieces.concat())
            .iter()
            .filter_map(|event| event["choices"][0]["delta"]["content"].as_str())
            .collect();
        assert_eq!(streamed_words.split(' ').count(), 30);
        assert!(
            streamed_words
                .chars()
                .all(|c| c.is_ascii_alphabetic() || matches!(c, ' ' | '.')),
            "{streamed_words}"
        );
    }

    #[test]
    fn a_paced_body_is_complete_one_interval_before_the_hold_limit() {
        let second = Duration::from_secs(1);
        // Enough time: one piece for each word.
        assert_eq!(piece_size(1000, 100, second, Duration::from_secs(500)), 10);
        // Ten seconds give nine ticks before the limit.
        assert_eq!(piece_size(900, 100, second, Duration::from_secs(10)), 100);
        // With no time, the body is one piece.
        assert_eq!(
            piece_size(900, 100, second, Duration::from_millis(1500)),
            900
        );
        assert_eq!(piece_size(900, 100, second, Duration::ZERO), 900);
        assert_eq!(piece_size(0, 100, second, Duration::from_secs(500)), 1);
        assert_eq!(piece_size(7, 3, second, Duration::from_secs(500)), 3);
    }

    #[test]
    fn the_largest_complete_answer_fits_in_the_reply_buffer() {
        let mut config = config(MODEL);
        config.model_api.answer_words = 1000;
        config.canary.origin = Some(format!("https://{}:65535", "h".repeat(240)));
        config.canary.path_prefix = format!("/{}", "c".repeat(63));
        let personas = personas_with(&config, SECRET_A);
        let model = "m".repeat(64);
        let body = json!({"model": model, "messages": [{"role": "user", "content": "x"}]});
        let planned = plan_for(&personas, &chat_request(&body.to_string()));
        match &planned.reply.body {
            Body::Paced { bytes, .. } => {
                assert!(bytes.len() < REPLY_BUFFER_BYTES, "{}", bytes.len());
                assert!(bytes.len() > 4000, "{}", bytes.len());
            }
            _ => panic!("the body is not paced"),
        }
    }

    #[test]
    fn a_long_text_is_added_only_up_to_the_limit_and_at_a_character_border() {
        let mut text = "ab".to_owned();
        push_limited(&mut text, "cdef", 4);
        assert_eq!(text, "abcd");
        push_limited(&mut text, "x", 4);
        assert_eq!(text, "abcd");
        let mut wide = String::new();
        push_limited(&mut wide, "ééé", 3);
        assert_eq!(wide, "é");
    }
}
