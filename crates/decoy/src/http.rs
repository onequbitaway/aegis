//! The HTTP/1.1 messages of the decoy.
//!
//! The decoy reads one request for each connection and then closes the connection. It
//! reads a body only with a `Content-Length` header. It never reads a compressed or a
//! chunked body, and it never sends a compressed body.

use chrono::{DateTime, Utc};

/// The chunk that ends a chunked body.
pub(crate) const LAST_CHUNK: &[u8] = b"0\r\n\r\n";
/// The interim response to `Expect: 100-continue`.
pub(crate) const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

/// One request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    /// The name, as the client wrote it.
    pub(crate) name: String,
    /// The value, as the client wrote it.
    pub(crate) value: Vec<u8>,
}

/// The request line and the headers of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestHead {
    /// The method, as the client wrote it.
    pub(crate) method: String,
    /// The request target, as the client wrote it.
    pub(crate) target: String,
    /// The minor HTTP version: 0 for HTTP/1.0 and 1 for HTTP/1.1.
    pub(crate) minor_version: u8,
    /// The headers, in the order of the request.
    pub(crate) headers: Vec<Header>,
}

impl RequestHead {
    /// Returns the values of all headers with the name `name`. The case is ignored.
    pub(crate) fn header_values<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = &'a [u8]> + use<'a, 'n> {
        self.headers
            .iter()
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_slice())
    }

    /// Returns the value of the first header with the name `name`.
    pub(crate) fn header(&self, name: &str) -> Option<&[u8]> {
        self.header_values(name).next()
    }

    /// Returns the HTTP version as text.
    pub(crate) fn version(&self) -> &'static str {
        if self.minor_version == 0 {
            "HTTP/1.0"
        } else {
            "HTTP/1.1"
        }
    }

    /// Returns the path of the request target, without the query.
    pub(crate) fn path(&self) -> &str {
        split_target(&self.target).0
    }

    /// Returns the query of the request target, without the `?`.
    pub(crate) fn query(&self) -> &str {
        split_target(&self.target).1
    }

    /// Returns the number of bytes that the request line and the headers use in memory.
    pub(crate) fn size(&self) -> usize {
        self.method.len()
            + self.target.len()
            + self
                .headers
                .iter()
                .map(|header| header.name.len() + header.value.len())
                .sum::<usize>()
    }
}

/// Divides a request target into the path and the query.
///
/// A target with a scheme and a host gives the path after the host.
fn split_target(target: &str) -> (&str, &str) {
    let lower_start = target.get(..8).unwrap_or(target).to_ascii_lowercase();
    let scheme_length = if lower_start.starts_with("http://") {
        Some(7)
    } else if lower_start.starts_with("https://") {
        Some(8)
    } else {
        None
    };
    let local = match scheme_length.and_then(|length| target.get(length..)) {
        Some(after_scheme) => match after_scheme.find(['/', '?']) {
            Some(start) => after_scheme.get(start..).unwrap_or("/"),
            None => "/",
        },
        None => target,
    };
    match local.split_once('?') {
        Some(("", query)) => ("/", query),
        Some((path, query)) => (path, query),
        None => (local, ""),
    }
}

/// Why the request line and the headers are not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// The request has more headers than the limit.
    TooManyHeaders,
    /// The bytes are not a valid HTTP/1.x request.
    Malformed,
}

/// Returns `true` if `buffer` holds the empty line that ends the headers.
///
/// The function examines only the bytes from `scanned`, and the three bytes before them.
pub(crate) fn has_head_end(buffer: &[u8], scanned: usize) -> bool {
    let start = scanned.saturating_sub(3);
    let window = buffer.get(start..).unwrap_or_default();
    window.windows(2).any(|pair| pair == b"\n\n")
        || window.windows(3).any(|triple| triple == b"\n\r\n")
}

/// Reads the request line and the headers from `buffer`.
///
/// Returns the request and the number of bytes that it used.
pub(crate) fn parse_head(
    buffer: &[u8],
    max_headers: usize,
) -> Result<(RequestHead, usize), HeadError> {
    let mut slots = vec![httparse::EMPTY_HEADER; max_headers];
    let mut request = httparse::Request::new(&mut slots);
    let length = match request.parse(buffer) {
        Ok(httparse::Status::Complete(length)) => length,
        Ok(httparse::Status::Partial) => return Err(HeadError::Malformed),
        Err(httparse::Error::TooManyHeaders) => return Err(HeadError::TooManyHeaders),
        Err(_) => return Err(HeadError::Malformed),
    };
    let (Some(method), Some(target), Some(minor_version)) =
        (request.method, request.path, request.version)
    else {
        return Err(HeadError::Malformed);
    };
    let headers = request
        .headers
        .iter()
        .map(|header| Header {
            name: header.name.to_owned(),
            value: header.value.to_vec(),
        })
        .collect();
    Ok((
        RequestHead {
            method: method.to_owned(),
            target: target.to_owned(),
            minor_version,
            headers,
        },
        length,
    ))
}

/// Why the decoy cannot read the body of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// The request has a `Transfer-Encoding` header. The decoy reads only a fixed length.
    LengthRequired,
    /// The `Content-Length` header is not one number.
    Invalid,
}

/// Returns the length of the request body from the headers.
///
/// A length that is too large for a number becomes the largest number.
pub(crate) fn body_length(head: &RequestHead) -> Result<u64, FramingError> {
    if head.header("transfer-encoding").is_some() {
        return Err(FramingError::LengthRequired);
    }
    let mut length: Option<u64> = None;
    for value in head.header_values("content-length") {
        let text = std::str::from_utf8(value)
            .map_err(|_| FramingError::Invalid)?
            .trim_matches([' ', '\t']);
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(FramingError::Invalid);
        }
        let parsed = text.parse::<u64>().unwrap_or(u64::MAX);
        if length.is_some_and(|known| known != parsed) {
            return Err(FramingError::Invalid);
        }
        length = Some(parsed);
    }
    Ok(length.unwrap_or(0))
}

/// Returns `true` if the client waits for `100 Continue` before it sends the body.
pub(crate) fn expects_continue(head: &RequestHead) -> bool {
    head.minor_version >= 1
        && head
            .header("expect")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"100-continue"))
}

/// Returns the reason phrase of a status code.
pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Response",
    }
}

/// How the body of a response ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyLength {
    /// The body has this number of bytes.
    Fixed(usize),
    /// The body is chunked.
    Chunked,
    /// The body ends when the decoy closes the connection. Use this for HTTP/1.0.
    UntilClose,
}

/// The status line and the headers of one response.
pub(crate) struct ResponseHead<'a> {
    pub(crate) status: u16,
    pub(crate) content_type: &'a str,
    pub(crate) length: BodyLength,
    /// More headers. The decoy makes each value. No value comes from a client.
    pub(crate) extra: &'a [(&'static str, String)],
}

impl ResponseHead<'_> {
    /// Returns the bytes of the status line and the headers, with the empty line.
    ///
    /// Each response closes the connection, forbids caching, and has no content encoding.
    pub(crate) fn encode(&self, now: DateTime<Utc>) -> Vec<u8> {
        let mut text = String::with_capacity(256);
        text.push_str("HTTP/1.1 ");
        text.push_str(&self.status.to_string());
        text.push(' ');
        text.push_str(reason(self.status));
        text.push_str("\r\n");
        push_header(&mut text, "Date", &http_date(now));
        push_header(&mut text, "Content-Type", self.content_type);
        match self.length {
            BodyLength::Fixed(length) => {
                push_header(&mut text, "Content-Length", &length.to_string())
            }
            BodyLength::Chunked => push_header(&mut text, "Transfer-Encoding", "chunked"),
            BodyLength::UntilClose => {}
        }
        push_header(&mut text, "Cache-Control", "no-store");
        push_header(&mut text, "Connection", "close");
        for (name, value) in self.extra {
            push_header(&mut text, name, value);
        }
        text.push_str("\r\n");
        text.into_bytes()
    }
}

/// Adds one header line. A value with a control character is not added.
///
/// A control character in a value can start a new header line. The decoy makes all
/// values itself, so this guard is a second barrier.
fn push_header(text: &mut String, name: &str, value: &str) {
    if value.chars().any(char::is_control) || name.chars().any(char::is_control) {
        return;
    }
    text.push_str(name);
    text.push_str(": ");
    text.push_str(value);
    text.push_str("\r\n");
}

/// Returns `time` in the date format of HTTP, for example `Tue, 03 Nov 2026 09:10:31 GMT`.
fn http_date(time: DateTime<Utc>) -> String {
    time.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Returns `piece` as one chunk of a chunked body. An empty piece gives no bytes.
///
/// A chunk with no data ends the body, so the function never makes one.
pub(crate) fn chunk(piece: &[u8]) -> Vec<u8> {
    if piece.is_empty() {
        return Vec::new();
    }
    let mut framed = format!("{:x}\r\n", piece.len()).into_bytes();
    framed.extend_from_slice(piece);
    framed.extend_from_slice(b"\r\n");
    framed
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn parse(text: &str) -> Result<(RequestHead, usize), HeadError> {
        parse_head(text.as_bytes(), 16)
    }

    fn head(text: &str) -> RequestHead {
        parse(text).unwrap().0
    }

    #[test]
    fn a_request_keeps_the_method_the_target_the_version_and_the_header_order() {
        let text = "POST /v1/chat/completions?x=1 HTTP/1.1\r\nhost: decoy\r\nUser-Agent: agent/1\r\nX-B: 2\r\nX-A: 1\r\n\r\nBODY";
        let (head, length) = parse(text).unwrap();
        assert_eq!(length, text.len() - 4);
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/v1/chat/completions?x=1");
        assert_eq!(head.path(), "/v1/chat/completions");
        assert_eq!(head.query(), "x=1");
        assert_eq!(head.minor_version, 1);
        assert_eq!(head.version(), "HTTP/1.1");
        let names: Vec<&str> = head.headers.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["host", "User-Agent", "X-B", "X-A"]);
        assert_eq!(head.header("USER-AGENT"), Some(b"agent/1".as_slice()));
        assert_eq!(head.header("x-missing"), None);
        assert_eq!(head.size(), 4 + 24 + 4 + 5 + 10 + 7 + 3 + 1 + 3 + 1);
    }

    #[test]
    fn an_http_1_0_request_has_the_minor_version_zero() {
        let head = head("GET / HTTP/1.0\r\n\r\n");
        assert_eq!(head.minor_version, 0);
        assert_eq!(head.version(), "HTTP/1.0");
        assert_eq!(head.path(), "/");
        assert_eq!(head.query(), "");
    }

    #[test]
    fn a_target_with_a_host_gives_the_path_after_the_host() {
        assert_eq!(
            split_target("http://decoy.example/a/b?c=d"),
            ("/a/b", "c=d")
        );
        assert_eq!(split_target("HTTPS://decoy.example:8443/a"), ("/a", ""));
        assert_eq!(split_target("http://decoy.example"), ("/", ""));
        assert_eq!(split_target("http://decoy.example?x=1"), ("/", "x=1"));
        assert_eq!(split_target("/a?b?c"), ("/a", "b?c"));
        assert_eq!(split_target("*"), ("*", ""));
        assert_eq!(split_target("decoy.example:443"), ("decoy.example:443", ""));
        assert_eq!(split_target("/é/x"), ("/é/x", ""));
    }

    #[test]
    fn bytes_that_are_not_a_request_are_malformed() {
        for text in [
            "GET /\r\n\r\n",
            "GET / HTTP/2.0\r\n\r\n",
            "GET  / HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\nno colon\r\n\r\n",
            "GET / HTTP/1.1\r\nbad name: x\r\n\r\n",
            "\u{16}\u{3}\u{1}\u{0}\n\n",
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            "GET / HTTP/1.1\r\n",
        ] {
            assert_eq!(parse(text).err(), Some(HeadError::Malformed), "{text:?}");
        }
    }

    #[test]
    fn more_headers_than_the_limit_is_a_separate_error() {
        let mut text = "GET / HTTP/1.1\r\n".to_owned();
        for index in 0..16 {
            text.push_str(&format!("X-{index}: v\r\n"));
        }
        let at_limit = format!("{text}\r\n");
        assert_eq!(parse(&at_limit).unwrap().0.headers.len(), 16);
        let above = format!("{text}X-16: v\r\n\r\n");
        assert_eq!(parse(&above).err(), Some(HeadError::TooManyHeaders));
    }

    #[test]
    fn the_end_of_the_headers_is_found_in_the_new_bytes_only() {
        assert!(has_head_end(b"GET / HTTP/1.1\r\n\r\n", 0));
        assert!(has_head_end(b"GET / HTTP/1.1\n\n", 0));
        assert!(!has_head_end(b"GET / HTTP/1.1\r\n", 0));
        assert!(!has_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n", 0));
        // The end can start in the bytes that an earlier read supplied.
        let bytes = b"GET / HTTP/1.1\r\n\r\n";
        for scanned in 0..bytes.len() {
            assert!(has_head_end(bytes, scanned), "{scanned}");
        }
        // Bytes before the window are not examined again.
        assert!(!has_head_end(b"a\n\nbcdefgh", 6));
        assert!(!has_head_end(b"", 0));
        assert!(!has_head_end(b"abc", 10));
    }

    #[test]
    fn the_body_length_comes_from_one_content_length_value() {
        let length =
            |headers: &str| body_length(&head(&format!("POST / HTTP/1.1\r\n{headers}\r\n")));
        assert_eq!(length(""), Ok(0));
        assert_eq!(length("Content-Length: 0\r\n"), Ok(0));
        assert_eq!(length("content-length:  42 \r\n"), Ok(42));
        assert_eq!(length("Content-Length: 7\r\nContent-Length: 7\r\n"), Ok(7));
        assert_eq!(
            length("Content-Length: 99999999999999999999999999\r\n"),
            Ok(u64::MAX)
        );
        for headers in [
            "Content-Length: 7\r\nContent-Length: 8\r\n",
            "Content-Length: -1\r\n",
            "Content-Length: +1\r\n",
            "Content-Length: 1,2\r\n",
            "Content-Length: 0x10\r\n",
            "Content-Length: \r\n",
            "Content-Length: 1 2\r\n",
        ] {
            assert_eq!(length(headers), Err(FramingError::Invalid), "{headers:?}");
        }
        assert_eq!(
            length("Transfer-Encoding: chunked\r\n"),
            Err(FramingError::LengthRequired)
        );
        assert_eq!(
            length("Content-Length: 5\r\nTransfer-Encoding: gzip, chunked\r\n"),
            Err(FramingError::LengthRequired)
        );
    }

    #[test]
    fn only_an_http_1_1_client_gets_the_interim_response() {
        assert!(expects_continue(&head(
            "POST / HTTP/1.1\r\nExpect: 100-Continue\r\n\r\n"
        )));
        assert!(!expects_continue(&head(
            "POST / HTTP/1.0\r\nExpect: 100-continue\r\n\r\n"
        )));
        assert!(!expects_continue(&head(
            "POST / HTTP/1.1\r\nExpect: something\r\n\r\n"
        )));
        assert!(!expects_continue(&head("POST / HTTP/1.1\r\n\r\n")));
    }

    #[test]
    fn a_response_head_closes_the_connection_and_has_no_content_encoding() {
        let now = Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 31).unwrap();
        let extra = [("Location", "/docs".to_owned())];
        let head = ResponseHead {
            status: 302,
            content_type: "text/plain; charset=utf-8",
            length: BodyLength::Fixed(12),
            extra: &extra,
        };
        assert_eq!(
            String::from_utf8(head.encode(now)).unwrap(),
            "HTTP/1.1 302 Found\r\n\
             Date: Tue, 03 Nov 2026 09:10:31 GMT\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: 12\r\n\
             Cache-Control: no-store\r\n\
             Connection: close\r\n\
             Location: /docs\r\n\
             \r\n"
        );
    }

    #[test]
    fn the_body_length_selects_the_framing_header() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let encode = |length| {
            let head = ResponseHead {
                status: 200,
                content_type: "text/html",
                length,
                extra: &[],
            };
            String::from_utf8(head.encode(now)).unwrap()
        };
        let chunked = encode(BodyLength::Chunked);
        assert!(
            chunked.contains("\r\nTransfer-Encoding: chunked\r\n"),
            "{chunked}"
        );
        assert!(!chunked.contains("Content-Length"), "{chunked}");
        let until_close = encode(BodyLength::UntilClose);
        assert!(!until_close.contains("Transfer-Encoding"), "{until_close}");
        assert!(!until_close.contains("Content-Length"), "{until_close}");
        assert!(
            until_close.starts_with("HTTP/1.1 200 OK\r\n"),
            "{until_close}"
        );
    }

    #[test]
    fn a_header_value_with_a_line_break_is_not_sent() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let extra = [
            ("X-Bad", "a\r\nSet-Cookie: x=1".to_owned()),
            ("X-Good", "b".to_owned()),
        ];
        let head = ResponseHead {
            status: 200,
            content_type: "text/plain",
            length: BodyLength::Fixed(0),
            extra: &extra,
        };
        let text = String::from_utf8(head.encode(now)).unwrap();
        assert!(!text.contains("Set-Cookie"), "{text}");
        assert!(!text.contains("X-Bad"), "{text}");
        assert!(text.contains("\r\nX-Good: b\r\n"), "{text}");
    }

    #[test]
    fn each_status_that_the_decoy_sends_has_a_reason_phrase() {
        for (status, phrase) in [
            (200, "OK"),
            (302, "Found"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (404, "Not Found"),
            (405, "Method Not Allowed"),
            (408, "Request Timeout"),
            (411, "Length Required"),
            (413, "Content Too Large"),
            (431, "Request Header Fields Too Large"),
        ] {
            assert_eq!(reason(status), phrase);
        }
    }

    #[test]
    fn a_chunk_has_the_length_in_hexadecimal_and_an_empty_piece_gives_nothing() {
        assert_eq!(chunk(b"abcd"), b"4\r\nabcd\r\n");
        assert_eq!(
            chunk(&[b'x'; 26]),
            [b"1a\r\n".as_slice(), &[b'x'; 26], b"\r\n"].concat()
        );
        assert_eq!(chunk(b""), b"");
    }
}
