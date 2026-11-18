//! The tarpit persona: a valid page that arrives very slowly.
//!
//! The tarpit answers each request with the status 200 and an HTML page. The page has no
//! end of its own. The decoy sends a few bytes at each interval. At the hold limit or the
//! byte limit, it sends the end of the page.

use crate::config::{PersonaKind, TarpitConfig};
use crate::persona::words;
use crate::persona::{Body, HTML, Personas, PieceSource, Planned, Reply, RequestView};
use crate::seed::Generator;

/// The end of the page. The decoy sends it when it ends the answer.
pub(crate) const CLOSING: &[u8] = b"</p>\n</body>\n</html>\n";

/// Plans the tarpit answer to one request.
pub(crate) fn plan(personas: &Personas, config: &TarpitConfig, view: &RequestView<'_>) -> Planned {
    let canary = personas.canary(PersonaKind::Tarpit, view);
    let generator = personas
        .seed
        .generator("tarpit-page", &[view.path.as_bytes()]);
    let source = TarpitSource::new(
        generator,
        canary.as_ref().map(|canary| canary.instruction.as_str()),
        config.chunk_bytes,
    );
    Planned {
        kind: Some(PersonaKind::Tarpit),
        reply: Reply {
            status: 200,
            content_type: HTML,
            headers: Vec::new(),
            body: Body::Stream {
                source: Box::new(source),
                closing: CLOSING.to_vec(),
                interval: config.interval,
            },
        },
        signal: None,
        planted_canary: canary.map(|canary| canary.id),
    }
}

/// Makes the bytes of an endless page, a few bytes for each call.
///
/// The source keeps only the text that it did not send yet: one sentence at most.
struct TarpitSource {
    generator: Generator,
    pending: Vec<u8>,
    chunk_bytes: usize,
}

impl TarpitSource {
    fn new(mut generator: Generator, instruction: Option<&str>, chunk_bytes: usize) -> Self {
        let title = words::title(&mut generator);
        let mut start = format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n</head>\n<body>\n"
        );
        if let Some(instruction) = instruction {
            start.push_str(&format!("<p hidden>{instruction}</p>\n"));
        }
        start.push_str(&format!("<h1>{title}</h1>\n<p>"));
        Self {
            generator,
            pending: start.into_bytes(),
            chunk_bytes: chunk_bytes.max(1),
        }
    }
}

impl PieceSource for TarpitSource {
    fn next_piece(&mut self) -> Option<Vec<u8>> {
        while self.pending.len() < self.chunk_bytes {
            let sentence = words::page_sentence(&mut self.generator);
            self.pending.extend_from_slice(sentence.as_bytes());
            self.pending.push(b' ');
        }
        let rest = self.pending.split_off(self.chunk_bytes);
        Some(std::mem::replace(&mut self.pending, rest))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::canary::CANARY_INSTRUCTION_PREFIX;
    use crate::persona::testing::*;

    const TARPIT: &[PersonaKind] = &[PersonaKind::Tarpit];

    /// Returns the first `pieces` pieces of the tarpit answer to `request`.
    fn page(personas: &Personas, request: &Request, pieces: usize) -> (Planned, Vec<Vec<u8>>) {
        let mut planned = plan_request(personas, request);
        let Body::Stream { source, .. } = &mut planned.reply.body else {
            panic!("the tarpit body is a stream");
        };
        let collected = (0..pieces).map(|_| source.next_piece().unwrap()).collect();
        (planned, collected)
    }

    fn plan_request(personas: &Personas, request: &Request) -> Planned {
        plan_for(personas, request)
    }

    fn text(pieces: &[Vec<u8>]) -> String {
        String::from_utf8(pieces.concat()).unwrap()
    }

    #[test]
    fn the_answer_is_an_html_stream_with_the_configured_pace() {
        let mut config = config(TARPIT);
        config.tarpit.chunk_bytes = 5;
        config.tarpit.interval = Duration::from_millis(250);
        let personas = personas_with(&config, SECRET_A);
        let planned = plan_request(&personas, &Request::new("POST", "/login"));
        assert_eq!(planned.kind, Some(PersonaKind::Tarpit));
        assert_eq!(planned.reply.status, 200);
        assert_eq!(planned.reply.content_type, HTML);
        assert!(planned.reply.headers.is_empty());
        assert!(planned.signal.is_none());
        let Body::Stream {
            closing, interval, ..
        } = &planned.reply.body
        else {
            panic!("the tarpit body is a stream");
        };
        assert_eq!(*interval, Duration::from_millis(250));
        assert_eq!(closing, b"</p>\n</body>\n</html>\n");
    }

    #[test]
    fn each_piece_has_the_configured_number_of_bytes_and_the_page_has_no_end() {
        let mut config = config(TARPIT);
        config.tarpit.chunk_bytes = 7;
        let personas = personas_with(&config, SECRET_A);
        let (_, pieces) = page(&personas, &Request::new("GET", "/"), 3000);
        assert_eq!(pieces.len(), 3000);
        assert!(pieces.iter().all(|piece| piece.len() == 7));
        let text = text(&pieces);
        assert!(
            text.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"),
            "{}",
            &text[..80]
        );
        assert!(!text.contains("</body>"));
        assert!(text.is_ascii());
    }

    #[test]
    fn the_page_is_the_same_for_one_seed_and_one_path() {
        let first = text(&page(&personas(TARPIT), &Request::new("GET", "/a"), 200).1);
        let second = text(&page(&personas(TARPIT), &Request::new("GET", "/a"), 200).1);
        let other_path = text(&page(&personas(TARPIT), &Request::new("GET", "/b"), 200).1);
        let other_seed = text(
            &page(
                &personas_with(&config(TARPIT), SECRET_B),
                &Request::new("GET", "/a"),
                200,
            )
            .1,
        );
        assert_eq!(first, second);
        assert_ne!(first, other_path);
        assert_ne!(first, other_seed);
    }

    #[test]
    fn the_page_carries_one_canary_instruction_near_its_start() {
        let personas = personas(TARPIT);
        let (planned, pieces) = page(&personas, &Request::new("GET", "/"), 100);
        let text = text(&pieces);
        let id = planned.planted_canary.unwrap();
        let hidden_start = text.find("<p hidden>").unwrap();
        let hidden_end = hidden_start + text[hidden_start..].find("</p>").unwrap();
        let instruction = &text[hidden_start + "<p hidden>".len()..hidden_end];
        let url = instruction.strip_prefix(CANARY_INSTRUCTION_PREFIX).unwrap();
        assert!(url.starts_with(&format!("/ref/{id}")), "{url}");
        assert_eq!(text.matches(CANARY_INSTRUCTION_PREFIX).count(), 1);
        assert!(hidden_start < 200);
    }

    #[test]
    fn with_canaries_off_the_page_has_no_instruction() {
        let mut config = config(TARPIT);
        config.canary.enabled = false;
        let personas = personas_with(&config, SECRET_A);
        let (planned, pieces) = page(&personas, &Request::new("GET", "/"), 100);
        assert_eq!(planned.planted_canary, None);
        let text = text(&pieces);
        assert!(!text.contains("hidden"));
        assert!(!text.contains("Automated agents"));
    }

    #[test]
    fn the_source_keeps_one_sentence_at_most() {
        let personas = personas(TARPIT);
        let mut source =
            TarpitSource::new(personas.seed.generator("tarpit-page", &[b"/"]), None, 8);
        let mut largest = 0;
        for _ in 0..5000 {
            source.next_piece().unwrap();
            largest = largest.max(source.pending.len());
        }
        // The start of the page is the longest text that the source holds.
        assert!(largest < 400, "{largest}");
    }
}
