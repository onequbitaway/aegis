//! The maze persona: an endless set of generated pages and an endless JSON API.
//!
//! Each page and each API answer comes from the secret seed and the request path. The
//! maze keeps no state: it makes the same content for the same path each time. Each page
//! links to more pages, and each API answer links to a next answer.
//!
//! The content is generated text from a fixed word list. It holds no real data.

use serde_json::{Value, json};

use crate::config::{MazeConfig, PersonaKind};
use crate::persona::words::{self, ADJECTIVES, COLLECTIONS, NOUNS, REGIONS, SECTIONS, STATES};
use crate::persona::{HTML, Personas, Planned, Reply, RequestView};
use crate::seed::Seed;

/// The number of hexadecimal digits in a cursor of the JSON API.
const CURSOR_LENGTH: usize = 16;
/// The number of text paragraphs on one page.
const PARAGRAPHS: usize = 3;
/// The number of links to other collections in one API answer.
const RELATED: usize = 3;

/// Plans the answer to a request below the page root.
pub(crate) fn page(personas: &Personas, config: &MazeConfig, view: &RequestView<'_>) -> Planned {
    if let Some(refusal) = refuse_method(view) {
        return refusal;
    }
    let canary = personas.canary(PersonaKind::Maze, view);
    let instruction = canary.as_ref().map(|canary| canary.instruction.as_str());
    let html = page_html(&personas.seed, config, view.path, instruction);
    let reply = Reply::full(200, HTML, html.into_bytes()).with_delay(config.delay);
    Planned {
        kind: Some(PersonaKind::Maze),
        reply,
        signal: None,
        planted_canary: canary.map(|canary| canary.id),
    }
}

/// Plans the answer to a request below the API root.
pub(crate) fn api(personas: &Personas, config: &MazeConfig, view: &RequestView<'_>) -> Planned {
    if let Some(refusal) = refuse_method(view) {
        return refusal;
    }
    let canary = personas.canary(PersonaKind::Maze, view);
    let instruction = canary.as_ref().map(|canary| canary.instruction.as_str());
    let answer = api_json(&personas.seed, config, view.path, view.query, instruction);
    let reply = Reply::json(200, &answer).with_delay(config.delay);
    Planned {
        kind: Some(PersonaKind::Maze),
        reply,
        signal: None,
        planted_canary: canary.map(|canary| canary.id),
    }
}

/// The maze answers only `GET` and `HEAD`.
fn refuse_method(view: &RequestView<'_>) -> Option<Planned> {
    if matches!(view.head.method.as_str(), "GET" | "HEAD") {
        return None;
    }
    let reply = Reply::plain(405).with_header("Allow", "GET, HEAD");
    Some(Planned::of(PersonaKind::Maze, reply))
}

/// Returns the title of the page at `path`.
fn page_title(seed: &Seed, path: &str) -> String {
    words::title(&mut seed.generator("maze-title", &[path.as_bytes()]))
}

/// Returns the path of link number `index` on the page at `path`.
///
/// The link has a fixed number of segments, so a path does not grow from page to page.
fn link_target(seed: &Seed, config: &MazeConfig, path: &str, index: usize) -> String {
    let mut generator = seed.generator("maze-link", &[path.as_bytes(), &index.to_be_bytes()]);
    format!(
        "{}/{}/{}-{}-{}",
        config.page_root,
        generator.word(SECTIONS),
        generator.word(ADJECTIVES),
        generator.word(NOUNS),
        generator.hex(8)
    )
}

/// Makes the HTML of the page at `path`.
///
/// The page shows only generated words, a canary instruction, and paths that the decoy
/// made. It never shows text of the request.
pub(crate) fn page_html(
    seed: &Seed,
    config: &MazeConfig,
    path: &str,
    instruction: Option<&str>,
) -> String {
    let title = page_title(seed, path);
    let mut text_generator = seed.generator("maze-text", &[path.as_bytes()]);
    let mut html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>{title}</title>\n</head>\n<body>\n<nav><a href=\"{root}\">Index</a></nav>\n<h1>{title}</h1>\n",
        root = config.page_root
    );
    for _ in 0..PARAGRAPHS {
        let sentences = 2 + text_generator.below(3);
        html.push_str("<p>");
        for index in 0..sentences {
            if index > 0 {
                html.push(' ');
            }
            html.push_str(&words::page_sentence(&mut text_generator));
        }
        html.push_str("</p>\n");
    }
    html.push_str("<h2>Related pages</h2>\n<ul>\n");
    for index in 0..config.links_per_page {
        let target = link_target(seed, config, path, index);
        let target_title = page_title(seed, &target);
        html.push_str(&format!(
            "<li><a href=\"{target}\">{target_title}</a></li>\n"
        ));
    }
    html.push_str("</ul>\n");
    let collection = text_generator.word(COLLECTIONS);
    html.push_str(&format!(
        "<p><a href=\"{}/{collection}\">Data export</a></p>\n",
        config.api_root
    ));
    if let Some(instruction) = instruction {
        html.push_str(&format!("<p hidden>{instruction}</p>\n"));
    }
    html.push_str("</body>\n</html>\n");
    html
}

/// Returns `true` if a client can name a collection with `name`.
fn is_collection_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
}

/// Returns the collection of an API path.
///
/// The first segment below the API root is the collection, if it is a clean name. For
/// each other path, the seed selects a collection. Thus an answer never shows text of
/// the request that is not a clean name.
fn collection_of(seed: &Seed, config: &MazeConfig, path: &str) -> String {
    let below = path.strip_prefix(config.api_root.as_str()).unwrap_or(path);
    let first = below
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or("");
    if is_collection_name(first) {
        first.to_owned()
    } else {
        seed.generator("maze-collection", &[path.as_bytes()])
            .word(COLLECTIONS)
            .to_owned()
    }
}

/// Returns the cursor of a query, if the query has a cursor that the decoy can have made.
fn cursor_of(query: &str) -> &str {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("cursor="))
        .filter(|cursor| {
            cursor.len() == CURSOR_LENGTH
                && cursor
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .unwrap_or("")
}

/// Makes one answer of the JSON API.
///
/// The answer always has a `next` link. The next cursor comes from the seed, the
/// collection, and the cursor of the request.
pub(crate) fn api_json(
    seed: &Seed,
    config: &MazeConfig,
    path: &str,
    query: &str,
    instruction: Option<&str>,
) -> Value {
    let collection = collection_of(seed, config, path);
    let cursor = cursor_of(query);
    let next = seed.derive_hex(
        "maze-cursor",
        &[collection.as_bytes(), cursor.as_bytes()],
        CURSOR_LENGTH,
    );
    let prefix: String = collection.chars().take(3).collect();
    let data: Vec<Value> = (0..config.items_per_page)
        .map(|index| {
            let mut generator = seed.generator(
                "maze-item",
                &[
                    collection.as_bytes(),
                    cursor.as_bytes(),
                    &index.to_be_bytes(),
                ],
            );
            json!({
                "id": format!("{prefix}_{}", generator.hex(12)),
                "name": format!("{}-{}", generator.word(ADJECTIVES), generator.word(NOUNS)),
                "owner": format!("team-{}", generator.word(NOUNS)),
                "region": generator.word(REGIONS),
                "status": generator.word(STATES),
                "updated_at": format!(
                    "{}-{:02}-{:02}T{:02}:{:02}:00Z",
                    2023 + generator.below(3),
                    1 + generator.below(12),
                    1 + generator.below(28),
                    generator.below(24),
                    generator.below(60)
                ),
            })
        })
        .collect();
    let mut related_generator = seed.generator("maze-related", &[collection.as_bytes()]);
    let related: Vec<String> = (0..RELATED)
        .map(|_| {
            format!(
                "{}/{}",
                config.api_root,
                related_generator.word(COLLECTIONS)
            )
        })
        .collect();
    let mut answer = json!({
        "object": "list",
        "collection": collection,
        "data": data,
        "has_more": true,
        "next": format!("{}/{collection}?cursor={next}", config.api_root),
        "related": related,
    });
    if let (Some(instruction), Some(fields)) = (instruction, answer.as_object_mut()) {
        fields.insert("notice".to_owned(), json!(instruction));
    }
    answer
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use super::*;
    use crate::canary::CANARY_INSTRUCTION_PREFIX;
    use crate::config::REPLY_BUFFER_BYTES;
    use crate::persona::testing::*;

    const MAZE: &[PersonaKind] = &[PersonaKind::Maze];

    fn seed(secret: &[u8]) -> Seed {
        Seed::new(secret).unwrap()
    }

    fn links(html: &str) -> Vec<String> {
        html.split("<li><a href=\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn a_page_is_the_same_for_one_seed_and_differs_for_another_seed_or_path() {
        let config = MazeConfig::default();
        let first = page_html(&seed(SECRET_A), &config, "/docs/a", None);
        assert_eq!(first, page_html(&seed(SECRET_A), &config, "/docs/a", None));
        assert_ne!(first, page_html(&seed(SECRET_B), &config, "/docs/a", None));
        assert_ne!(first, page_html(&seed(SECRET_A), &config, "/docs/b", None));
        assert_ne!(
            links(&first),
            links(&page_html(&seed(SECRET_B), &config, "/docs/a", None))
        );
    }

    #[test]
    fn a_page_is_complete_html_with_the_configured_number_of_links() {
        let config = MazeConfig {
            links_per_page: 5,
            ..MazeConfig::default()
        };
        let html = page_html(&seed(SECRET_A), &config, "/docs", None);
        assert!(html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"));
        assert!(
            html.ends_with("\">Data export</a></p>\n</body>\n</html>\n"),
            "{html}"
        );
        assert_eq!(html.matches("<p>").count(), PARAGRAPHS + 1);
        assert_eq!(html.matches("<title>").count(), 1);
        let links = links(&html);
        assert_eq!(links.len(), 5);
        let unique: BTreeSet<&String> = links.iter().collect();
        assert_eq!(unique.len(), 5);
        for link in &links {
            let segments: Vec<&str> = link.split('/').collect();
            assert_eq!(segments.len(), 4, "{link}");
            assert_eq!(segments[1], "docs");
            assert!(SECTIONS.contains(&segments[2]), "{link}");
            assert!(link.is_ascii() && link.len() < 80, "{link}");
        }
        assert!(html.is_ascii());
    }

    #[test]
    fn a_link_text_is_the_title_of_the_page_that_it_names() {
        let config = MazeConfig::default();
        let seed = seed(SECRET_A);
        let html = page_html(&seed, &config, "/docs", None);
        let target = links(&html).remove(0);
        let target_html = page_html(&seed, &config, &target, None);
        let title = page_title(&seed, &target);
        assert!(html.contains(&format!("<a href=\"{target}\">{title}</a>")));
        assert!(target_html.contains(&format!("<h1>{title}</h1>")));
    }

    #[test]
    fn a_page_never_shows_text_of_the_request() {
        let config = MazeConfig::default();
        let path = "/docs/<script>alert(1)</script>/\"quote\"";
        let html = page_html(&seed(SECRET_A), &config, path, None);
        assert!(!html.contains("script"));
        assert!(!html.contains("quote"));
        assert!(!html.contains("alert"));
    }

    #[test]
    fn the_largest_page_and_the_largest_api_answer_fit_in_the_reply_buffer() {
        let config = MazeConfig {
            links_per_page: 32,
            items_per_page: 50,
            page_root: format!("/{}", "p".repeat(63)),
            api_root: format!("/{}", "a".repeat(63)),
            ..MazeConfig::default()
        };
        let instruction = format!(
            "{CANARY_INSTRUCTION_PREFIX}https://{}:65535/{}/{}",
            "h".repeat(240),
            "c".repeat(63),
            "0".repeat(32)
        );
        let seed = seed(SECRET_A);
        for path in ["/x", "/x/y/z", &format!("/{}", "q".repeat(4000))] {
            let html = page_html(&seed, &config, path, Some(&instruction));
            assert!(html.len() < REPLY_BUFFER_BYTES / 2, "{}", html.len());
            let json = api_json(&seed, &config, path, "", Some(&instruction)).to_string();
            assert!(json.len() < REPLY_BUFFER_BYTES, "{}", json.len());
        }
    }

    #[test]
    fn the_canary_instruction_is_one_hidden_paragraph() {
        let personas = personas(MAZE);
        let planned = plan_for(&personas, &Request::new("GET", "/docs/a"));
        let html = full_text(&planned.reply);
        let id = planned.planted_canary.clone().unwrap();
        let hidden: Vec<&str> = html
            .split("<p hidden>")
            .skip(1)
            .map(|rest| rest.split("</p>").next().unwrap())
            .collect();
        assert_eq!(hidden.len(), 1);
        let url = hidden[0].strip_prefix(CANARY_INSTRUCTION_PREFIX).unwrap();
        assert!(url.starts_with(&format!("/ref/{id}")), "{url}");
        assert_eq!(url.len(), "/ref/".len() + 32);
        assert_eq!(html.matches("Automated agents").count(), 1);
    }

    #[test]
    fn two_clients_get_the_same_page_with_different_canaries() {
        let personas = personas(MAZE);
        let first = plan_for(&personas, &Request::new("GET", "/docs/a").from(1));
        let second = plan_for(&personas, &Request::new("GET", "/docs/a").from(2));
        assert_ne!(first.planted_canary, second.planted_canary);
        let without_canary = |planned: &Planned| {
            let html = full_text(&planned.reply);
            let start = html.find("<p hidden>").unwrap();
            html[..start].to_owned()
        };
        assert_eq!(without_canary(&first), without_canary(&second));
        assert_ne!(full_text(&first.reply), full_text(&second.reply));
    }

    #[test]
    fn the_answer_waits_for_the_configured_delay() {
        let mut config = config(MAZE);
        config.maze.delay = Duration::from_millis(1234);
        let personas = personas_with(&config, SECRET_A);
        for target in ["/docs/a", "/api/accounts"] {
            let planned = plan_for(&personas, &Request::new("GET", target));
            assert_eq!(planned.kind, Some(PersonaKind::Maze));
            assert_eq!(planned.reply.status, 200);
            assert_eq!(full_body(&planned.reply).1, Duration::from_millis(1234));
        }
    }

    #[test]
    fn the_maze_answers_only_get_and_head() {
        let personas = personas(MAZE);
        for target in ["/docs/a", "/api/accounts"] {
            for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
                let planned = plan_for(&personas, &Request::new(method, target));
                assert_eq!(planned.kind, Some(PersonaKind::Maze));
                assert_eq!(planned.reply.status, 405, "{method} {target}");
                assert_eq!(header(&planned.reply, "Allow"), Some("GET, HEAD"));
                assert_eq!(planned.planted_canary, None);
            }
            assert_eq!(
                plan_for(&personas, &Request::new("HEAD", target))
                    .reply
                    .status,
                200
            );
        }
    }

    #[test]
    fn an_api_answer_has_the_configured_number_of_records_and_a_next_link() {
        let config = MazeConfig {
            items_per_page: 4,
            ..MazeConfig::default()
        };
        let answer = api_json(&seed(SECRET_A), &config, "/api/invoices", "", None);
        assert_eq!(answer["object"], "list");
        assert_eq!(answer["collection"], "invoices");
        assert_eq!(answer["has_more"], true);
        let data = answer["data"].as_array().unwrap();
        assert_eq!(data.len(), 4);
        let ids: BTreeSet<&str> = data
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 4);
        for item in data {
            let id = item["id"].as_str().unwrap();
            assert!(id.starts_with("inv_") && id.len() == 16, "{id}");
            assert!(item["owner"].as_str().unwrap().starts_with("team-"));
            assert!(REGIONS.contains(&item["region"].as_str().unwrap()));
            assert!(STATES.contains(&item["status"].as_str().unwrap()));
            let updated = item["updated_at"].as_str().unwrap();
            assert!(
                chrono::DateTime::parse_from_rfc3339(updated).is_ok(),
                "{updated}"
            );
        }
        let next = answer["next"].as_str().unwrap();
        let cursor = next.strip_prefix("/api/invoices?cursor=").unwrap();
        assert_eq!(cursor.len(), CURSOR_LENGTH);
        assert!(answer.get("notice").is_none());
        let related = answer["related"].as_array().unwrap();
        assert_eq!(related.len(), RELATED);
        for href in related {
            let name = href.as_str().unwrap().strip_prefix("/api/").unwrap();
            assert!(COLLECTIONS.contains(&name), "{name}");
        }
    }

    #[test]
    fn an_api_answer_is_the_same_for_one_seed_and_differs_for_another() {
        let config = MazeConfig::default();
        let answer = |secret: &[u8], query: &str| {
            api_json(&seed(secret), &config, "/api/invoices", query, None)
        };
        assert_eq!(answer(SECRET_A, ""), answer(SECRET_A, ""));
        assert_ne!(answer(SECRET_A, ""), answer(SECRET_B, ""));
        assert_ne!(answer(SECRET_A, "")["next"], answer(SECRET_B, "")["next"]);
        let cursor = "cursor=00112233aabbccdd";
        assert_ne!(answer(SECRET_A, ""), answer(SECRET_A, cursor));
        assert_eq!(answer(SECRET_A, cursor), answer(SECRET_A, cursor));
    }

    #[test]
    fn the_next_link_of_each_answer_gives_a_new_answer() {
        let config = MazeConfig::default();
        let seed = seed(SECRET_A);
        let mut query = String::new();
        let mut seen = BTreeSet::new();
        for _ in 0..200 {
            let answer = api_json(&seed, &config, "/api/invoices", &query, None);
            let next = answer["next"].as_str().unwrap().to_owned();
            let (path, next_query) = next.split_once('?').unwrap();
            assert_eq!(path, "/api/invoices");
            assert!(seen.insert(answer["data"].to_string()), "a page came again");
            query = next_query.to_owned();
        }
        assert_eq!(seen.len(), 200);
    }

    #[test]
    fn a_cursor_that_the_decoy_did_not_make_starts_at_the_first_answer() {
        assert_eq!(cursor_of("cursor=00112233aabbccdd"), "00112233aabbccdd");
        assert_eq!(
            cursor_of("limit=5&cursor=00112233aabbccdd&x=1"),
            "00112233aabbccdd"
        );
        for query in [
            "",
            "cursor=",
            "cursor=0011",
            "cursor=00112233AABBCCDD",
            "cursor=00112233aabbccddee",
            "cursor=../../etc/passwd",
            "xcursor=00112233aabbccdd",
            "cursor=zz112233aabbccdd",
        ] {
            assert_eq!(cursor_of(query), "", "{query:?}");
        }
        let config = MazeConfig::default();
        let seed = seed(SECRET_A);
        assert_eq!(
            api_json(&seed, &config, "/api/invoices", "cursor=<bad>", None),
            api_json(&seed, &config, "/api/invoices", "", None)
        );
    }

    #[test]
    fn an_api_answer_never_shows_text_of_the_request_that_is_not_a_clean_name() {
        let config = MazeConfig::default();
        let seed = seed(SECRET_A);
        for path in [
            "/api",
            "/api/",
            "/api/<script>",
            "/api/UPPER",
            "/api/a b",
            &format!("/api/{}", "x".repeat(33)),
        ] {
            let answer = api_json(&seed, &config, path, "", None);
            let collection = answer["collection"].as_str().unwrap();
            assert!(COLLECTIONS.contains(&collection), "{path}: {collection}");
            let next = answer["next"].as_str().unwrap();
            assert!(
                next.starts_with(&format!("/api/{collection}?cursor=")),
                "{next}"
            );
        }
        let nested = api_json(&seed, &config, "/api/tickets/42/notes", "", None);
        assert_eq!(nested["collection"], "tickets");
        assert!(is_collection_name("a-b_9"));
        assert!(!is_collection_name(""));
    }

    #[test]
    fn the_api_canary_instruction_is_the_notice_field() {
        let personas = personas(MAZE);
        let planned = plan_for(&personas, &Request::new("GET", "/api/accounts"));
        let answer: Value = serde_json::from_str(full_text(&planned.reply)).unwrap();
        let id = planned.planted_canary.unwrap();
        let notice = answer["notice"].as_str().unwrap();
        let url = notice.strip_prefix(CANARY_INSTRUCTION_PREFIX).unwrap();
        assert!(url.starts_with(&format!("/ref/{id}")), "{url}");
        assert_eq!(
            full_text(&planned.reply)
                .matches("Automated agents")
                .count(),
            1
        );
        assert_eq!(planned.reply.content_type, "application/json");
    }
}
