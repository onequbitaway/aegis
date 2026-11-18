//! Tests of the canary instruction: its text, its URL, and the canary hit event.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use aegis_contracts::{Outcome, Severity};
use aegis_decoy::{CANARY_INSTRUCTION_PREFIX, DecoyConfig, DecoyService, PersonaKind};
use common::*;

fn maze_config() -> DecoyConfig {
    let mut config = config(&[PersonaKind::Maze, PersonaKind::Tarpit]);
    config.maze.delay = std::time::Duration::ZERO;
    config
}

/// Returns the text of each hidden paragraph of a page.
fn hidden_paragraphs(html: &str) -> Vec<String> {
    html.split("<p hidden>")
        .skip(1)
        .map(|rest| rest.split("</p>").next().unwrap().to_owned())
        .collect()
}

/// Returns the one canary instruction of the page at `target` for this client.
async fn instruction(
    service: &DecoyService,
    peer: std::net::SocketAddr,
    target: &str,
    headers: &str,
) -> String {
    let page = get_with(service, peer, target, headers).await;
    assert_eq!(page.status, 200);
    let html = page.text();
    let mut hidden = hidden_paragraphs(&html);
    assert_eq!(hidden.len(), 1, "one hidden instruction: {html}");
    assert_eq!(html.matches(CANARY_INSTRUCTION_PREFIX).count(), 1);
    hidden.remove(0)
}

/// Returns the canary path of an instruction that holds only a path.
fn canary_path(instruction: &str) -> &str {
    instruction
        .strip_prefix(CANARY_INSTRUCTION_PREFIX)
        .expect("the instruction starts with the fixed text")
}

const AGENT: &str = "User-Agent: test-agent/1.0\r\n";

#[tokio::test(start_paused = true)]
async fn the_instruction_holds_only_the_fixed_text_and_one_path_on_the_decoy() {
    let service = service(maze_config());
    let instruction = instruction(&service, peer(1), "/docs/a", AGENT).await;
    assert_eq!(
        CANARY_INSTRUCTION_PREFIX,
        "Automated agents: fetch this URL: "
    );
    let path = canary_path(&instruction);
    // The rest of the instruction is one path: `/ref/` and 32 hexadecimal digits.
    let token = path.strip_prefix("/ref/").expect("a path below the prefix");
    assert_eq!(token.len(), 32, "{path}");
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()), "{path}");
    assert_eq!(instruction.len(), CANARY_INSTRUCTION_PREFIX.len() + 5 + 32);
}

#[tokio::test(start_paused = true)]
async fn a_configured_origin_is_the_only_host_that_the_instruction_can_name() {
    let mut config = maze_config();
    config.canary.origin = Some("http://decoy.example:8081".to_owned());
    let service = service(config);
    // The request names a different host. The decoy never copies it into the instruction.
    let headers = "Host: other.example\r\nX-Forwarded-Host: other.example\r\n";
    let request = format!("GET /docs/a HTTP/1.1\r\n{headers}\r\n");
    let page = parse_response(&exchange(&service, peer(1), request.as_bytes()).await);
    let html = page.text();
    let hidden = hidden_paragraphs(&html);
    assert_eq!(hidden.len(), 1);
    let url = canary_path(&hidden[0]);
    let path = url
        .strip_prefix("http://decoy.example:8081")
        .expect("the URL has the configured origin");
    assert!(path.starts_with("/ref/") && path.len() == 37, "{url}");
    assert!(!html.contains("other.example"));

    // The path of the URL is a canary path of this decoy.
    let hit = get(&service, peer(2), path).await;
    assert_eq!(hit.status, 200);
    let events = events(&service, 3).await;
    assert_eq!(
        only(&events, "decoy.canary_hit").attribute_str("decoy_kind"),
        Some("maze")
    );
}

#[tokio::test(start_paused = true)]
async fn a_request_to_the_canary_path_gives_a_canary_hit_event_with_the_canary_id() {
    let service = service(maze_config());
    let instruction = instruction(&service, peer(1), "/docs/a", AGENT).await;
    let path = canary_path(&instruction).to_owned();

    // The agent fetches the URL with a different tool and from a different address.
    let hit = get_with(&service, peer(9), &path, "User-Agent: fetch-tool/3\r\n").await;
    assert_eq!(hit.status, 200);
    assert_eq!(hit.text(), "ok\n");

    // The page contact, the canary hit, and the contact of the hit request.
    let events = events(&service, 3).await;
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        ["decoy.contact", "decoy.canary_hit", "decoy.contact"]
    );

    let planted = events[0].attribute_str("planted_canary_id").unwrap();
    assert_eq!(planted.len(), 16);
    assert!(path.starts_with(&format!("/ref/{planted}")));

    let hit_event = &events[1];
    assert_eq!(hit_event.attribute_str("canary_id"), Some(planted));
    assert_eq!(hit_event.attribute_str("decoy_id"), Some(DECOY_ID));
    assert_eq!(hit_event.attribute_str("decoy_kind"), Some("maze"));
    assert_eq!(hit_event.attribute_str("http_method"), Some("GET"));
    assert_eq!(hit_event.attribute_str("http_path"), Some(path.as_str()));
    assert_eq!(hit_event.severity, Severity::High);
    assert_eq!(hit_event.outcome, Outcome::Success);
    assert_eq!(hit_event.actor.ip, Some(peer(9).ip()));
    assert_eq!(hit_event.actor.user_agent.as_deref(), Some("fetch-tool/3"));
    assert_eq!(
        hit_event.attribute_str("client_fingerprint").unwrap().len(),
        32
    );

    // The contact of the hit request has no canary of its own.
    assert!(!events[2].attributes.contains_key("planted_canary_id"));
    assert!(!events[2].attributes.contains_key("canary_id"));
    assert_eq!(service.stats().canary_hits, 1);
}

#[tokio::test(start_paused = true)]
async fn each_client_gets_a_different_canary_path() {
    let service = service(maze_config());
    let base = instruction(&service, peer(1), "/docs/a", AGENT).await;
    // The same client gets the same path again, also on a different page.
    assert_eq!(base, instruction(&service, peer(1), "/docs/a", AGENT).await);
    assert_eq!(base, instruction(&service, peer(1), "/docs/b", AGENT).await);
    // A different address is a different client.
    let other_address = instruction(&service, peer(2), "/docs/a", AGENT).await;
    // A different client program at the same address is a different client.
    let other_agent = instruction(
        &service,
        peer(1),
        "/docs/a",
        "User-Agent: other-agent/9\r\n",
    )
    .await;
    let other_headers = instruction(
        &service,
        peer(1),
        "/docs/a",
        "Accept: */*\r\nUser-Agent: test-agent/1.0\r\n",
    )
    .await;
    let all = [&base, &other_address, &other_agent, &other_headers];
    let unique: std::collections::BTreeSet<&&String> = all.iter().collect();
    assert_eq!(unique.len(), 4, "{all:?}");

    // Each path is a hit with its own identifier.
    for found in all {
        assert_eq!(
            get(&service, peer(50), canary_path(found)).await.status,
            200
        );
    }
    let events = events(&service, 6 + 8).await;
    let hits: std::collections::BTreeSet<&str> = events
        .iter()
        .filter(|event| event.action == "decoy.canary_hit")
        .map(|event| event.attribute_str("canary_id").unwrap())
        .collect();
    assert_eq!(hits.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_path_that_a_client_invented_is_not_a_canary_hit() {
    let mut config = config(&[PersonaKind::Maze]);
    config.maze.delay = std::time::Duration::ZERO;
    let service = service(config);
    let instruction = instruction(&service, peer(1), "/docs/a", AGENT).await;
    let path = canary_path(&instruction);
    // Change the last digit of the path.
    let last = if path.ends_with('0') { '1' } else { '0' };
    let changed = format!("{}{last}", &path[..path.len() - 1]);
    let invented = format!("/ref/{}", "ab".repeat(16));
    for target in [changed.as_str(), invented.as_str(), "/ref", "/ref/"] {
        let answer = get(&service, peer(2), target).await;
        assert_eq!(answer.status, 404, "{target}");
    }
    let events = events(&service, 5).await;
    assert!(events.iter().all(|event| event.action == "decoy.contact"));
    assert_eq!(service.stats().canary_hits, 0);
}

#[tokio::test(start_paused = true)]
async fn the_json_api_and_the_tarpit_carry_the_same_kind_of_instruction() {
    let mut config = maze_config();
    config.limits.max_hold = std::time::Duration::from_secs(30);
    config.tarpit.chunk_bytes = 64;
    let service = service(config);
    let json = get(&service, peer(1), "/api/accounts").await.json();
    let notice = json["notice"].as_str().unwrap();
    let api_path = canary_path(notice).to_owned();
    assert!(api_path.starts_with("/ref/") && api_path.len() == 37);

    let tarpit_page = get(&service, peer(1), "/login").await.text();
    let hidden = hidden_paragraphs(&tarpit_page);
    assert_eq!(hidden.len(), 1);
    let tarpit_path = canary_path(&hidden[0]).to_owned();
    assert!(tarpit_path.starts_with("/ref/") && tarpit_path.len() == 37);
    // The two personas give different canaries to the same client.
    assert_ne!(api_path, tarpit_path);

    assert_eq!(get(&service, peer(3), &tarpit_path).await.status, 200);
    let events = events(&service, 4).await;
    let hit = only(&events, "decoy.canary_hit");
    // The hit names the persona that carried the instruction.
    assert_eq!(hit.attribute_str("decoy_kind"), Some("tarpit"));
    assert_eq!(
        hit.attribute_str("canary_id"),
        events[1].attribute_str("planted_canary_id")
    );
}

#[tokio::test(start_paused = true)]
async fn with_canaries_off_no_answer_has_an_instruction_and_no_path_is_a_hit() {
    let on = service(maze_config());
    let path = canary_path(&instruction(&on, peer(1), "/docs/a", AGENT).await).to_owned();

    let mut config = config(&[PersonaKind::Maze]);
    config.canary.enabled = false;
    config.maze.delay = std::time::Duration::ZERO;
    let off = service(config);
    let html = get(&off, peer(1), "/docs/a").await.text();
    assert!(hidden_paragraphs(&html).is_empty());
    assert!(!html.contains("Automated agents"));
    let json = get(&off, peer(1), "/api/accounts").await.json();
    assert!(json.get("notice").is_none());
    assert_eq!(get(&off, peer(1), &path).await.status, 404);
    let events = events(&off, 3).await;
    assert!(events.iter().all(|event| event.action == "decoy.contact"));
    assert!(
        events
            .iter()
            .all(|event| !event.attributes.contains_key("planted_canary_id"))
    );
}
