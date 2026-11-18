//! Tests of the maze persona: generated pages, onward links, and the endless JSON API.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use aegis_decoy::{DecoyConfig, DecoyService, PersonaKind};
use common::*;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

fn maze_config() -> DecoyConfig {
    config(&[PersonaKind::Maze])
}

fn service_with_seed(seed: &'static str) -> DecoyService {
    DecoyService::with_env(maze_config(), env(seed)).unwrap()
}

/// Returns the targets of the links in the list of related pages.
fn page_links(html: &str) -> Vec<String> {
    html.split("<li><a href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap().to_owned())
        .collect()
}

/// Returns the page without the hidden paragraph that holds the canary instruction.
fn visible(html: &str) -> String {
    let start = html.find("<p hidden>").expect("a hidden paragraph");
    let end = start + html[start..].find("</p>\n").unwrap() + "</p>\n".len();
    format!("{}{}", &html[..start], &html[end..])
}

#[tokio::test(start_paused = true)]
async fn a_page_is_the_same_for_one_seed_and_differs_for_another_seed() {
    let first = service_with_seed(SEED_A);
    let second = service_with_seed(SEED_A);
    let other = service_with_seed(SEED_B);

    let page = get(&first, peer(1), "/docs/runbooks/start").await;
    assert_eq!(page.status, 200);
    assert_eq!(
        page.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let again = get(&first, peer(1), "/docs/runbooks/start").await;
    let same_seed = get(&second, peer(1), "/docs/runbooks/start").await;
    let other_seed = get(&other, peer(1), "/docs/runbooks/start").await;
    let other_path = get(&first, peer(1), "/docs/runbooks/other").await;

    // One seed gives the same bytes, in the same service and in a new service.
    assert_eq!(page.body, again.body);
    assert_eq!(page.body, same_seed.body);
    // A different seed gives different content, not only a different canary.
    assert_ne!(visible(&page.text()), visible(&other_seed.text()));
    assert_ne!(page_links(&page.text()), page_links(&other_seed.text()));
    assert_ne!(visible(&page.text()), visible(&other_path.text()));
}

#[tokio::test(start_paused = true)]
async fn a_page_is_complete_html_that_links_only_to_paths_on_the_decoy() {
    let service = service(maze_config());
    let page = get(&service, peer(1), "/docs").await;
    let html = page.text();
    assert!(
        html.starts_with("<!DOCTYPE html>\n<html lang=\"en\">"),
        "{html}"
    );
    assert!(html.ends_with("</body>\n</html>\n"), "{html}");
    assert_eq!(page_links(&html).len(), 8);
    // Each link on the page is a path on this decoy.
    let hrefs: Vec<&str> = html
        .split("href=\"")
        .skip(1)
        .map(|rest| rest.split('"').next().unwrap())
        .collect();
    assert_eq!(hrefs.len(), 10, "{hrefs:?}");
    for href in &hrefs {
        assert!(
            href.starts_with("/docs") || href.starts_with("/api/"),
            "{href}"
        );
        assert!(!href.starts_with("//") && !href.contains("://"), "{href}");
    }
    assert!(!html.contains("src="), "the page loads nothing");
    assert!(!html.contains("<script"), "the page has no script");
}

#[tokio::test(start_paused = true)]
async fn the_pages_link_onward_for_1000_steps_with_bounded_memory() {
    let mut config = maze_config();
    // Nothing reads the events in this test. A small queue shows that the memory of the
    // recorded data has a limit too.
    config.events.max_queued = 16;
    let service = service(config);

    let mut path = "/docs".to_owned();
    let mut visited = BTreeSet::new();
    let mut tracked_after_full = BTreeSet::new();
    let started = Instant::now();
    for step in 0..1000_usize {
        assert!(
            visited.insert(path.clone()),
            "step {step} came back to {path}"
        );
        let page = get(&service, peer(1), &path).await;
        assert_eq!(page.status, 200, "step {step}: {path}");
        let links = page_links(&page.text());
        assert_eq!(links.len(), 8, "step {step}: {path}");
        // The path does not grow from page to page.
        assert!(links.iter().all(|link| link.len() < 80), "{links:?}");
        path = links[step % links.len()].clone();
        if step >= 16 {
            tracked_after_full.insert(service.stats().tracked_bytes);
        }
    }
    assert_eq!(visited.len(), 1000);
    // Each answer waited for the configured delay of the maze.
    assert_eq!(started.elapsed(), Duration::from_millis(500) * 1000);

    let stats = service.stats();
    assert_eq!(stats.requests, 1000);
    assert_eq!(stats.active_connections, 0);
    assert_eq!(stats.peak_connections, 1);
    // A contact can use three quarters of the queue: 12 events. The decoy dropped and
    // counted all other events.
    assert_eq!(stats.events_queued, 12);
    assert_eq!(stats.events_dropped, 988);
    // The memory did not grow after the queue was full.
    assert_eq!(tracked_after_full.len(), 1, "{tracked_after_full:?}");
    assert!(stats.tracked_bytes < 16 * 2048, "{}", stats.tracked_bytes);
    assert!(
        stats.peak_tracked_bytes < 64 * 1024,
        "{}",
        stats.peak_tracked_bytes
    );
    assert!(stats.peak_tracked_bytes <= service.memory_bound());
}

#[tokio::test(start_paused = true)]
async fn the_json_api_always_has_a_next_page() {
    let service = service(maze_config());
    let mut target = "/api/invoices".to_owned();
    let mut seen = BTreeSet::new();
    for step in 0..300 {
        let answer = get(&service, peer(1), &target).await;
        assert_eq!(answer.status, 200, "step {step}: {target}");
        assert_eq!(answer.header("content-type"), Some("application/json"));
        let json = answer.json();
        assert_eq!(json["object"], "list");
        assert_eq!(json["collection"], "invoices");
        assert_eq!(json["has_more"], true);
        let data = json["data"].as_array().unwrap();
        assert_eq!(data.len(), 10);
        assert!(
            seen.insert(data[0]["id"].as_str().unwrap().to_owned()),
            "step {step}"
        );
        let next = json["next"].as_str().expect("a next link").to_owned();
        assert!(next.starts_with("/api/invoices?cursor="), "{next}");
        assert_ne!(next, target);
        target = next;
    }
    assert_eq!(seen.len(), 300);
}

#[tokio::test(start_paused = true)]
async fn the_json_api_is_the_same_for_one_seed_and_differs_for_another_seed() {
    let without_notice = |mut json: serde_json::Value| {
        json.as_object_mut()
            .unwrap()
            .remove("notice")
            .expect("a notice");
        json
    };
    let first = get(&service_with_seed(SEED_A), peer(1), "/api/devices").await;
    let again = get(&service_with_seed(SEED_A), peer(1), "/api/devices").await;
    let other = get(&service_with_seed(SEED_B), peer(1), "/api/devices").await;
    assert_eq!(first.body, again.body);
    assert_ne!(without_notice(first.json()), without_notice(other.json()));
    assert_ne!(first.json()["next"], other.json()["next"]);
}

#[tokio::test(start_paused = true)]
async fn a_page_links_to_the_json_api_and_the_api_links_to_more_collections() {
    let service = service(maze_config());
    let html = get(&service, peer(1), "/docs").await.text();
    let export = html
        .split("<p><a href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a data export link");
    assert!(export.starts_with("/api/"), "{export}");
    let json = get(&service, peer(1), export).await.json();
    let related = json["related"].as_array().unwrap();
    assert_eq!(related.len(), 3);
    for href in related {
        let answer = get(&service, peer(1), href.as_str().unwrap()).await;
        assert_eq!(answer.status, 200);
        assert!(answer.json()["next"].is_string());
    }
}

#[tokio::test(start_paused = true)]
async fn the_answer_comes_after_the_configured_delay_and_the_event_has_the_time() {
    let mut config = maze_config();
    config.maze.delay = Duration::from_millis(750);
    let service = service(config);
    let (mut client, server) = connect(&service, peer(1));
    let start = Instant::now();
    client
        .write_all(&get_request("/docs/a", "User-Agent: crawler/2\r\n"))
        .await
        .unwrap();
    let timeline = read_timeline(&mut client, start).await;
    drop(client);
    server.await.unwrap();
    // The full answer comes in one write, after the delay.
    assert_eq!(timeline.len(), 1);
    assert_eq!(timeline[0].0, Duration::from_millis(750));
    let response = parse_response(&timeline[0].1);
    assert_eq!(
        response
            .header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        response.body.len()
    );

    let events = events(&service, 1).await;
    let event = &events[0];
    assert_eq!(event.action, "decoy.contact");
    assert_eq!(event.attribute_str("decoy_kind"), Some("maze"));
    assert_eq!(event.attribute_str("decoy_result"), Some("completed"));
    assert_eq!(event.attribute_str("http_path"), Some("/docs/a"));
    assert_eq!(number(event, "held_milliseconds"), 750);
    assert_eq!(number(event, "http_status"), 200);
    assert_eq!(event.actor.user_agent.as_deref(), Some("crawler/2"));
}

#[tokio::test(start_paused = true)]
async fn the_delay_never_holds_a_client_for_longer_than_the_hold_limit() {
    let mut config = maze_config();
    config.maze.delay = Duration::from_secs(60);
    config.limits.max_hold = Duration::from_secs(5);
    let service = service(config);
    let start = Instant::now();
    let page = get(&service, peer(1), "/docs").await;
    assert_eq!(page.status, 200);
    assert_eq!(start.elapsed(), Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn with_no_tarpit_the_root_sends_the_client_into_the_maze() {
    let service = service(maze_config());
    let root = get(&service, peer(1), "/").await;
    assert_eq!(root.status, 302);
    assert_eq!(root.header("location"), Some("/docs"));
    let missing = get(&service, peer(1), "/no-such-path").await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.text(), "404 Not Found\n");
    let post = exchange(
        &service,
        peer(1),
        b"POST /docs HTTP/1.1\r\nHost: decoy.test\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let post = parse_response(&post);
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow"), Some("GET, HEAD"));

    let events = events(&service, 3).await;
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event.attribute_str("decoy_kind").unwrap())
        .collect();
    assert_eq!(kinds, ["maze", "listener", "maze"]);
    let statuses: Vec<u64> = events
        .iter()
        .map(|event| number(event, "http_status"))
        .collect();
    assert_eq!(statuses, [302, 404, 405]);
}
