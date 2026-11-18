//! The web console: the page, the files, and the rules that keep it on its own origin.

use std::collections::BTreeSet;

use aegis_api::{
    API_CONTENT_SECURITY_POLICY, CONSOLE_CONTENT_SECURITY_POLICY, ConsoleAsset, console_assets,
};
use axum::http::{Method, StatusCode};
use serde_json::json;

use crate::support::{TestApi, VIEWER, config, get, request, send};

/// The name of the SVG namespace. It is an identifier. A browser does not request it.
const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";

fn asset(path: &str) -> &'static ConsoleAsset {
    console_assets()
        .iter()
        .find(|asset| asset.path == path)
        .unwrap_or_else(|| panic!("the console has no file {path}"))
}

/// Returns the URL of a console file.
fn url_of(asset: &ConsoleAsset) -> String {
    if asset.path == "index.html" {
        "/".to_owned()
    } else {
        format!("/assets/{}", asset.path)
    }
}

#[tokio::test]
async fn the_page_and_each_file_load_with_the_console_policy() {
    let api = TestApi::new();
    let router = api.router();
    let assets = console_assets();
    assert!(assets.len() >= 10, "{} files", assets.len());
    for asset in assets {
        let url = url_of(asset);
        let reply = send(&router, request(Method::GET, &url, None, None)).await;
        assert_eq!(reply.status, StatusCode::OK, "{url}");
        assert_eq!(
            reply.header("content-type"),
            Some(asset.content_type),
            "{url}"
        );
        assert_eq!(
            reply.header("content-security-policy"),
            Some(CONSOLE_CONTENT_SECURITY_POLICY),
            "{url}"
        );
        assert_eq!(
            reply.header("x-content-type-options"),
            Some("nosniff"),
            "{url}"
        );
        assert_eq!(reply.header("x-frame-options"), Some("DENY"), "{url}");
        assert_eq!(
            reply.header("referrer-policy"),
            Some("no-referrer"),
            "{url}"
        );
        assert_eq!(reply.text(), asset.body, "{url}");
        assert!(!asset.body.trim().is_empty(), "{url} is empty");
    }
}

#[tokio::test]
async fn each_file_has_the_content_type_of_its_extension() {
    let assets = console_assets();
    assert!(!assets.is_empty());
    for asset in assets {
        let expected = match asset.path.rsplit('.').next().unwrap() {
            "html" => "text/html; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "js" => "text/javascript; charset=utf-8",
            "svg" => "image/svg+xml",
            other => panic!("{}: no content type for the extension {other}", asset.path),
        };
        assert_eq!(asset.content_type, expected, "{}", asset.path);
    }
}

/// Returns the values of one attribute in an HTML text, for example `src`.
fn attribute_values(html: &str, name: &str) -> Vec<String> {
    let marker = format!(" {name}=\"");
    html.match_indices(&marker)
        .map(|(start, _)| {
            let rest = &html[start + marker.len()..];
            rest[..rest.find('"').unwrap()].to_owned()
        })
        .collect()
}

/// Returns the module paths that a JavaScript file imports.
fn imports(script: &str) -> Vec<String> {
    script
        .lines()
        .filter(|line| line.trim_start().starts_with("import "))
        .map(|line| {
            let from = line.rfind(" from '").expect("an import with a path");
            let rest = &line[from + " from '".len()..];
            rest[..rest.find('\'').unwrap()].to_owned()
        })
        .collect()
}

/// Resolves a relative module path against the file that imports it.
fn resolve(importer: &str, path: &str) -> String {
    let mut parts: Vec<&str> = importer.split('/').collect();
    parts.pop();
    for part in path.split('/') {
        match part {
            "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    parts.join("/")
}

#[test]
fn each_reference_of_the_console_is_a_file_of_the_console() {
    let paths: BTreeSet<&str> = console_assets().iter().map(|asset| asset.path).collect();
    let index = asset("index.html").body;

    let mut references = attribute_values(index, "src");
    references.extend(
        attribute_values(index, "href")
            .into_iter()
            .filter(|href| !href.starts_with('#')),
    );
    assert!(references.len() >= 3, "{references:?}");
    for reference in &references {
        let path = reference
            .strip_prefix("/assets/")
            .unwrap_or_else(|| panic!("{reference} is not below /assets/"));
        assert!(paths.contains(path), "index.html refers to {reference}");
    }

    let mut imported = 0;
    for script in console_assets()
        .iter()
        .filter(|asset| asset.path.ends_with(".js"))
    {
        for path in imports(script.body) {
            assert!(
                path.starts_with("./") || path.starts_with("../"),
                "{}: {path}",
                script.path
            );
            let resolved = resolve(script.path, &path);
            assert!(
                paths.contains(resolved.as_str()),
                "{} imports {path}",
                script.path
            );
            imported += 1;
        }
    }
    assert!(imported >= 10, "{imported} imports");

    // Each script file is in use: the page loads it, or a different script imports it.
    let used: BTreeSet<String> = console_assets()
        .iter()
        .filter(|asset| asset.path.ends_with(".js"))
        .flat_map(|script| {
            imports(script.body)
                .into_iter()
                .map(|path| resolve(script.path, &path))
        })
        .chain(
            references
                .iter()
                .map(|reference| reference.trim_start_matches("/assets/").to_owned()),
        )
        .collect();
    for path in paths.iter().filter(|path| **path != "index.html") {
        assert!(used.contains(*path), "no file refers to {path}");
    }
}

/// Returns each absolute or protocol-relative URL in a text.
fn external_references(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (start, _) in text.match_indices("//") {
        let before = &text[..start];
        let rest = &text[start + 2..];
        let end = rest
            .find(|character: char| character.is_whitespace() || "\"'`)<>".contains(character))
            .unwrap_or(rest.len());
        if let Some(head) = before.strip_suffix(':') {
            // An absolute URL: scheme, colon, two slashes.
            let scheme_start = head
                .rfind(|character: char| {
                    !(character.is_ascii_alphanumeric() || "+.-".contains(character))
                })
                .map_or(0, |index| index + 1);
            if scheme_start < head.len() {
                found.push(format!("{}://{}", &head[scheme_start..], &rest[..end]));
            }
        } else if before.ends_with(['"', '\'', '`', '(', '=']) && end > 0 {
            // A protocol-relative URL at the start of a string or of a CSS url().
            found.push(format!("//{}", &rest[..end]));
        }
    }
    found
}

#[test]
fn the_search_for_external_references_finds_each_form() {
    assert_eq!(
        external_references("a \"https://cdn.example/x.js\" b"),
        ["https://cdn.example/x.js"]
    );
    assert_eq!(
        external_references("url(//fonts.example/f.woff)"),
        ["//fonts.example/f.woff"]
    );
    assert_eq!(
        external_references("src='//evil.example/x'"),
        ["//evil.example/x"]
    );
    assert_eq!(
        external_references("ws://127.0.0.1/feed"),
        ["ws://127.0.0.1/feed"]
    );
    assert!(external_references("// A comment.\nconst a = b / c; // more").is_empty());
    assert!(external_references("fetch('/api/v1/status')").is_empty());
}

#[test]
fn no_file_of_the_console_refers_to_a_different_origin() {
    let assets = console_assets();
    assert!(!assets.is_empty());
    let mut namespace_uses = 0;
    for asset in assets {
        for reference in external_references(asset.body) {
            assert_eq!(
                reference, SVG_NAMESPACE,
                "{} refers to {reference}",
                asset.path
            );
            namespace_uses += 1;
        }
        for forbidden in ["@import", "sourceMappingURL", "sendBeacon", "importScripts"] {
            assert!(
                !asset.body.contains(forbidden),
                "{} uses {forbidden}",
                asset.path
            );
        }
    }
    // The search works: it finds the namespace of the SVG drawing and of the icon.
    assert_eq!(namespace_uses, 2);
}

#[test]
fn the_page_has_no_inline_script_no_inline_style_and_no_inline_handler() {
    let index = asset("index.html").body;
    let scripts: Vec<&str> = index
        .match_indices("<script")
        .map(|(start, _)| &index[start..start + index[start..].find("</script>").unwrap()])
        .collect();
    assert_eq!(scripts.len(), 1);
    for script in scripts {
        assert!(script.contains(" src=\"/assets/"), "{script}");
        assert!(script.contains("type=\"module\""), "{script}");
        assert!(
            script.trim_end().ends_with('>'),
            "a script with inline code: {script}"
        );
    }
    assert!(!index.contains("<style"));
    assert!(!index.contains(" style="));
    let lower = index.to_ascii_lowercase();
    for handler in [
        " onclick",
        " onload",
        " onerror",
        " onsubmit",
        " onfocus",
        " onmouseover",
    ] {
        assert!(!lower.contains(handler), "{handler}");
    }
    assert!(!lower.contains("javascript:"));
    assert!(!lower.contains("<iframe"));
    assert!(!lower.contains("<base"));
}

#[test]
fn the_scripts_build_the_page_without_markup_from_text() {
    let scripts: Vec<&ConsoleAsset> = console_assets()
        .iter()
        .filter(|asset| asset.path.ends_with(".js"))
        .collect();
    assert!(scripts.len() >= 8, "{} scripts", scripts.len());
    let sinks = [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "createContextualFragment",
        "DOMParser",
        "setHTMLUnsafe",
        "srcdoc",
        "eval(",
        "new Function",
        "setTimeout(\"",
        "setTimeout('",
        "javascript:",
        "localStorage",
        "document.cookie",
    ];
    for script in scripts {
        for sink in sinks {
            assert!(!script.body.contains(sink), "{} uses {sink}", script.path);
        }
    }
}

#[tokio::test]
async fn a_file_that_the_console_does_not_have_is_a_404() {
    let api = TestApi::new();
    let router = api.router();
    for path in [
        "/assets/missing.js",
        "/assets/index.html",
        "/assets/../Cargo.toml",
        "/assets/js/../../../Cargo.toml",
        "/assets/%2e%2e/%2e%2e/Cargo.toml",
        "/assets/js/",
        "/index.html",
        "/favicon.ico",
    ] {
        let reply = send(&router, request(Method::GET, path, None, None)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.error_code(), "not_found", "{path}");
        assert!(!reply.text().contains("[package]"), "{path}");
    }
}

#[tokio::test]
async fn the_console_can_be_off() {
    let api = TestApi::new();
    let mut config = config();
    config.console = false;
    let router = api.router_with(&config);
    for path in ["/", "/assets/console.css"] {
        let reply = send(&router, request(Method::GET, path, None, None)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    let reply = get(&router, "/api/v1/session", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn a_response_that_is_not_a_console_file_has_the_policy_that_loads_nothing() {
    let api = TestApi::new();
    let router = api.router();
    for (path, token, status) in [
        ("/healthz", None, StatusCode::OK),
        ("/api/v1/session", Some(VIEWER), StatusCode::OK),
        ("/api/v1/session", None, StatusCode::UNAUTHORIZED),
        ("/api/v1/audit", Some(VIEWER), StatusCode::FORBIDDEN),
        ("/nothing", None, StatusCode::NOT_FOUND),
    ] {
        let reply = send(&router, request(Method::GET, path, token, None)).await;
        assert_eq!(reply.status, status, "{path}");
        assert_eq!(
            reply.header("content-security-policy"),
            Some(API_CONTENT_SECURITY_POLICY),
            "{path}"
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{path}");
        assert_eq!(
            reply.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(reply.header("x-frame-options"), Some("DENY"), "{path}");
        assert_eq!(
            reply.header("referrer-policy"),
            Some("no-referrer"),
            "{path}"
        );
        assert_eq!(
            reply.header("cross-origin-resource-policy"),
            Some("same-origin"),
            "{path}"
        );
    }
    assert_eq!(
        get(&router, "/api/v1/nothing", VIEWER).await.json(),
        json!({ "error": { "code": "not_found", "message": "The path does not exist." } })
    );
}
