//! The web console. The files are part of the binary.
//!
//! The console is plain HTML, CSS, and JavaScript modules. It has no build step and it
//! makes no request to a different origin, so it works on a network with no internet.

use axum::Router;
use axum::extract::Path;
use axum::extract::rejection::PathRejection;
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::error::ApiError;
use crate::security::CONSOLE_CONTENT_SECURITY_POLICY;

/// One file of the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleAsset {
    /// The path of the file below `/assets/`. The page itself has the path `index.html`
    /// and the URL `/`.
    pub path: &'static str,
    /// The content type of the file.
    pub content_type: &'static str,
    /// The text of the file.
    pub body: &'static str,
}

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml";

const INDEX_PATH: &str = "index.html";

macro_rules! asset {
    ($path:literal, $content_type:expr) => {
        ConsoleAsset {
            path: $path,
            content_type: $content_type,
            body: include_str!(concat!("../assets/", $path)),
        }
    };
}

const ASSETS: &[ConsoleAsset] = &[
    asset!("index.html", HTML),
    asset!("console.css", CSS),
    asset!("favicon.svg", SVG),
    asset!("js/main.js", JAVASCRIPT),
    asset!("js/api.js", JAVASCRIPT),
    asset!("js/dom.js", JAVASCRIPT),
    asset!("js/format.js", JAVASCRIPT),
    asset!("js/sse.js", JAVASCRIPT),
    asset!("js/views/incidents.js", JAVASCRIPT),
    asset!("js/views/activity.js", JAVASCRIPT),
    asset!("js/views/approvals.js", JAVASCRIPT),
    asset!("js/views/graph.js", JAVASCRIPT),
    asset!("js/views/audit.js", JAVASCRIPT),
];

/// Returns each file of the console.
#[must_use]
pub fn console_assets() -> &'static [ConsoleAsset] {
    ASSETS
}

fn respond(asset: &ConsoleAsset) -> Response {
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static(asset.content_type)),
        (
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONSOLE_CONTENT_SECURITY_POLICY),
        ),
        // The browser asks the server each time, so a new binary gives new files.
        (CACHE_CONTROL, HeaderValue::from_static("no-cache")),
    ];
    (headers, asset.body).into_response()
}

fn find(path: &str) -> Option<&'static ConsoleAsset> {
    ASSETS.iter().find(|asset| asset.path == path)
}

async fn index() -> Response {
    match find(INDEX_PATH) {
        Some(asset) => respond(asset),
        None => not_found(),
    }
}

async fn asset(path: Result<Path<String>, PathRejection>) -> Response {
    // A path that is not valid text is the path of no file.
    match path.ok().and_then(|Path(path)| find(&path)) {
        Some(asset) if asset.path != INDEX_PATH => respond(asset),
        _ => not_found(),
    }
}

fn not_found() -> Response {
    ApiError::NotFound("The file does not exist.".to_owned()).into_response()
}

/// Builds the router of the console: `/` and `/assets/{path}`.
pub(crate) fn console_router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/", get(index))
        .route("/assets/{*path}", get(asset))
}
