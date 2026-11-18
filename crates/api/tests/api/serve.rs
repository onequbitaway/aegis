//! The server on a loopback address: start, requests, the live feed, and shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use aegis_api::{ApiConfig, CONSOLE_CONTENT_SECURITY_POLICY, SlackConfig};
use aegis_contracts::bus::{publish_json, subject};
use aegis_contracts::common::Severity;
use aegis_contracts::{Error, Result};
use aegis_core::Shutdown;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::support::{TestApi, VIEWER, approval_request, config, incident, to_json};

const LIMIT: Duration = Duration::from_secs(10);

struct Server {
    address: SocketAddr,
    shutdown: Shutdown,
    task: JoinHandle<Result<()>>,
    client: reqwest::Client,
}

impl Server {
    /// Starts the server on a port that the operating system selects.
    async fn start(api: &TestApi, config: ApiConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Shutdown::new();
        let task = tokio::spawn(aegis_api::serve_on(
            listener,
            api.state.clone(),
            config,
            shutdown.clone(),
        ));
        // A proxy of the environment must not get the requests of the test.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        Self {
            address,
            shutdown,
            task,
            client,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// Triggers the shutdown and returns the result of the server.
    async fn stop(self) -> Result<()> {
        self.shutdown.trigger();
        tokio::time::timeout(LIMIT, self.task)
            .await
            .expect("the server did not stop in time")
            .unwrap()
    }
}

#[tokio::test]
async fn the_server_answers_rest_requests_and_serves_the_console() {
    let api = TestApi::new();
    let server = Server::start(&api, config()).await;

    let health = server
        .client
        .get(server.url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    assert_eq!(
        health.json::<Value>().await.unwrap(),
        json!({ "status": "ok" })
    );

    let session = server
        .client
        .get(server.url("/api/v1/session"))
        .bearer_auth(VIEWER)
        .send()
        .await
        .unwrap();
    assert_eq!(session.status(), 200);
    assert_eq!(
        session.json::<Value>().await.unwrap()["principal"]["id"],
        "vera@example.com"
    );

    let refused = server
        .client
        .get(server.url("/api/v1/session"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);

    let page = server.client.get(server.url("/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(
        page.headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some(CONSOLE_CONTENT_SECURITY_POLICY)
    );
    assert!(page.text().await.unwrap().starts_with("<!doctype html>"));

    server.stop().await.unwrap();
}

/// Reads the response until it has `count` events. Returns the type and the data of each.
async fn read_events(
    response: &mut reqwest::Response,
    buffer: &mut String,
    count: usize,
) -> Vec<(String, Value)> {
    let mut events = Vec::new();
    while events.len() < count {
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer.drain(..end + 2).collect();
            let field = |name: &str| {
                block
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .map(str::to_owned)
            };
            if let (Some(event), Some(data)) = (field("event: "), field("data: ")) {
                events.push((event, serde_json::from_str(&data).unwrap()));
            }
        }
        if events.len() >= count {
            break;
        }
        let chunk = tokio::time::timeout(LIMIT, response.chunk())
            .await
            .expect("the live feed gave no data in time")
            .unwrap()
            .expect("the live feed ended");
        buffer.push_str(std::str::from_utf8(&chunk).unwrap());
    }
    events
}

#[tokio::test]
async fn a_shutdown_ends_an_open_live_feed_and_stops_the_server() {
    let api = TestApi::new();
    let server = Server::start(&api, config()).await;

    let mut feed = server
        .client
        .get(server.url("/api/v1/stream"))
        .bearer_auth(VIEWER)
        .send()
        .await
        .unwrap();
    assert_eq!(feed.status(), 200);
    let mut buffer = String::new();
    let ready = read_events(&mut feed, &mut buffer, 1).await;
    assert_eq!(ready[0].0, "ready");

    let incident = incident("Password spray", Severity::High);
    publish_json(api.bus.as_ref(), subject::INCIDENTS, &incident)
        .await
        .unwrap();
    assert_eq!(
        read_events(&mut feed, &mut buffer, 1).await,
        [(
            "incident".to_owned(),
            json!({ "subject": "aegis.incidents", "payload": to_json(&incident) })
        )]
    );

    // The feed is open. The server must still stop.
    let address = server.address;
    server.stop().await.unwrap();

    // The server closed the feed: the body ends with no more events.
    let rest = tokio::time::timeout(LIMIT, async {
        let mut rest = String::new();
        while let Ok(Some(chunk)) = feed.chunk().await {
            rest.push_str(std::str::from_utf8(&chunk).unwrap());
        }
        rest
    })
    .await
    .expect("the live feed did not end after the shutdown");
    assert!(!rest.contains("event:"), "{rest}");

    // The port is free: the server does not accept connections.
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let error = client
        .get(format!("http://{address}/healthz"))
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect(), "{error}");
}

#[tokio::test]
async fn the_server_runs_the_notification_task_until_the_shutdown() {
    let webhook = MockServer::start().await;
    let (sender, mut bodies) = tokio::sync::mpsc::unbounded_channel::<Value>();
    Mock::given(method("POST"))
        .and(path("/slack-hook"))
        .respond_with(move |request: &wiremock::Request| {
            let _ = sender.send(serde_json::from_slice(&request.body).unwrap_or(Value::Null));
            ResponseTemplate::new(200)
        })
        .mount(&webhook)
        .await;
    let hook = format!("{}/slack-hook", webhook.uri());
    let api = TestApi::with_env(&[("SLACK_WEBHOOK_URL", &hook)]);
    let mut config = config();
    config.chatops.slack = Some(SlackConfig {
        webhook_url_env: Some("SLACK_WEBHOOK_URL".to_owned()),
        ..SlackConfig::default()
    });
    let server = Server::start(&api, config).await;

    // The server answers, so it started the task and the task has its subscriptions.
    let health = server
        .client
        .get(server.url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);

    let request = approval_request();
    publish_json(api.bus.as_ref(), subject::APPROVALS, &request)
        .await
        .unwrap();
    let body = tokio::time::timeout(LIMIT, bodies.recv())
        .await
        .expect("the webhook got no request in time")
        .unwrap();
    assert_eq!(body["text"], "AEGIS approval needed");
    assert_eq!(
        body["blocks"][2]["elements"][0]["text"],
        format!("Approval {}", request.id)
    );

    server.stop().await.unwrap();
}

#[tokio::test]
async fn the_server_refuses_an_address_that_is_not_loopback() {
    let api = TestApi::new();
    let config = ApiConfig {
        bind: "0.0.0.0:0".parse().unwrap(),
        ..config()
    };
    let error = aegis_api::serve(api.state.clone(), config, Shutdown::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message.starts_with("api.bind is not a loopback address.")),
        "{error}"
    );
}

#[tokio::test]
async fn a_port_that_is_in_use_is_an_unavailable_error() {
    let api = TestApi::new();
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = ApiConfig {
        bind: taken.local_addr().unwrap(),
        ..config()
    };
    let error = aegis_api::serve(api.state.clone(), config, Shutdown::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Unavailable(message) if message.starts_with("the API server cannot listen on 127.0.0.1:")),
        "{error}"
    );
}

#[tokio::test]
async fn a_configuration_that_is_not_valid_stops_the_start() {
    let api = TestApi::new();
    let mut config = config();
    config.principals[0].token_env = Some("TOKEN_THAT_IS_NOT_SET".to_owned());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = aegis_api::serve_on(listener, api.state.clone(), config, Shutdown::new())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, Error::Config(message) if message == "principal vera@example.com: the environment variable TOKEN_THAT_IS_NOT_SET is not set"),
        "{error}"
    );
}

#[tokio::test]
async fn serve_listens_on_the_address_of_the_configuration() {
    let api = TestApi::new();
    // Take a free port from the operating system, then give it to the server.
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let config = ApiConfig {
        bind: SocketAddr::from(([127, 0, 0, 1], port)),
        ..config()
    };
    let shutdown = Shutdown::new();
    let task = tokio::spawn(aegis_api::serve(
        api.state.clone(),
        config,
        shutdown.clone(),
    ));

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://127.0.0.1:{port}/healthz");
    // The server binds in its task. Ask until the connection is accepted.
    let health = tokio::time::timeout(LIMIT, async {
        loop {
            match client.get(&url).send().await {
                Ok(response) => break response,
                Err(error) if error.is_connect() => tokio::task::yield_now().await,
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .expect("the server did not start in time");
    assert_eq!(health.status(), 200);

    shutdown.trigger();
    tokio::time::timeout(LIMIT, task)
        .await
        .expect("the server did not stop in time")
        .unwrap()
        .unwrap();
}
