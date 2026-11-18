//! Authentication and authorization of each REST route.

use aegis_api::{ApiConfig, route_permissions};
use aegis_policy::Permission;
use axum::http::{Method, StatusCode};
use serde_json::json;

use crate::support::{
    ADMIN, ANALYST, APPROVER, AUDITOR, GUEST, OPERATOR, TestApi, UNKNOWN, VIEWER, config, get,
    request, send,
};

/// Returns a concrete path for a route template.
fn concrete(path: &str) -> String {
    let id = "0190d5b0-7c3a-7e5b-9f6e-3d2c1b0a9f8e";
    format!(
        "/api/v1{}",
        path.replace("{id}", id)
            .replace("{name}", "block-spray-source")
    )
}

fn method(name: &str) -> Method {
    name.parse().unwrap()
}

/// Returns the token of a test principal that has `permission`.
fn token_with(permission: Permission) -> &'static str {
    match permission {
        Permission::ViewIncidents => VIEWER,
        Permission::ViewAudit => AUDITOR,
        Permission::ApproveActions => APPROVER,
        Permission::RunPlaybooks => OPERATOR,
        Permission::Administer => ADMIN,
        other => panic!("no test principal has {other}"),
    }
}

/// The tokens of the principals that have at most one permission.
const SINGLE_ROLE_TOKENS: [&str; 6] = [VIEWER, AUDITOR, APPROVER, OPERATOR, ADMIN, GUEST];

/// The access rules of the REST API. A change of a permission must change this list.
#[test]
fn each_route_needs_the_documented_permission() {
    use Permission::{Administer, ApproveActions, RunPlaybooks, ViewAudit, ViewIncidents};
    let expected: [(&str, &str, &[Permission]); 19] = [
        ("GET", "/session", &[]),
        ("GET", "/status", &[ViewIncidents]),
        ("GET", "/incidents", &[ViewIncidents]),
        ("GET", "/incidents/{id}", &[ViewIncidents]),
        ("GET", "/incidents/{id}/explanation", &[ViewAudit]),
        ("GET", "/actions/{id}/explanation", &[ViewAudit]),
        ("GET", "/approvals", &[ViewIncidents, ApproveActions]),
        ("GET", "/approvals/{id}", &[ViewIncidents, ApproveActions]),
        ("POST", "/approvals/{id}/decision", &[ApproveActions]),
        ("GET", "/graph/nodes", &[ViewIncidents]),
        ("GET", "/graph/nodes/{id}", &[ViewIncidents]),
        ("GET", "/graph/nodes/{id}/neighbors", &[ViewIncidents]),
        ("GET", "/audit", &[ViewAudit]),
        ("GET", "/audit/verification", &[ViewAudit]),
        ("GET", "/agents", &[ViewIncidents]),
        ("POST", "/goal", &[Administer]),
        ("GET", "/playbooks", &[ViewIncidents, RunPlaybooks]),
        ("POST", "/playbooks/{name}/runs", &[RunPlaybooks]),
        ("GET", "/stream", &[ViewIncidents]),
    ];
    let actual: Vec<(&str, &str, &[Permission])> = route_permissions()
        .iter()
        .map(|route| (route.method, route.path, route.any_of))
        .collect();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn each_route_answers_401_without_a_token_and_with_an_unknown_token() {
    let api = TestApi::new();
    let router = api.router();
    let routes = route_permissions();
    assert!(routes.len() >= 18, "{} routes", routes.len());
    for route in routes {
        let path = concrete(route.path);
        for token in [None, Some(UNKNOWN), Some("")] {
            let reply = send(&router, request(method(route.method), &path, token, None)).await;
            assert_eq!(
                reply.status,
                StatusCode::UNAUTHORIZED,
                "{} {path} with {token:?}",
                route.method
            );
            assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
            assert_eq!(
                reply.json(),
                json!({ "error": {
                    "code": "unauthorized",
                    "message": "The request has no valid bearer token."
                } })
            );
        }
    }
    assert!(api.actions.calls().is_empty());
    assert!(api.audit.records().is_empty());
}

#[tokio::test]
async fn each_route_answers_403_to_a_principal_without_the_permission() {
    let api = TestApi::new();
    let router = api.router();
    let mut checked = 0;
    for route in route_permissions() {
        let path = concrete(route.path);
        let permitted: Vec<&str> = route.any_of.iter().map(|p| token_with(*p)).collect();
        let names = route
            .any_of
            .iter()
            .map(|permission| permission.as_str())
            .collect::<Vec<_>>()
            .join(" or ");
        for token in SINGLE_ROLE_TOKENS {
            // A route with an empty list is open to each principal with a valid token.
            if route.any_of.is_empty() || permitted.contains(&token) {
                continue;
            }
            let reply = send(
                &router,
                request(method(route.method), &path, Some(token), None),
            )
            .await;
            assert_eq!(
                reply.status,
                StatusCode::FORBIDDEN,
                "{} {path} with {token}",
                route.method
            );
            assert_eq!(
                reply.json(),
                json!({ "error": {
                    "code": "forbidden",
                    "message": format!("The principal does not have the permission {names}.")
                } })
            );
            checked += 1;
        }
    }
    // Each of the protected routes refuses four or five of the six principals.
    assert!(checked >= 18 * 4, "{checked} refusals");
    assert!(api.actions.calls().is_empty());
    assert!(api.audit.records().is_empty());
}

#[tokio::test]
async fn a_principal_with_the_permission_passes_the_guard_of_each_route() {
    let api = TestApi::new();
    let router = api.router();
    let mut checked = 0;
    for route in route_permissions() {
        let path = concrete(route.path);
        for permission in route.any_of {
            let token = token_with(*permission);
            let reply = send(
                &router,
                request(method(route.method), &path, Some(token), None),
            )
            .await;
            // The guard passed. The handler then answers for an empty store or an empty body.
            assert!(
                reply.status != StatusCode::UNAUTHORIZED && reply.status != StatusCode::FORBIDDEN,
                "{} {path} with {permission}: {}",
                route.method,
                reply.status
            );
            checked += 1;
        }
    }
    assert!(checked >= 18, "{checked} checks");
}

#[tokio::test]
async fn no_principals_means_that_each_protected_route_answers_401() {
    let api = TestApi::new();
    let router = api.router_with(&ApiConfig::default());
    let routes = route_permissions();
    assert!(!routes.is_empty());
    for route in routes {
        let path = concrete(route.path);
        for token in [None, Some(VIEWER), Some(ADMIN)] {
            let reply = send(&router, request(method(route.method), &path, token, None)).await;
            assert_eq!(
                reply.status,
                StatusCode::UNAUTHORIZED,
                "{} {path}",
                route.method
            );
        }
    }
}

#[tokio::test]
async fn the_health_route_needs_no_token_and_shows_no_detail() {
    let api = TestApi::new();
    let router = api.router();
    let reply = send(&router, request(Method::GET, "/healthz", None, None)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), json!({ "status": "ok" }));
}

#[tokio::test]
async fn the_session_route_shows_the_principal_of_the_token_and_its_permissions() {
    let api = TestApi::new();
    let router = api.router();
    let reply = get(&router, "/api/v1/session", APPROVER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "principal": { "id": "alice@example.com", "kind": "human", "roles": ["approver"] },
            "permissions": ["approve_actions"]
        })
    );
    let reply = get(&router, "/api/v1/session", ANALYST).await;
    assert_eq!(
        reply.json()["permissions"],
        json!(["view_incidents", "view_audit"])
    );
    let reply = get(&router, "/api/v1/session", GUEST).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "principal": { "id": "gus@example.com", "kind": "human", "roles": ["guest"] },
            "permissions": []
        })
    );
}

#[tokio::test]
async fn a_missing_token_variable_is_a_configuration_error() {
    let api = TestApi::new();
    let mut config = config();
    config.principals[0].token_env = Some("TOKEN_THAT_IS_NOT_SET".to_owned());
    let error = aegis_api::router(api.state.clone(), &config).unwrap_err();
    assert!(
        matches!(&error, aegis_contracts::Error::Config(message) if message == "principal vera@example.com: the environment variable TOKEN_THAT_IS_NOT_SET is not set"),
        "{error}"
    );
}

#[tokio::test]
async fn an_unknown_path_and_a_wrong_method_have_json_errors() {
    let api = TestApi::new();
    let router = api.router();
    let reply = get(&router, "/api/v1/nothing", VIEWER).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({ "error": { "code": "not_found", "message": "The path does not exist." } })
    );
    let reply = send(
        &router,
        request(Method::DELETE, "/api/v1/incidents", Some(VIEWER), None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(reply.error_code(), "method_not_allowed");
}
