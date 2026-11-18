//! The Defensive Graph routes.

use aegis_contracts::common::{EntityKind, EntityRef, IncidentId};
use aegis_contracts::graph::{DefensiveGraph, GraphEdge, GraphNode, NodeId, NodeKind, relation};
use axum::http::StatusCode;
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;

use crate::support::{TestApi, VIEWER, get, to_json};

struct Seeded {
    incident: GraphNode,
    user: GraphNode,
    address: GraphNode,
    resource: GraphNode,
}

/// Writes one incident that involves a user and an address. The user authenticated from
/// the address and owns a resource.
async fn seed(api: &TestApi) -> Seeded {
    let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 0).unwrap();
    let entity = |kind, id: &str, minutes| {
        let mut node = GraphNode::from_entity(&EntityRef::new(kind, id));
        node.updated_at = time + Duration::minutes(minutes);
        node
    };
    let incident = GraphNode {
        id: NodeId::for_incident(IncidentId::new()),
        kind: NodeKind::Incident,
        label: "Password spray".to_owned(),
        properties: [("severity".to_owned(), json!("high"))].into(),
        updated_at: time,
    };
    let user = entity(EntityKind::User, "user-1", 1);
    let address = entity(EntityKind::IpAddress, "203.0.113.50", 2);
    let resource = entity(EntityKind::Resource, "/subscriptions/s1/vaults/kv prod", 3);
    for node in [&incident, &user, &address, &resource] {
        api.graph.upsert_node(node.clone()).await.unwrap();
    }
    for (from, name, to) in [
        (&incident, relation::INVOLVES, &user),
        (&incident, relation::INVOLVES, &address),
        (&user, relation::AUTHENTICATED_FROM, &address),
        (&user, relation::OWNS, &resource),
    ] {
        api.graph
            .upsert_edge(GraphEdge::new(from.id.clone(), name, to.id.clone()))
            .await
            .unwrap();
    }
    Seeded {
        incident,
        user,
        address,
        resource,
    }
}

/// Returns a node identifier as one path segment.
fn segment(id: &NodeId) -> String {
    url::form_urlencoded::byte_serialize(id.0.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

#[tokio::test]
async fn the_node_list_has_the_nodes_of_one_type_newest_first() {
    let api = TestApi::new();
    let seeded = seed(&api).await;
    let router = api.router();

    let reply = get(&router, "/api/v1/graph/nodes?kind=asset", VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({ "items": [to_json(&seeded.resource), to_json(&seeded.address)] })
    );
    let reply = get(&router, "/api/v1/graph/nodes?kind=asset&limit=1", VIEWER).await;
    assert_eq!(
        reply.json(),
        json!({ "items": [to_json(&seeded.resource)] })
    );
    let reply = get(&router, "/api/v1/graph/nodes?kind=finding", VIEWER).await;
    assert_eq!(reply.json(), json!({ "items": [] }));
}

#[tokio::test]
async fn a_node_query_that_is_not_valid_is_a_400() {
    let api = TestApi::new();
    seed(&api).await;
    let router = api.router();
    let cases = [
        (
            "/api/v1/graph/nodes",
            "The query parameter kind is necessary. It must be one of: asset, identity, alert, \
             finding, incident.",
        ),
        (
            "/api/v1/graph/nodes?kind=host",
            "The query parameter kind must be one of: asset, identity, alert, finding, incident.",
        ),
        (
            "/api/v1/graph/nodes?kind=asset&limit=0",
            "The query parameter limit must be from 1 to 200.",
        ),
        (
            "/api/v1/graph/nodes/user%3Auser-1/neighbors?direction=up",
            "The query parameter direction must be one of: outgoing, incoming, both.",
        ),
        (
            "/api/v1/graph/nodes/user%3Auser-1/neighbors?depth=2",
            "The query has a parameter that this route does not know. The known parameters \
             are: direction, relation, limit.",
        ),
    ];
    for (path, message) in cases {
        let reply = get(&router, path, VIEWER).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            reply.json(),
            json!({ "error": { "code": "invalid_input", "message": message } }),
            "{path}"
        );
    }
}

#[tokio::test]
async fn one_node_is_read_by_its_identifier() {
    let api = TestApi::new();
    let seeded = seed(&api).await;
    let router = api.router();

    for node in [
        &seeded.incident,
        &seeded.user,
        &seeded.address,
        &seeded.resource,
    ] {
        let path = format!("/api/v1/graph/nodes/{}", segment(&node.id));
        let reply = get(&router, &path, VIEWER).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.json(), to_json(node), "{path}");
    }
    let body = get(
        &router,
        &format!("/api/v1/graph/nodes/{}", segment(&seeded.resource.id)),
        VIEWER,
    )
    .await
    .json();
    assert_eq!(body["id"], "resource:/subscriptions/s1/vaults/kv prod");
    assert_eq!(body["kind"], "asset");

    let reply = get(&router, "/api/v1/graph/nodes/user%3Anobody", VIEWER).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.json(),
        json!({ "error": { "code": "not_found", "message": "The graph node does not exist." } })
    );
}

#[tokio::test]
async fn the_neighbors_follow_the_direction_and_the_relation() {
    let api = TestApi::new();
    let seeded = seed(&api).await;
    let router = api.router();
    let base = format!("/api/v1/graph/nodes/{}/neighbors", segment(&seeded.user.id));

    let reply = get(&router, &base, VIEWER).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({
            "node": to_json(&seeded.user),
            "items": [
                to_json(&seeded.incident),
                to_json(&seeded.address),
                to_json(&seeded.resource)
            ],
            "total": 3
        })
    );

    let ids = |path: String| {
        let router = router.clone();
        async move {
            let body = get(&router, &path, VIEWER).await.json();
            let ids: Vec<String> = body["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node["id"].as_str().unwrap().to_owned())
                .collect();
            (ids, body["total"].as_u64().unwrap())
        }
    };
    assert_eq!(
        ids(format!("{base}?direction=outgoing")).await,
        (
            vec![seeded.address.id.0.clone(), seeded.resource.id.0.clone()],
            2
        )
    );
    assert_eq!(
        ids(format!("{base}?direction=incoming")).await,
        (vec![seeded.incident.id.0.clone()], 1)
    );
    assert_eq!(
        ids(format!("{base}?direction=both&relation=owns")).await,
        (vec![seeded.resource.id.0.clone()], 1)
    );
    assert_eq!(
        ids(format!("{base}?relation=member_of")).await,
        (Vec::new(), 0)
    );
    assert_eq!(
        ids(format!("{base}?limit=2")).await,
        (
            vec![seeded.incident.id.0.clone(), seeded.address.id.0.clone()],
            3
        )
    );

    let reply = get(
        &router,
        "/api/v1/graph/nodes/user%3Anobody/neighbors",
        VIEWER,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.error_message(), "The graph node does not exist.");
}
