//! Real HTTP request/response cycles through the actual router and the
//! real cedar-policy Authorizer/Validator — in-process via
//! `tower::ServiceExt::oneshot`, not a reimplementation of the handler
//! logic. This is the Rust-side counterpart to aegis-server's pytest
//! integration suite and aegis-sdk's adapter tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use cedar_sidecar::{app, AuthorizeResponse, ValidateResponse};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn post(path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

const ANALYST_POLICY: &str = r#"
@mask_fields("ssn,compensation")
@approval_required("false")
permit(principal, action == Action::"execute_query", resource)
when { principal.role == "Analyst" };
"#;

fn entities() -> serde_json::Value {
    serde_json::json!([
        {"uid": {"type": "Human", "id": "alice"}, "attrs": {"role": "Analyst", "department": "Finance"}, "parents": []},
        {"uid": {"type": "Resource", "id": "urn:x"}, "attrs": {"type": "database_table"}, "parents": []}
    ])
}

#[tokio::test]
async fn health_check_returns_ok() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn authorize_allows_matching_policy_and_extracts_annotations() {
    let (status, body) = post(
        "/authorize",
        serde_json::json!({
            "policy_set": ANALYST_POLICY,
            "entities": entities(),
            "principal": "Human::\"alice\"",
            "action": "Action::\"execute_query\"",
            "resource": "Resource::\"urn:x\"",
            "context": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: AuthorizeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.decision, "Allow");
    assert_eq!(parsed.determining_policies, vec!["policy0"]);
    assert_eq!(
        parsed.annotations.get("mask_fields").unwrap(),
        "compensation,ssn"
    );
    assert_eq!(
        parsed.annotations.get("approval_required").unwrap(),
        "false"
    );
}

#[tokio::test]
async fn authorize_denies_non_matching_principal_by_default() {
    let mut ents = entities();
    ents[0]["attrs"]["role"] = serde_json::json!("Junior Analyst");
    let (status, body) = post(
        "/authorize",
        serde_json::json!({
            "policy_set": ANALYST_POLICY,
            "entities": ents,
            "principal": "Human::\"alice\"",
            "action": "Action::\"execute_query\"",
            "resource": "Resource::\"urn:x\"",
            "context": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: AuthorizeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.decision, "Deny");
    assert!(parsed.determining_policies.is_empty());
}

#[tokio::test]
async fn authorize_rejects_malformed_policy_set() {
    let (status, body) = post(
        "/authorize",
        serde_json::json!({
            "policy_set": "permit(this is not cedar",
            "entities": entities(),
            "principal": "Human::\"alice\"",
            "action": "Action::\"execute_query\"",
            "resource": "Resource::\"urn:x\"",
            "context": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("invalid policy_set"));
}

#[tokio::test]
async fn authorize_rejects_malformed_entity_uid() {
    let (status, _body) = post(
        "/authorize",
        serde_json::json!({
            "policy_set": ANALYST_POLICY,
            "entities": entities(),
            "principal": "not a valid euid",
            "action": "Action::\"execute_query\"",
            "resource": "Resource::\"urn:x\"",
            "context": {}
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn validate_accepts_well_formed_policy_without_schema() {
    let (status, body) = post(
        "/validate",
        serde_json::json!({"policy_set": "permit(principal, action, resource);"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: ValidateResponse = serde_json::from_value(body).unwrap();
    assert!(parsed.valid);
    assert!(!parsed.schema_checked);
}

#[tokio::test]
async fn validate_rejects_malformed_policy_syntax() {
    let (_status, body) = post(
        "/validate",
        serde_json::json!({"policy_set": "permit(this is not cedar"}),
    )
    .await;
    let parsed: ValidateResponse = serde_json::from_value(body).unwrap();
    assert!(!parsed.valid);
    assert!(!parsed.errors.is_empty());
}

fn test_schema() -> serde_json::Value {
    serde_json::json!({
        "": {
            "entityTypes": {
                "Human": {"shape": {"type": "Record", "attributes": {
                    "role": {"type": "String"}, "department": {"type": "String"}
                }}},
                "Resource": {"shape": {"type": "Record", "attributes": {"type": {"type": "String"}}}}
            },
            "actions": {
                "execute_query": {"appliesTo": {
                    "principalTypes": ["Human"], "resourceTypes": ["Resource"],
                    "context": {"type": "Record", "attributes": {}}
                }}
            }
        }
    })
}

#[tokio::test]
async fn validate_with_schema_accepts_conformant_policy() {
    let (_status, body) = post(
        "/validate",
        serde_json::json!({"policy_set": ANALYST_POLICY, "schema": test_schema().to_string()}),
    )
    .await;
    let parsed: ValidateResponse = serde_json::from_value(body).unwrap();
    assert!(parsed.valid);
    assert!(parsed.schema_checked);
}

#[tokio::test]
async fn validate_with_schema_catches_undeclared_attribute() {
    let bad_policy = r#"permit(principal, action == Action::"execute_query", resource)
        when { principal.nonexistent_attribute == "x" };"#;
    let (_status, body) = post(
        "/validate",
        serde_json::json!({"policy_set": bad_policy, "schema": test_schema().to_string()}),
    )
    .await;
    let parsed: ValidateResponse = serde_json::from_value(body).unwrap();
    assert!(!parsed.valid);
    assert!(parsed.schema_checked);
    assert!(!parsed.errors.is_empty());
}

#[tokio::test]
async fn validate_rejects_malformed_schema() {
    let (_status, body) = post(
        "/validate",
        serde_json::json!({"policy_set": "permit(principal, action, resource);", "schema": "not json"}),
    )
    .await;
    let parsed: ValidateResponse = serde_json::from_value(body).unwrap();
    assert!(!parsed.valid);
    assert!(parsed.errors[0].contains("invalid schema"));
}

// Two policies permit the same request. Before the merge rules, their
// annotations went into a HashMap last-write-wins, so which `mask_fields`
// survived depended on iteration order and masking could be silently lost.
const OVERLAPPING_POLICIES: &str = r#"
@mask_fields("ssn")
@approval_required("false")
@risk_tier("low")
permit(principal, action == Action::"execute_query", resource)
when { principal.role == "Analyst" };

@mask_fields("compensation, ssn")
@approval_required("true")
permit(principal, action == Action::"execute_query", resource)
when { principal.department == "Finance" };
"#;

#[tokio::test]
async fn overlapping_permits_merge_to_the_strictest_annotations() {
    for _ in 0..20 {
        let (status, body) = post(
            "/authorize",
            serde_json::json!({
                "policy_set": OVERLAPPING_POLICIES,
                "entities": entities(),
                "principal": "Human::\"alice\"",
                "action": "Action::\"execute_query\"",
                "resource": "Resource::\"urn:x\"",
                "context": {}
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: AuthorizeResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.decision, "Allow");
        assert_eq!(parsed.determining_policies, vec!["policy0", "policy1"]);
        assert_eq!(parsed.annotations["mask_fields"], "compensation,ssn");
        assert_eq!(parsed.annotations["approval_required"], "true");
        // policy1 declares no tier, so policy0's "low" must not win.
        assert!(!parsed.annotations.contains_key("risk_tier"));
    }
}
