use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use axum::{
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    /// Raw Cedar policy text (one or more policies), as stored in tenant_policies.policy_script
    pub policy_set: String,
    /// Cedar entities JSON array. Optional; defaults to no entities.
    #[serde(default)]
    pub entities: serde_json::Value,
    /// Cedar entity UID string, e.g. `User::"alice"`
    pub principal: String,
    /// Cedar entity UID string, e.g. `Action::"execute_query"`
    pub action: String,
    /// Cedar entity UID string, e.g. `Resource::"urn:enterprise:db:finance:q3_revenue"`
    pub resource: String,
    /// Arbitrary JSON object passed through as the Cedar request context
    #[serde(default)]
    pub context: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub decision: String,
    pub determining_policies: Vec<String>,
    pub errors: Vec<String>,
    /// Annotations (e.g. `mask_fields`, `approval_required`) of every
    /// determining policy, merged strictest-first by `merge_annotations`.
    pub annotations: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub policy_set: String,
    /// Optional Cedar schema as a JSON string (Cedar's JSON schema format,
    /// not the human-readable `.cedarschema` DSL — `Schema::from_str` in
    /// this crate version parses JSON). If present, runs real strict-mode
    /// semantic validation (entity types, action `appliesTo` constraints)
    /// via `cedar_policy::Validator`, not just a parse check. Authoring a
    /// schema is each tenant's choice — there's no single global schema
    /// since tenants define their own action/tool vocabulary.
    #[serde(default)]
    pub schema: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    /// True only when a schema was supplied and real semantic validation
    /// ran; false means this was syntax-only (parse) validation.
    pub schema_checked: bool,
}

async fn health() -> &'static str {
    "ok"
}

/// Without a schema: syntactic validation only (does this parse as a
/// well-formed Cedar PolicySet?). With a schema: real strict-mode semantic
/// validation via `cedar_policy::Validator` — catches things like
/// `principal.role` referencing an attribute the schema never declared, or
/// an action applied to a resource type it isn't declared to apply to.
async fn validate(Json(req): Json<ValidateRequest>) -> Json<ValidateResponse> {
    let policy_set = match PolicySet::from_str(&req.policy_set) {
        Ok(ps) => ps,
        Err(e) => {
            return Json(ValidateResponse {
                valid: false,
                errors: vec![e.to_string()],
                schema_checked: false,
            })
        }
    };

    let Some(schema_src) = req.schema else {
        return Json(ValidateResponse {
            valid: true,
            errors: vec![],
            schema_checked: false,
        });
    };

    let schema = match Schema::from_str(&schema_src) {
        Ok(s) => s,
        Err(e) => {
            return Json(ValidateResponse {
                valid: false,
                errors: vec![format!("invalid schema: {e}")],
                schema_checked: false,
            })
        }
    };

    let validator = Validator::new(schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    if result.validation_passed() {
        Json(ValidateResponse {
            valid: true,
            errors: vec![],
            schema_checked: true,
        })
    } else {
        Json(ValidateResponse {
            valid: false,
            errors: result.validation_errors().map(|e| e.to_string()).collect(),
            schema_checked: true,
        })
    }
}

async fn authorize(
    headers: HeaderMap,
    Json(req): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();
    // Propagated from aegis-server's per-request correlation_id so a slow or
    // rejected /v1/evaluate call can be traced into this service's logs
    // even without full distributed tracing wired up on this side yet.
    let correlation_id = headers
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let policy_set = PolicySet::from_str(&req.policy_set).map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid policy_set");
        bad_request(format!("invalid policy_set: {e}"))
    })?;

    let entities_json = if req.entities.is_null() {
        "[]".to_string()
    } else {
        req.entities.to_string()
    };
    let entities = Entities::from_json_str(&entities_json, None).map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid entities");
        bad_request(format!("invalid entities: {e}"))
    })?;

    let principal: EntityUid = req.principal.parse().map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid principal euid");
        bad_request(format!("invalid principal euid: {e}"))
    })?;
    let action: EntityUid = req.action.parse().map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid action euid");
        bad_request(format!("invalid action euid: {e}"))
    })?;
    let resource: EntityUid = req.resource.parse().map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid resource euid");
        bad_request(format!("invalid resource euid: {e}"))
    })?;

    let context_json = if req.context.is_null() {
        "{}".to_string()
    } else {
        req.context.to_string()
    };
    let context = Context::from_json_str(&context_json, None).map_err(|e| {
        tracing::warn!(correlation_id, error = %e, "invalid context");
        bad_request(format!("invalid context: {e}"))
    })?;

    let request = Request::new(Some(principal), Some(action), Some(resource), context, None)
        .map_err(|e| {
            tracing::warn!(correlation_id, error = %e, "invalid request");
            bad_request(format!("invalid request: {e}"))
        })?;

    let authorizer = Authorizer::new();
    let response = authorizer.is_authorized(&request, &policy_set, &entities);

    let decision = match response.decision() {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
    };

    let mut determining_policy_ids: Vec<_> = response.diagnostics().reason().collect();
    // Cedar returns these from a set; sort so the response, and the merge
    // below, are the same on every call.
    determining_policy_ids.sort_by_key(|id| id.to_string());

    let per_policy: Vec<HashMap<String, String>> = determining_policy_ids
        .iter()
        .filter_map(|id| policy_set.policy(id))
        .map(|policy| {
            policy
                .annotations()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .collect();
    let annotations = merge_annotations(&per_policy);

    let determining_policies = determining_policy_ids
        .iter()
        .map(|id| id.to_string())
        .collect();

    let errors = response
        .diagnostics()
        .errors()
        .map(|e| e.to_string())
        .collect();

    tracing::info!(
        correlation_id,
        decision,
        latency_ms = start.elapsed().as_secs_f64() * 1000.0,
        "authorize decision"
    );

    Ok(Json(AuthorizeResponse {
        decision: decision.to_string(),
        determining_policies,
        errors,
        annotations,
    }))
}

const RISK_TIERS: [&str; 4] = ["low", "medium", "high", "critical"];

fn risk_rank(tier: Option<&String>) -> usize {
    // A policy without a tier, or with one we do not know, ranks above
    // every known tier: it must never let another policy's "low" through.
    tier.and_then(|t| {
        RISK_TIERS
            .iter()
            .position(|k| *k == t.trim().to_lowercase())
    })
    .unwrap_or(RISK_TIERS.len())
}

/// Merges the annotations of every determining policy into one map. When
/// several policies allow the same request, the result is the strictest
/// combination, never whichever policy happened to be read last:
///
/// - `mask_fields`: the union of every policy's fields.
/// - `approval_required`: `"true"` if any policy requires approval.
/// - `risk_tier`: the most severe tier. A policy with no tier counts as more
///   severe than any tier, so the merged tier is `"low"` only when every
///   determining policy says `"low"`; otherwise it is omitted.
/// - any other key: the value from the first policy, in policy-id order.
///
/// `policies` must already be in policy-id order.
pub fn merge_annotations(policies: &[HashMap<String, String>]) -> HashMap<String, String> {
    let mut merged = HashMap::new();
    if policies.is_empty() {
        return merged;
    }

    let mut fields: Vec<String> = policies
        .iter()
        .filter_map(|p| p.get("mask_fields"))
        .flat_map(|v| v.split(','))
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .collect();
    fields.sort();
    fields.dedup();
    if !fields.is_empty() {
        merged.insert("mask_fields".to_string(), fields.join(","));
    }

    let declared_approval: Vec<&String> = policies
        .iter()
        .filter_map(|p| p.get("approval_required"))
        .collect();
    if !declared_approval.is_empty() {
        let any_true = declared_approval
            .iter()
            .any(|v| v.trim().eq_ignore_ascii_case("true"));
        merged.insert(
            "approval_required".to_string(),
            if any_true { "true" } else { "false" }.to_string(),
        );
    }

    if policies.iter().any(|p| p.contains_key("risk_tier")) {
        let worst = policies
            .iter()
            .map(|p| risk_rank(p.get("risk_tier")))
            .max()
            .unwrap_or(RISK_TIERS.len());
        if worst < RISK_TIERS.len() {
            merged.insert("risk_tier".to_string(), RISK_TIERS[worst].to_string());
        }
    }

    for policy in policies {
        for (key, value) in policy {
            if matches!(
                key.as_str(),
                "mask_fields" | "approval_required" | "risk_tier"
            ) {
                continue;
            }
            merged.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    merged
}

fn bad_request(msg: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorResponse { error: msg }),
    )
}

/// Builds the router with no side effects (no logging init, no socket
/// binding) so `tests/integration.rs` can exercise it in-process via
/// `tower::ServiceExt::oneshot` — real request/response cycles through
/// the real Cedar authorizer, not a reimplementation of the logic.
pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/authorize", post(authorize))
        .route("/validate", post(validate))
}

#[cfg(test)]
mod tests {
    use super::merge_annotations;
    use std::collections::HashMap;

    fn ann(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_policies_no_annotations() {
        assert!(merge_annotations(&[]).is_empty());
    }

    #[test]
    fn single_policy_is_passed_through_normalised() {
        let m = merge_annotations(&[ann(&[
            ("mask_fields", " ssn , email,"),
            ("approval_required", "TRUE"),
            ("risk_tier", "Medium"),
        ])]);
        assert_eq!(m["mask_fields"], "email,ssn");
        assert_eq!(m["approval_required"], "true");
        assert_eq!(m["risk_tier"], "medium");
    }

    #[test]
    fn mask_fields_are_unioned() {
        let m = merge_annotations(&[
            ann(&[("mask_fields", "ssn")]),
            ann(&[("mask_fields", "salary")]),
            ann(&[]),
        ]);
        assert_eq!(m["mask_fields"], "salary,ssn");
    }

    #[test]
    fn approval_is_required_if_any_policy_requires_it() {
        let m = merge_annotations(&[
            ann(&[("approval_required", "false")]),
            ann(&[("approval_required", "true")]),
        ]);
        assert_eq!(m["approval_required"], "true");
        let m = merge_annotations(&[ann(&[("approval_required", "false")]), ann(&[])]);
        assert_eq!(m["approval_required"], "false");
    }

    #[test]
    fn risk_tier_takes_the_most_severe() {
        let m = merge_annotations(&[
            ann(&[("risk_tier", "low")]),
            ann(&[("risk_tier", "high")]),
            ann(&[("risk_tier", "medium")]),
        ]);
        assert_eq!(m["risk_tier"], "high");
    }

    #[test]
    fn low_tier_survives_only_if_every_policy_says_low() {
        let m = merge_annotations(&[ann(&[("risk_tier", "low")]), ann(&[("risk_tier", "low")])]);
        assert_eq!(m["risk_tier"], "low");
        let m = merge_annotations(&[ann(&[("risk_tier", "low")]), ann(&[])]);
        assert!(!m.contains_key("risk_tier"));
        let m = merge_annotations(&[
            ann(&[("risk_tier", "low")]),
            ann(&[("risk_tier", "banana")]),
        ]);
        assert!(!m.contains_key("risk_tier"));
    }

    #[test]
    fn other_keys_take_the_first_policy_in_id_order() {
        let m = merge_annotations(&[ann(&[("owner", "team-a")]), ann(&[("owner", "team-b")])]);
        assert_eq!(m["owner"], "team-a");
    }
}
