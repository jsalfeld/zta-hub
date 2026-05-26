use engine::policy_evaluator::{PolicyEvaluator, ExecutionMode, EvaluationResult};
use broker::credential_broker::CredentialBroker;
use schemas::governance::schemas::{ActionRequest};
use axum::{
    extract::{Path, State},
    http::{StatusCode, Method},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::Value;
use rand::RngCore;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use sha2::{Sha256, Digest};
use tracing::{info, error, debug};

#[derive(Clone)]
pub struct PendingIntent {
    pub intent_id: String,
    pub agent_attestation_class: String,
    pub action_type: String,
    pub requested_parameters: Vec<u8>,
}

struct AppState {
    pub engine_signing_key: SigningKey,
    pub evaluator: Mutex<PolicyEvaluator>,
    pub broker: CredentialBroker,
    pub db_pool: PgPool,
}

#[derive(serde::Deserialize)]
struct CreateIntentReq {
    agent_attestation_class: String,
    action_type: String,
    requested_parameters: Value,
}

#[derive(serde::Deserialize)]
struct TrustedSourceEntry {
    source_id: String,
    public_key_hex: String,
}

#[derive(serde::Deserialize)]
struct TrustedSourcesConfig {
    sources: Vec<TrustedSourceEntry>,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
enum HubError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Intent not found")]
    IntentNotFound,
    #[error("Policy denied: {0}")]
    PolicyDenied(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for HubError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            HubError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            HubError::IntentNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            HubError::PolicyDenied(_) => (StatusCode::FORBIDDEN, self.to_string()),
            HubError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            HubError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        error!(error = %message, status = %status.as_u16(), "Request failed");
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn load_trusted_sources(config_dir: &str, evaluator: &mut PolicyEvaluator) {
    let path = format!("{}/trusted_sources.json", config_dir);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            tracing::warn!("No trusted_sources.json found in {}. Oracles will not be trusted.", config_dir);
            return;
        }
    };
    
    let config: TrustedSourcesConfig = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to parse trusted_sources.json: {}", e);
            return;
        }
    };

    for source in config.sources {
        if source.public_key_hex.len() != 64 {
            tracing::error!("Invalid public key length for source {}: expected 64 hex chars", source.source_id);
            continue;
        }
        
        match hex::decode(&source.public_key_hex) {
            Ok(bytes) => {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    evaluator.register_trusted_source(&source.source_id, arr);
                    tracing::info!("Registered trusted source: {}", source.source_id);
                } else {
                    tracing::error!("Invalid decoded public key length for source {}: expected 32 bytes", source.source_id);
                }
            },
            Err(e) => tracing::error!("Failed to decode hex public key for source {}: {}", source.source_id, e),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hub_server=info".parse().unwrap())
        )
        .json()
        .init();

    info!("Governed Action Hub: API Server starting");

    let config_dir = std::env::var("HUB_CONFIG_DIR").unwrap_or_else(|_| "config".to_string());
    info!(config_dir = %config_dir, "Loading configuration");

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://hub_admin:supersecretpassword@localhost:5432/governance_db".to_string());

    info!("Connecting to database");
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url).await
        .expect("Failed to connect to Postgres");
        
    // Create Tables
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS intents (
            id VARCHAR PRIMARY KEY,
            agent_attestation_class VARCHAR NOT NULL,
            action_type VARCHAR NOT NULL,
            requested_parameters BYTEA NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    ).execute(&db_pool).await.expect("Failed to create intents table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            intent_id VARCHAR NOT NULL,
            action_type VARCHAR NOT NULL,
            receipt_payload BYTEA NOT NULL,
            signature BYTEA NOT NULL,
            previous_hash VARCHAR NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    ).execute(&db_pool).await.expect("Failed to create audit_log table");

    let mut csprng = OsRng;
    let engine_signing_key = SigningKey::generate(&mut csprng);
    let engine_pubkey_bytes = engine_signing_key.verifying_key().to_bytes();

    let mut policy_evaluator = PolicyEvaluator::new();
    policy_evaluator.set_signing_key(engine_signing_key.clone());
    policy_evaluator.register_computation_verifier(
        engine::computation_verifier::MockVerifier::new()
    );
    if let Err(e) = policy_evaluator.load_from_config(&config_dir) {
        error!(error = %e, "Failed to load config");
    }
    if let Err(e) = policy_evaluator.computation_registry.load_from_dir(&config_dir) {
        error!(error = %e, "Failed to load computation registry");
    }

    let broker = CredentialBroker::new(engine_pubkey_bytes).expect("Failed to init broker");
    
    // Configure Policy Evaluator to verify its own Hub receipts
    policy_evaluator.register_trusted_source("governance_hub", engine_pubkey_bytes);
    
    // Load trusted public keys for external Oracles from config
    load_trusted_sources(&config_dir, &mut policy_evaluator);

    let shared_state = Arc::new(AppState {
        engine_signing_key,
        evaluator: Mutex::new(policy_evaluator),
        broker,
        db_pool,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(Any);

    let app = Router::new()
        .route("/v1/intent", post(create_intent))
        .route("/v1/execute/:intent_id", post(execute_action))
        .route("/v1/skills", get(list_skills))
        .route("/v1/skills/:id/skill.md", get(get_skill_md))
        .route("/v1/computations", get(list_computations))
        .route("/v1/computations/:id", get(get_computation))
        .layer(cors)
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Server listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

#[derive(serde::Deserialize)]
struct ExecuteRequestPayload {
    request_id: String,
    #[serde(default)]
    external_data: Vec<schemas::governance::schemas::SignedDataRecord>,
    #[serde(default)]
    prior_execution_receipts: Vec<schemas::governance::schemas::SignedDataRecord>,
    #[serde(default)]
    computation_proofs: Vec<schemas::governance::schemas::ComputationProof>,
}

async fn execute_action(
    State(state): State<Arc<AppState>>,
    Path(intent_id): Path<String>,
    body: String,
) -> Result<impl IntoResponse, HubError> {
    debug!(body = %body, "Received execute request");
    let execute_req: ExecuteRequestPayload = serde_json::from_str(&body)
        .map_err(|e| HubError::BadRequest(e.to_string()))?;

    let mut payload = ActionRequest {
        request_id: execute_req.request_id,
        agent_attestation_class: "".to_string(),
        action_type: "".to_string(),
        requested_parameters: vec![],
        external_data: execute_req.external_data,
        prior_execution_receipts: execute_req.prior_execution_receipts,
        computation_proofs: execute_req.computation_proofs,
    };

    let intent_record = sqlx::query(
        "SELECT id, agent_attestation_class, action_type, requested_parameters FROM intents WHERE id = $1"
    )
    .bind(&intent_id)
    .fetch_optional(&state.db_pool).await?;

    let intent = match intent_record {
        Some(r) => PendingIntent {
            intent_id: r.get("id"),
            agent_attestation_class: r.get("agent_attestation_class"),
            action_type: r.get("action_type"),
            requested_parameters: r.get("requested_parameters"),
        },
        None => return Err(HubError::IntentNotFound),
    };

    payload.action_type = intent.action_type.clone();
    payload.agent_attestation_class = intent.agent_attestation_class;
    payload.requested_parameters = intent.requested_parameters;

    let evaluator = state.evaluator.lock().await;
    let result = evaluator.evaluate_request(&payload, &intent_id)
        .map_err(HubError::PolicyDenied)?;

    let execution_mode = evaluator.skills.get(&intent.action_type)
        .map(|s| s.execution_mode.clone())
        .unwrap_or_default();
    drop(evaluator); // release lock before IO

    let EvaluationResult { token, computation_proof_hashes } = result;

    use std::time::{SystemTime, UNIX_EPOCH};
    use ed25519_dalek::Signer;

    match execution_mode {
        ExecutionMode::BrokerMediated => {
            let _result = state.broker.execute_capability(token);

            // Mint Execution Receipt
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let mut receipt_json = serde_json::json!({
                "action_type": intent.action_type,
                "intent_id": intent_id,
                "status": "executed"
            });
            if !computation_proof_hashes.is_empty() {
                receipt_json.as_object_mut().unwrap().insert(
                    "computation_proof_hashes".to_string(),
                    serde_json::json!(computation_proof_hashes),
                );
            }
            let payload_json = serde_json::to_string(&receipt_json).unwrap();
            let payload_bytes = payload_json.into_bytes();
            let signature = state.engine_signing_key.sign(&payload_bytes).to_bytes().to_vec();

            // Merkle Chain logic: fetch previous hash with FOR UPDATE to prevent race conditions
            let mut tx = state.db_pool.begin().await?;
            let prev_record = sqlx::query(
                "SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE"
            ).fetch_optional(&mut *tx).await?;

            let previous_hash_str = match prev_record {
                Some(record) => {
                    let mut hasher = Sha256::new();
                    let sig: Vec<u8> = record.get("signature");
                    hasher.update(&sig);
                    hex::encode(hasher.finalize())
                },
                None => "GENESIS".to_string(),
            };

            sqlx::query(
                "INSERT INTO audit_log (intent_id, action_type, receipt_payload, signature, previous_hash) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(&intent_id)
            .bind(&intent.action_type)
            .bind(&payload_bytes)
            .bind(&signature)
            .bind(&previous_hash_str)
            .execute(&mut *tx).await?;

            tx.commit().await?;

            let execution_receipt = schemas::governance::schemas::SignedDataRecord {
                source_id: "governance_hub".to_string(),
                version_id: "v1".to_string(),
                timestamp,
                payload: payload_bytes,
                signature,
            };

            Ok((StatusCode::OK, Json(serde_json::json!({
                "status": "success",
                "execution_receipt": execution_receipt
            }))))
        },
        ExecutionMode::SelfServiceToken => {
            // Write audit log entry for auditability (authorized but not broker-executed)
            let mut receipt_json = serde_json::json!({
                "action_type": intent.action_type,
                "intent_id": intent_id,
                "status": "authorized"
            });
            if !computation_proof_hashes.is_empty() {
                receipt_json.as_object_mut().unwrap().insert(
                    "computation_proof_hashes".to_string(),
                    serde_json::json!(computation_proof_hashes),
                );
            }
            let payload_json = serde_json::to_string(&receipt_json).unwrap();
            let payload_bytes = payload_json.into_bytes();
            let signature = state.engine_signing_key.sign(&payload_bytes).to_bytes().to_vec();

            let mut tx = state.db_pool.begin().await?;
            let prev_record = sqlx::query(
                "SELECT signature FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE"
            ).fetch_optional(&mut *tx).await?;

            let previous_hash_str = match prev_record {
                Some(record) => {
                    let mut hasher = Sha256::new();
                    let sig: Vec<u8> = record.get("signature");
                    hasher.update(&sig);
                    hex::encode(hasher.finalize())
                },
                None => "GENESIS".to_string(),
            };

            sqlx::query(
                "INSERT INTO audit_log (intent_id, action_type, receipt_payload, signature, previous_hash) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(&intent_id)
            .bind(&intent.action_type)
            .bind(&payload_bytes)
            .bind(&signature)
            .bind(&previous_hash_str)
            .execute(&mut *tx).await?;

            tx.commit().await?;

            // Return the signed capability token directly
            Ok((StatusCode::OK, Json(serde_json::json!({
                "status": "authorized",
                "capability_token": {
                    "token_id": token.token_id,
                    "action_type": token.action_type,
                    "audit_id": token.audit_id,
                    "expires_at": token.expires_at,
                    "effect_parameters": token.effect_parameters,
                    "engine_signature": hex::encode(&token.engine_signature)
                }
            }))))
        },
    }
}

async fn list_skills(
    State(state): State<Arc<AppState>>
) -> impl IntoResponse {
    let evaluator = state.evaluator.lock().await;
    let mut skills_list = Vec::new();
    for (skill_id, skill) in evaluator.skills.iter() {
        let mut skill_json = serde_json::json!({
            "skill_id": skill_id,
            "risk_classification": skill.contract.risk_classification,
            "execution_mode": skill.execution_mode,
            "requirements": skill.requirements.iter().map(|req| {
                let mut r = serde_json::json!({
                    "source_id": req.source_id,
                    "data_type": req.data_type
                });
                if let Some(url) = &req.oracle_url {
                    r.as_object_mut().unwrap().insert("oracle_url".to_string(), serde_json::json!(url));
                }
                r
            }).collect::<Vec<_>>(),
            "policy": skill.policy_src,
        });
        let obj = skill_json.as_object_mut().unwrap();
        if let Some(desc) = &skill.description {
            obj.insert("description".to_string(), serde_json::json!(desc));
        }
        if skill.contract.input_schema_json != "{}" {
            obj.insert("input_schema".to_string(), serde_json::json!(skill.contract.input_schema_json));
        }
        if skill.contract.output_schema_json != "{}" {
            obj.insert("output_schema".to_string(), serde_json::json!(skill.contract.output_schema_json));
        }
        if let Some(url) = &skill.downstream_url {
            obj.insert("downstream_url".to_string(), serde_json::json!(url));
        }
        skills_list.push(skill_json);
    }
    Json(serde_json::json!({ "skills": skills_list }))
}

async fn get_skill_md(
    State(state): State<Arc<AppState>>,
    Path(skill_id): Path<String>,
) -> impl IntoResponse {
    let evaluator = state.evaluator.lock().await;
    if let Some(skill) = evaluator.skills.get(&skill_id) {
        let mut md = format!("# Skill: {}\n\n", skill.contract.skill_id);

        // Optional description
        if let Some(desc) = &skill.description {
            md.push_str(&format!("{}\n\n", desc));
        }

        // Metadata
        let mode_str = match &skill.execution_mode {
            ExecutionMode::BrokerMediated => "broker_mediated",
            ExecutionMode::SelfServiceToken => "self_service_token",
        };
        md.push_str("## Metadata\n\n");
        md.push_str("| Field | Value |\n|-------|-------|\n");
        md.push_str(&format!("| Risk Level | {} |\n", skill.contract.risk_classification));
        md.push_str(&format!("| Execution Mode | {} |\n", mode_str));
        md.push_str(&format!("| Version | {} |\n", skill.contract.version));
        md.push_str("| Endpoint | `POST <HUB_URL>/v1/execute/<INTENT_ID>` |\n\n");

        // Input Schema
        if skill.contract.input_schema_json != "{}" {
            md.push_str("## Input Schema\n\n```json\n");
            md.push_str(&skill.contract.input_schema_json);
            md.push_str("\n```\n\n");
        }

        // Output Schema
        if skill.contract.output_schema_json != "{}" {
            md.push_str("## Output Schema\n\n```json\n");
            md.push_str(&skill.contract.output_schema_json);
            md.push_str("\n```\n\n");
        }

        // Execution steps
        md.push_str("## Execution Steps\n\n");

        // Step 1: Create Intent
        md.push_str("### Step 1: Create Intent\n\n");
        md.push_str(&format!(
            "POST `<HUB_URL>/v1/intent`\n\n```json\n{{\n  \"action_type\": \"{}\",\n  \"agent_attestation_class\": \"<YOUR_AGENT_CLASS>\",\n  \"requested_parameters\": {}\n}}\n```\n\nExtract `intent_id` from the response.\n\n",
            skill.contract.skill_id,
            if skill.contract.input_schema_json != "{}" { &skill.contract.input_schema_json } else { "{}" }
        ));

        // Steps 2..N: Oracle calls
        let mut step_num = 2;
        for req in &skill.requirements {
            if req.source_id == "governance_hub" {
                md.push_str(&format!("### Step {}: Prior Action — `{}`\n\n", step_num, req.data_type));
                md.push_str(&format!("Execute the prior action to obtain the `{}` receipt. Pass this into the `prior_execution_receipts` array in the final payload.\n\n", req.data_type));
            } else {
                md.push_str(&format!("### Step {}: Oracle `{}`\n\n", step_num, req.source_id));
                if let Some(desc) = &req.description {
                    md.push_str(&format!("{}\n\n", desc));
                }
                let method = req.oracle_method.as_deref().unwrap_or("POST");
                if let Some(url) = &req.oracle_url {
                    md.push_str(&format!("```\n{} {}\n```\n\n", method, url));
                } else {
                    md.push_str(&format!("Call Oracle `{}` using {} to obtain a `{}` receipt.\n\n", req.source_id, method, req.data_type));
                }
                if let Some(schema) = &req.oracle_request_schema {
                    md.push_str(&format!("Request body:\n\n```json\n{}\n```\n\n", schema));
                }
                md.push_str("The oracle **must** bind the receipt to your `intent_id`.\n\n");
            }
            step_num += 1;
        }

        // Final Step: Submit Proofs
        md.push_str(&format!("### Step {}: Submit Proofs\n\n", step_num));
        md.push_str("POST `<HUB_URL>/v1/execute/<INTENT_ID>`\n\n```json\n{\n  \"request_id\": \"<UNIQUE_REQUEST_ID>\",\n  \"external_data\": [\n");
        for (i, req) in skill.requirements.iter().enumerate() {
            if req.source_id != "governance_hub" {
                if i > 0 { md.push_str(",\n"); }
                md.push_str(&format!("    {{ \"source_id\": \"{}\", \"version_id\": \"v1\", \"timestamp\": 0, \"payload\": \"<BASE64>\", \"signature\": \"<BASE64>\" }}", req.source_id));
            }
        }
        md.push_str("\n  ],\n  \"prior_execution_receipts\": []\n}\n```\n\n");
        md.push_str("You do NOT need to provide `action_type` or `requested_parameters` — they are securely stored by the Hub.\n\n");

        // Token Presentation (self_service_token only)
        if matches!(skill.execution_mode, ExecutionMode::SelfServiceToken) {
            md.push_str("## Token Presentation\n\n");
            md.push_str("On success, the Hub returns a signed `capability_token`. Present it to the downstream service:\n\n");
            if let Some(url) = &skill.downstream_url {
                md.push_str(&format!("**Downstream URL**: `{}`\n\n", url));
            }
            if let Some(pres) = &skill.token_presentation {
                md.push_str(&format!("**Presentation**: `{}`\n\n", pres));
            }
        }

        // Cedar Policy
        md.push_str("## Cedar Policy\n\n```cedar\n");
        md.push_str(&skill.policy_src);
        md.push_str("\n```\n");

        (StatusCode::OK, md).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Skill not found".to_string()).into_response()
    }
}

async fn create_intent(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateIntentReq>,
) -> Result<impl IntoResponse, HubError> {
    let mut csprng = OsRng;
    let intent_id = format!("int-{:x}", csprng.next_u64());

    let requested_params_bytes = serde_json::to_vec(&payload.requested_parameters).unwrap_or_default();

    sqlx::query(
        "INSERT INTO intents (id, agent_attestation_class, action_type, requested_parameters) VALUES ($1, $2, $3, $4)"
    )
    .bind(&intent_id)
    .bind(&payload.agent_attestation_class)
    .bind(&payload.action_type)
    .bind(&requested_params_bytes)
    .execute(&state.db_pool).await?;

    let evaluator = state.evaluator.lock().await;
    let skill = evaluator.skills.get(&payload.action_type)
        .ok_or_else(|| HubError::BadRequest(format!("Unknown action_type: {}", payload.action_type)))?;

    let reqs: Vec<_> = skill.requirements.iter().map(|r| {
        serde_json::json!({
            "source_id": r.source_id,
            "data_type": r.data_type
        })
    }).collect();

    Ok((StatusCode::OK, Json(serde_json::json!({
        "intent_id": intent_id,
        "requirements": reqs
    }))))
}

async fn list_computations(
    State(state): State<Arc<AppState>>
) -> impl IntoResponse {
    let evaluator = state.evaluator.lock().await;
    let mut comps_list = Vec::new();
    for (_, comp) in evaluator.computation_registry.records.iter() {
        comps_list.push(serde_json::json!({
            "computation_id": comp.computation_id,
            "code_hash": comp.code_hash,
            "version": comp.version,
            "audit_status": comp.audit_status,
            "consumes": comp.consumes,
            "description": comp.description,
        }));
    }
    Json(serde_json::json!({ "computations": comps_list }))
}

async fn get_computation(
    State(state): State<Arc<AppState>>,
    Path(computation_id): Path<String>,
) -> impl IntoResponse {
    let evaluator = state.evaluator.lock().await;
    if let Some(comp) = evaluator.computation_registry.get_record(&computation_id) {
        let comp_json = serde_json::json!({
            "computation_id": comp.computation_id,
            "code_hash": comp.code_hash,
            "version": comp.version,
            "audit_status": comp.audit_status,
            "consumes": comp.consumes,
            "description": comp.description,
        });
        (StatusCode::OK, Json(comp_json)).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Computation not found" }))).into_response()
    }
}

