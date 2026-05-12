use schemas::governance::schemas::{ActionRequest, CapabilityToken, SignedDataRecord, SkillContract};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature, Verifier};
use std::str::FromStr;
use std::fs;
use std::path::Path;
use cedar_policy::{Authorizer, Context, Decision, Entities, PolicySet, Request};
use serde_json::Value;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use crate::computation_verifier::ComputationVerifier;
use crate::computation_registry::ComputationRegistry;

/// Result of a successful policy evaluation, containing the capability token
/// and metadata about any computation proofs that were verified.
#[derive(Debug)]
pub struct EvaluationResult {
    pub token: CapabilityToken,
    pub computation_proof_hashes: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, PartialEq, Debug)]
pub enum ExecutionMode {
    #[serde(rename = "broker_mediated")]
    BrokerMediated,
    #[serde(rename = "self_service_token")]
    SelfServiceToken,
}

impl Default for ExecutionMode {
    fn default() -> Self {
        ExecutionMode::BrokerMediated
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone)]
pub struct SkillRequirement {
    pub source_id: String,
    pub data_type: String, // e.g., "ehr_data", "patient_consent"
    #[serde(default)]
    pub description: Option<String>,           // what the oracle verifies
    #[serde(default)]
    pub oracle_url: Option<String>,            // endpoint URL
    #[serde(default)]
    pub oracle_method: Option<String>,         // HTTP method (defaults to POST in template)
    #[serde(default)]
    pub oracle_request_schema: Option<String>, // example request body
}

#[derive(Clone)]
pub struct RegisteredSkill {
    pub contract: SkillContract,
    pub requirements: Vec<SkillRequirement>,
    pub policy_src: String,
    pub execution_mode: ExecutionMode,
    pub description: Option<String>,
    pub downstream_url: Option<String>,
    pub token_presentation: Option<String>,
}

#[derive(serde::Deserialize)]
struct SkillConfig {
    contract: SkillContract,
    requirements: Vec<SkillRequirement>,
    policy_file: String,
    #[serde(default)]
    execution_mode: ExecutionMode,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    downstream_url: Option<String>,
    #[serde(default)]
    token_presentation: Option<String>,
}

#[derive(serde::Deserialize)]
struct SkillsRegistryConfig {
    skills: Vec<SkillConfig>,
}

pub struct PolicyEvaluator {
    pub trusted_ingest_pubkeys: HashMap<String, [u8; 32]>,
    pub skills: HashMap<String, RegisteredSkill>,
    pub computation_registry: ComputationRegistry,
    pub verifiers: HashMap<String, Box<dyn ComputationVerifier>>,
    engine_signing_key: Option<SigningKey>,
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            trusted_ingest_pubkeys: HashMap::new(),
            skills: HashMap::new(),
            computation_registry: ComputationRegistry::new(),
            verifiers: HashMap::new(),
            engine_signing_key: None,
        }
    }

    pub fn register_computation_verifier<V: ComputationVerifier + 'static>(&mut self, verifier: V) {
        self.verifiers.insert(verifier.proof_type().to_string(), Box::new(verifier));
    }

    pub fn set_signing_key(&mut self, key: SigningKey) {
        self.engine_signing_key = Some(key);
    }

    pub fn load_from_config(&mut self, config_dir: &str) -> Result<(), String> {
        let skills_path = Path::new(config_dir).join("skills.json");
        let skills_json = fs::read_to_string(&skills_path)
            .map_err(|e| format!("Failed to read skills.json: {}", e))?;
            
        let registry: SkillsRegistryConfig = serde_json::from_str(&skills_json)
            .map_err(|e| format!("Failed to parse skills.json: {}", e))?;
            
        for skill_cfg in registry.skills {
            // policy_file is just the filename now (e.g. prescribe_medication.cedar)
            // It might still be a path if migrating, so we just join it to config_dir/policies if it doesn't already have it, or simply assume it's just the filename.
            // Let's strip any "config/policies/" prefix if it exists to be safe during migration
            let clean_filename = skill_cfg.policy_file.replace("config/policies/", "");
            let policy_path = Path::new(config_dir).join("policies").join(clean_filename);
            
            let policy_src = fs::read_to_string(&policy_path)
                .map_err(|e| format!("Failed to read policy file {}: {}", policy_path.display(), e))?;
                
            let registered_skill = RegisteredSkill {
                contract: skill_cfg.contract,
                requirements: skill_cfg.requirements,
                policy_src,
                execution_mode: skill_cfg.execution_mode,
                description: skill_cfg.description,
                downstream_url: skill_cfg.downstream_url,
                token_presentation: skill_cfg.token_presentation,
            };
            self.register_skill(registered_skill);
        }
        Ok(())
    }

    pub fn register_trusted_source(&mut self, source_id: &str, pubkey: [u8; 32]) {
        self.trusted_ingest_pubkeys.insert(source_id.to_string(), pubkey);
    }

    pub fn register_skill(&mut self, skill: RegisteredSkill) {
        self.skills.insert(skill.contract.skill_id.clone(), skill);
    }

    pub fn evaluate_request(&self, request: &ActionRequest, expected_intent_id: &str) -> Result<EvaluationResult, String> {
        // 1. Lookup the Skill
        let skill = self.skills.get(&request.action_type)
            .ok_or_else(|| format!("Unknown action/skill: {}", request.action_type))?;

        // 2. Validate all mandatory requirements (Proofs) are present and signed
        // Verify all required proofs are present
        for req in &skill.requirements {
            let found_external = request.external_data.iter().any(|r| r.source_id == req.source_id);
            let found_prior = request.prior_execution_receipts.iter().any(|r| r.source_id == req.source_id);
            if !found_external && !found_prior {
                return Err(format!("Missing mandatory proof from source: {}", req.source_id));
            }
        }

        let mut context_map = serde_json::Map::new();

        let all_proofs = request.external_data.iter().chain(request.prior_execution_receipts.iter());
        for req in &skill.requirements {
            let proof = all_proofs.clone()
                .find(|d| d.source_id == req.source_id)
                .ok_or_else(|| format!("Missing mandatory proof from source: {}", req.source_id))?;

            self.verify_data_signature(proof)?;

            // Extract data into policy context
            let payload_str = String::from_utf8_lossy(&proof.payload);
            let json_val: Value = serde_json::from_str(&payload_str)
                .map_err(|_| format!("Invalid JSON payload from source: {}", req.source_id))?;
            
            // Merge into context (simplified: flat merge)
            if let Some(obj) = json_val.as_object() {
                // Verify intent_id mathematically prevents replay attacks (skip for prior actions)
                if req.source_id != "governance_hub" {
                    if let Some(id_val) = obj.get("intent_id") {
                        if let Some(id_str) = id_val.as_str() {
                            if id_str != expected_intent_id {
                                return Err(format!("Replay Attack Prevented! Intent ID mismatch in receipt from: {}", req.source_id));
                            }
                        }
                    } else {
                        return Err(format!("Missing intent_id in receipt from {}", req.source_id));
                    }
                }

                for (k, v) in obj {
                    context_map.insert(k.clone(), v.clone());
                }
            }
        }

        // Merge requested_parameters into context
        let req_params_str = String::from_utf8_lossy(&request.requested_parameters);
        if let Ok(Value::Object(obj)) = serde_json::from_str(&req_params_str) {
            for (k, v) in obj {
                context_map.insert(k, v);
            }
        }

        // Build a map of payload hashes for verified oracle data (computed by the hub, not trusted from oracle)
        let verified_payload_hashes: HashMap<String, &str> = request.external_data.iter()
            .chain(request.prior_execution_receipts.iter())
            .map(|r| {
                let mut hasher = Sha256::new();
                hasher.update(&r.payload);
                let hash = hex::encode(hasher.finalize());
                (hash, r.source_id.as_str())
            })
            .collect();

        // Verify computation proofs
        let mut computation_proof_hashes: Vec<String> = Vec::new();

        if !request.computation_proofs.is_empty() {
            let mut computations_context = Vec::new();

            for proof in &request.computation_proofs {
                // Input binding: every claimed input hash must match a hub-computed sha256(payload)
                for hash_str in &proof.input_data_hashes {
                    if !verified_payload_hashes.contains_key(hash_str.as_str()) {
                        return Err(format!(
                            "Computation proof references input hash {} which does not match any verified oracle payload",
                            hash_str
                        ));
                    }
                }

                // Code hash check against registry
                let reg_record = self.computation_registry.get_record(&proof.computation_id)
                    .ok_or_else(|| format!("Computation ID {} not found in registry", proof.computation_id))?;

                if reg_record.code_hash != proof.code_hash {
                    return Err(format!("Computation proof code hash mismatch for {}", proof.computation_id));
                }

                if reg_record.audit_status != "certified" {
                    return Err(format!(
                        "Computation {} has audit_status '{}', expected 'certified'",
                        proof.computation_id, reg_record.audit_status
                    ));
                }

                // Verify input hashes only reference oracle source_ids the computation is authorized to consume
                if !reg_record.consumes.is_empty() {
                    for hash_str in &proof.input_data_hashes {
                        if let Some(source_id) = verified_payload_hashes.get(hash_str.as_str()) {
                            if !reg_record.consumes.iter().any(|c| c == source_id) {
                                return Err(format!(
                                    "Computation {} is not authorized to consume data from source '{}' (allowed: {:?})",
                                    proof.computation_id, source_id, reg_record.consumes
                                ));
                            }
                        }
                    }
                }

                // Proof verification: dispatch to registered verifier
                let proof_type = if let Some(tee) = &proof.tee_attestation {
                    tee.platform.clone()
                } else if let Some(zk) = &proof.zk_proof {
                    zk.proof_system.clone()
                } else {
                    return Err("Computation proof missing both TEE and ZK proofs".to_string());
                };

                let verifier = self.verifiers.get(&proof_type)
                    .ok_or_else(|| format!("No verifier registered for proof type: {}", proof_type))?;

                let verified_output = verifier.verify(proof, &reg_record.code_hash, &proof.input_data_hashes)
                    .map_err(|e| format!("Computation verification failed: {}", e))?;

                // Inject output payload into context
                if let Some(obj) = verified_output.payload.as_object() {
                    for (k, v) in obj {
                        context_map.insert(k.clone(), v.clone());
                    }
                }

                // Track for audit log
                computation_proof_hashes.push(reg_record.code_hash.clone());
                for h in &proof.input_data_hashes {
                    computation_proof_hashes.push(h.clone());
                }

                // Build per-proof context entry
                computations_context.push(serde_json::json!({
                    "computation_id": reg_record.computation_id,
                    "code_hash": reg_record.code_hash,
                    "audit_status": reg_record.audit_status,
                    "proof_type": proof_type,
                    "input_bound": true,
                    "verified": true,
                }));
            }

            // Inject computation context as an array (supports multiple proofs)
            context_map.insert("computation_verified".to_string(), Value::Bool(true));
            context_map.insert("computation_input_bound".to_string(), Value::Bool(true));
            context_map.insert("computations".to_string(), Value::Array(computations_context));

            // For single-proof convenience, also set scalar fields from the first proof
            if let Some(first) = request.computation_proofs.first() {
                if let Some(reg) = self.computation_registry.get_record(&first.computation_id) {
                    context_map.insert("computation_id".to_string(), Value::String(reg.computation_id.clone()));
                    context_map.insert("computation_code_hash".to_string(), Value::String(reg.code_hash.clone()));
                    context_map.insert("computation_audit_status".to_string(), Value::String(reg.audit_status.clone()));
                }
                let pt = if let Some(tee) = &first.tee_attestation {
                    &tee.platform
                } else if let Some(zk) = &first.zk_proof {
                    &zk.proof_system
                } else {
                    ""
                };
                context_map.insert("computation_proof_type".to_string(), Value::String(pt.to_string()));
            }
        }

        // Verify prior execution receipts (Action Composability)
        let mut prior_actions = serde_json::Map::new();
        for receipt in &request.prior_execution_receipts {
            self.verify_data_signature(receipt)?;
            
            let payload_str = String::from_utf8_lossy(&receipt.payload);
            if let Ok(json_val) = serde_json::from_str::<Value>(&payload_str) {
                if let Some(obj) = json_val.as_object() {
                    if let Some(action_type) = obj.get("action_type").and_then(|v| v.as_str()) {
                        prior_actions.insert(action_type.to_string(), json_val.clone());
                    }
                }
            }
        }
        if !prior_actions.is_empty() {
            context_map.insert("prior_actions".to_string(), Value::Object(prior_actions));
        }

        // 3. Evaluate Cedar Policy
        let policy_set = PolicySet::from_str(&skill.policy_src)
            .map_err(|e| format!("Policy Error: {}", e))?;

        let principal = format!(r#"Agent::"{}""#, request.agent_attestation_class).parse().unwrap();
        let action = format!(r#"Action::"{}""#, request.action_type).parse().unwrap();
        let resource = r#"System::"Core""#.parse().unwrap();
        
        let context = Context::from_json_value(Value::Object(context_map), None)
            .map_err(|e| format!("Failed to build context: {}", e))?;

        let cedar_request = Request::new(Some(principal), Some(action), Some(resource), context, None).unwrap();
        let entities = Entities::empty();
        let authorizer = Authorizer::new();
        
        let decision = authorizer.is_authorized(&cedar_request, &policy_set, &entities);

        if decision.decision() == Decision::Allow {
            let token_id = format!("CT-{}", request.request_id);
            let audit_id = format!("AUDIT-{}", request.request_id);
            let canonical = format!("{}:{}:{}", token_id, request.action_type, audit_id);
            let engine_signature = match &self.engine_signing_key {
                Some(key) => key.sign(canonical.as_bytes()).to_bytes().to_vec(),
                None => vec![],
            };
            Ok(EvaluationResult {
                token: CapabilityToken {
                    token_id,
                    action_type: request.action_type.clone(),
                    audit_id,
                    expires_at: 0,
                    effect_parameters: request.requested_parameters.clone(),
                    engine_signature,
                },
                computation_proof_hashes,
            })
        } else {
            let diagnostics = decision.diagnostics();
            let reasons: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();
            Err(format!("Policy Denied. Reasons: {:?}", reasons))
        }
    }

    fn verify_data_signature(&self, data: &SignedDataRecord) -> Result<(), String> {
        let pubkey_bytes = self.trusted_ingest_pubkeys.get(&data.source_id)
            .ok_or_else(|| format!("Untrusted data source: {}", data.source_id))?;

        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|_| "Invalid public key in registry".to_string())?;

        let sig_bytes: [u8; 64] = data.signature.as_slice().try_into()
            .map_err(|_| "Invalid signature length".to_string())?;

        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key.verify(&data.payload, &signature)
            .map_err(|_| "Signature verification failed".to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    const ALLOW_ALL_POLICY: &str = r#"
permit(principal, action, resource);
"#;

    const DENY_ALL_POLICY: &str = r#"
forbid(principal, action, resource);
"#;

    fn make_evaluator_with_key() -> (PolicyEvaluator, SigningKey, SigningKey) {
        let mut csprng = OsRng;
        let engine_key = SigningKey::generate(&mut csprng);
        let source_key = SigningKey::generate(&mut csprng);

        let mut eval = PolicyEvaluator::new();
        eval.set_signing_key(engine_key.clone());
        eval.register_trusted_source("test_oracle", source_key.verifying_key().to_bytes());
        (eval, engine_key, source_key)
    }

    fn make_signed_proof(source_key: &SigningKey, source_id: &str, intent_id: &str) -> SignedDataRecord {
        let payload = format!(r#"{{"intent_id":"{}","status":"ok"}}"#, intent_id).into_bytes();
        let signature = source_key.sign(&payload).to_bytes().to_vec();
        SignedDataRecord {
            source_id: source_id.to_string(),
            version_id: "v1".to_string(),
            timestamp: 1000,
            payload,
            signature,
        }
    }

    fn register_test_skill(eval: &mut PolicyEvaluator, policy: &str) {
        register_test_skill_with_mode(eval, policy, ExecutionMode::BrokerMediated);
    }

    fn register_test_skill_with_mode(eval: &mut PolicyEvaluator, policy: &str, mode: ExecutionMode) {
        eval.register_skill(RegisteredSkill {
            contract: SkillContract {
                skill_id: "test_action".to_string(),
                version: "1.0.0".to_string(),
                risk_classification: "internal_effect".to_string(),
                input_schema_json: "{}".to_string(),
                output_schema_json: "{}".to_string(),
                consumes_prerequisites: vec![],
                produces_prerequisites: vec![],
            },
            requirements: vec![SkillRequirement {
                source_id: "test_oracle".to_string(),
                data_type: "test_data".to_string(),
                description: None,
                oracle_url: None,
                oracle_method: None,
                oracle_request_schema: None,
            }],
            policy_src: policy.to_string(),
            execution_mode: mode,
            description: None,
            downstream_url: None,
            token_presentation: None,
        });
    }

    #[test]
    fn test_evaluate_request_approved() {
        let (mut eval, _engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        let intent_id = "int-abc123";
        let proof = make_signed_proof(&source_key, "test_oracle", intent_id);

        let request = ActionRequest {
            request_id: "req-1".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval.evaluate_request(&request, intent_id);
        assert!(result.is_ok());
        let eval_result = result.unwrap();
        assert_eq!(eval_result.token.token_id, "CT-req-1");
        assert_eq!(eval_result.token.action_type, "test_action");
        assert!(!eval_result.token.engine_signature.is_empty());
        assert!(eval_result.computation_proof_hashes.is_empty());
    }

    #[test]
    fn test_evaluate_request_denied_by_policy() {
        let (mut eval, _engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, DENY_ALL_POLICY);

        let intent_id = "int-deny";
        let proof = make_signed_proof(&source_key, "test_oracle", intent_id);

        let request = ActionRequest {
            request_id: "req-2".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval.evaluate_request(&request, intent_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Policy Denied"));
    }

    #[test]
    fn test_replay_attack_prevention() {
        let (mut eval, _engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        // Proof is bound to "int-original" but we pass "int-different"
        let proof = make_signed_proof(&source_key, "test_oracle", "int-original");

        let request = ActionRequest {
            request_id: "req-3".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval.evaluate_request(&request, "int-different");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Replay Attack Prevented"));
    }

    #[test]
    fn test_untrusted_source_rejected() {
        let (mut eval, _engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        // Register skill requirement for "test_oracle" but provide proof from "unknown_oracle"
        let mut eval2 = PolicyEvaluator::new();
        eval2.set_signing_key(SigningKey::generate(&mut OsRng));
        // Register skill that requires "unknown_source"
        eval2.register_skill(RegisteredSkill {
            contract: SkillContract {
                skill_id: "test_action".to_string(),
                version: "1.0.0".to_string(),
                risk_classification: "internal_effect".to_string(),
                input_schema_json: "{}".to_string(),
                output_schema_json: "{}".to_string(),
                consumes_prerequisites: vec![],
                produces_prerequisites: vec![],
            },
            requirements: vec![SkillRequirement {
                source_id: "unknown_source".to_string(),
                data_type: "test_data".to_string(),
                description: None,
                oracle_url: None,
                oracle_method: None,
                oracle_request_schema: None,
            }],
            policy_src: ALLOW_ALL_POLICY.to_string(),
            execution_mode: ExecutionMode::BrokerMediated,
            description: None,
            downstream_url: None,
            token_presentation: None,
        });

        let intent_id = "int-untrusted";
        let proof = make_signed_proof(&source_key, "unknown_source", intent_id);

        let request = ActionRequest {
            request_id: "req-4".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval2.evaluate_request(&request, intent_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Untrusted data source"));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (mut eval, _engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        let intent_id = "int-tamper";
        let mut proof = make_signed_proof(&source_key, "test_oracle", intent_id);
        // Flip a byte in the signature
        proof.signature[0] ^= 0xFF;

        let request = ActionRequest {
            request_id: "req-5".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval.evaluate_request(&request, intent_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Signature verification failed"));
    }

    #[test]
    fn test_missing_required_proof() {
        let (mut eval, _engine_key, _source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        let request = ActionRequest {
            request_id: "req-6".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let result = eval.evaluate_request(&request, "int-missing");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing mandatory proof"));
    }

    #[test]
    fn test_token_signature_is_verifiable() {
        let (mut eval, engine_key, source_key) = make_evaluator_with_key();
        register_test_skill(&mut eval, ALLOW_ALL_POLICY);

        let intent_id = "int-verify";
        let proof = make_signed_proof(&source_key, "test_oracle", intent_id);

        let request = ActionRequest {
            request_id: "req-7".to_string(),
            agent_attestation_class: "test_agent".to_string(),
            action_type: "test_action".to_string(),
            requested_parameters: b"{}".to_vec(),
            external_data: vec![proof],
            prior_execution_receipts: vec![],
            computation_proofs: vec![],
        };

        let eval_result = eval.evaluate_request(&request, intent_id).unwrap();

        // Verify the token signature using the broker's verification logic
        let broker = broker::credential_broker::CredentialBroker::new(
            engine_key.verifying_key().to_bytes()
        ).unwrap();
        let result = broker.execute_capability(eval_result.token);
        assert!(result.is_ok());
    }
}
