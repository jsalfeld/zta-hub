use schemas::governance::schemas::ActionRequest;
use crate::policy_evaluator::PolicyEvaluator;

/// Represents the host environment orchestration layer that runs the WASM engine
pub struct EngineOrchestrator {
    evaluator: PolicyEvaluator,
}

impl EngineOrchestrator {
    pub fn new(evaluator: PolicyEvaluator) -> Self {
        Self { evaluator }
    }

    /// Assembles the request, injects data, and calls the deterministic evaluator
    pub fn submit_action(&self, request: ActionRequest, intent_id: &str) {
        // In a real system, the evaluator runs inside isolated WASM to guarantee determinism.
        // We pass the fully formed ActionRequest bundle in.
        match self.evaluator.evaluate_request(&request, intent_id) {
            Ok(result) => tracing::info!(token_id = %result.token.token_id, "Action approved, capability minted"),
            Err(e) => tracing::warn!(reason = %e, "Action denied"),
        }
    }
}
