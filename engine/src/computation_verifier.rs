use schemas::governance::schemas::ComputationProof;
use serde_json::Value;

#[derive(Debug)]
pub enum VerificationError {
    InvalidProof,
    InputHashMismatch,
    CodeHashMismatch,
    UnsupportedProofType,
    OutputDeserializationFailed(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidProof => write!(f, "Invalid proof signature/attestation"),
            VerificationError::InputHashMismatch => write!(f, "Input hash mismatch"),
            VerificationError::CodeHashMismatch => write!(f, "Code hash mismatch"),
            VerificationError::UnsupportedProofType => write!(f, "Unsupported proof type"),
            VerificationError::OutputDeserializationFailed(e) => write!(f, "Output deserialization failed: {}", e),
        }
    }
}

impl std::error::Error for VerificationError {}

pub struct VerifiedOutput {
    pub payload: Value,
    pub verified_code_hash: String,
}

pub trait ComputationVerifier: Send + Sync {
    /// Verify a computation proof and return the verified output
    fn verify(
        &self,
        proof: &ComputationProof,
        registered_code_hash: &str,
        expected_input_hashes: &[String],
    ) -> Result<VerifiedOutput, VerificationError>;

    /// Which proof type this verifier handles
    fn proof_type(&self) -> &str;
}

/// A mock verifier for local testing that automatically passes if the platform matches "mock".
pub struct MockVerifier;

impl Default for MockVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MockVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl ComputationVerifier for MockVerifier {
    fn verify(
        &self,
        proof: &ComputationProof,
        registered_code_hash: &str,
        expected_input_hashes: &[String],
    ) -> Result<VerifiedOutput, VerificationError> {
        if proof.code_hash != registered_code_hash {
            return Err(VerificationError::CodeHashMismatch);
        }

        // Just basic mock validation: if it has tee_attestation and platform is "mock", pass.
        // Otherwise, error.
        let is_valid = if let Some(tee) = &proof.tee_attestation {
            tee.platform == "mock"
        } else if let Some(zk) = &proof.zk_proof {
            zk.proof_system == "mock"
        } else {
            false
        };

        if !is_valid {
            return Err(VerificationError::InvalidProof);
        }
        
        let mut all_match = true;
        for hash in expected_input_hashes {
            if !proof.input_data_hashes.contains(hash) {
                all_match = false;
                break;
            }
        }
        if !all_match {
            return Err(VerificationError::InputHashMismatch);
        }

        let payload: Value = serde_json::from_slice(&proof.output_payload)
            .map_err(|e| VerificationError::OutputDeserializationFailed(e.to_string()))?;

        Ok(VerifiedOutput {
            payload,
            verified_code_hash: registered_code_hash.to_string(),
        })
    }

    fn proof_type(&self) -> &str {
        "mock"
    }
}
