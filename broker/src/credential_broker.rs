use schemas::governance::schemas::CapabilityToken;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

pub struct CredentialBroker {
    engine_pubkey: VerifyingKey,
}

impl CredentialBroker {
    pub fn new(engine_pubkey_bytes: [u8; 32]) -> Result<Self, String> {
        let engine_pubkey = VerifyingKey::from_bytes(&engine_pubkey_bytes)
            .map_err(|_| "Invalid engine pubkey".to_string())?;
        Ok(Self { engine_pubkey })
    }

    /// Verifies the capability token and executes the legacy side-effect
    pub fn execute_capability(&self, token: CapabilityToken) -> Result<(), String> {
        self.verify_token_signature(&token)?;

        tracing::info!(action_type = %token.action_type, audit_id = %token.audit_id, "Token verified, executing capability");
        Ok(())
    }

    fn verify_token_signature(&self, token: &CapabilityToken) -> Result<(), String> {
        let sig_bytes: [u8; 64] = token.engine_signature.as_slice().try_into()
            .map_err(|_| "Invalid signature length".to_string())?;

        let signature = Signature::from_bytes(&sig_bytes);

        let canonical = format!("{}:{}:{}", token.token_id, token.action_type, token.audit_id);

        self.engine_pubkey.verify(canonical.as_bytes(), &signature)
            .map_err(|_| "Invalid token signature".to_string())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use rand::rngs::OsRng;

    fn make_signed_token(key: &SigningKey) -> CapabilityToken {
        let token_id = "CT-test".to_string();
        let action_type = "test_action".to_string();
        let audit_id = "AUDIT-test".to_string();
        let canonical = format!("{}:{}:{}", token_id, action_type, audit_id);
        let signature = key.sign(canonical.as_bytes()).to_bytes().to_vec();

        CapabilityToken {
            token_id,
            action_type,
            audit_id,
            expires_at: 0,
            effect_parameters: vec![],
            engine_signature: signature,
        }
    }

    #[test]
    fn test_valid_token_accepted() {
        let key = SigningKey::generate(&mut OsRng);
        let broker = CredentialBroker::new(key.verifying_key().to_bytes()).unwrap();
        let token = make_signed_token(&key);
        assert!(broker.execute_capability(token).is_ok());
    }

    #[test]
    fn test_tampered_token_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let broker = CredentialBroker::new(key.verifying_key().to_bytes()).unwrap();
        let mut token = make_signed_token(&key);
        token.action_type = "tampered_action".to_string();
        assert!(broker.execute_capability(token).is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let broker = CredentialBroker::new(key.verifying_key().to_bytes()).unwrap();
        let token = make_signed_token(&wrong_key);
        assert!(broker.execute_capability(token).is_err());
    }

    #[test]
    fn test_empty_signature_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let broker = CredentialBroker::new(key.verifying_key().to_bytes()).unwrap();
        let token = CapabilityToken {
            token_id: "CT-test".to_string(),
            action_type: "test_action".to_string(),
            audit_id: "AUDIT-test".to_string(),
            expires_at: 0,
            effect_parameters: vec![],
            engine_signature: vec![],
        };
        assert!(broker.execute_capability(token).is_err());
    }
}
