use schemas::governance::schemas::AuditReceipt;
use sha2::{Sha256, Digest};

pub struct AuditLog {
    pub entries: Vec<AuditReceipt>,
    pub merkle_roots: Vec<[u8; 32]>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            merkle_roots: Vec::new(),
        }
    }

    pub fn append(&mut self, receipt: AuditReceipt) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Mock serialization for hash
        hasher.update(receipt.audit_id.as_bytes());
        hasher.update(receipt.decision.as_bytes());
        let hash = hasher.finalize().into();
        
        self.entries.push(receipt);
        self.merkle_roots.push(hash);
        
        hash
    }

    pub fn latest_root(&self) -> Option<[u8; 32]> {
        self.merkle_roots.last().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt(audit_id: &str, decision: &str) -> AuditReceipt {
        AuditReceipt {
            audit_id: audit_id.to_string(),
            request_id: "req-1".to_string(),
            decision: decision.to_string(),
            policy_version_hash: "hash1".to_string(),
            evaluated_data_hashes: vec![],
            generated_token_id: "".to_string(),
            engine_signature: vec![],
        }
    }

    #[test]
    fn test_empty_log_has_no_root() {
        let log = AuditLog::new();
        assert!(log.latest_root().is_none());
    }

    #[test]
    fn test_append_produces_root() {
        let mut log = AuditLog::new();
        let hash = log.append(make_receipt("audit-1", "APPROVED"));
        assert_eq!(log.latest_root(), Some(hash));
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn test_chain_integrity_different_inputs() {
        let mut log = AuditLog::new();
        let hash1 = log.append(make_receipt("audit-1", "APPROVED"));
        let hash2 = log.append(make_receipt("audit-2", "DENIED"));
        assert_ne!(hash1, hash2);
        assert_eq!(log.merkle_roots.len(), 2);
    }

    #[test]
    fn test_deterministic_hashing() {
        let mut log1 = AuditLog::new();
        let mut log2 = AuditLog::new();
        let hash1 = log1.append(make_receipt("audit-x", "APPROVED"));
        let hash2 = log2.append(make_receipt("audit-x", "APPROVED"));
        assert_eq!(hash1, hash2);
    }
}
