/// Mock external monotonic log (e.g., AWS QLDB or internal Trillian)
pub struct ExternalMonotonicLog {
    roots: Vec<[u8; 32]>,
}

impl ExternalMonotonicLog {
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    pub fn anchor_root(&mut self, root: [u8; 32]) {
        self.roots.push(root);
    }

    pub fn verify_latest_root(&self, proposed_root: [u8; 32]) -> bool {
        if let Some(latest) = self.roots.last() {
            latest == &proposed_root
        } else {
            false
        }
    }
}
