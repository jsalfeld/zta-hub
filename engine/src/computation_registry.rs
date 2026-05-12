use schemas::governance::schemas::ComputationRecord;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn, error};
use std::fs;

#[derive(Clone, Default)]
pub struct ComputationRegistry {
    pub records: HashMap<String, ComputationRecord>,
}

impl ComputationRegistry {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn load_from_dir(&mut self, config_dir: &str) -> Result<(), String> {
        let computations_dir = Path::new(config_dir).join("computations");
        if !computations_dir.exists() {
            warn!("No computations directory found at {}", computations_dir.display());
            return Ok(());
        }

        for entry in fs::read_dir(&computations_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.is_file() && path.extension().unwrap_or_default() == "json" {
                let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
                match serde_json::from_str::<ComputationRecord>(&content) {
                    Ok(record) => {
                        info!("Loaded computation record: {}", record.computation_id);
                        self.records.insert(record.computation_id.clone(), record);
                    }
                    Err(e) => {
                        error!("Failed to parse computation record in {}: {}", path.display(), e);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_record(&self, computation_id: &str) -> Option<&ComputationRecord> {
        self.records.get(computation_id)
    }
}
