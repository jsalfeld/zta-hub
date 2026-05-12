pub mod base64_serde;

pub mod governance {
    pub mod schemas {
        include!(concat!(env!("OUT_DIR"), "/governance.schemas.rs"));
    }
}
