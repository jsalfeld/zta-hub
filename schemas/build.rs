fn main() {
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(default)]");

    // Use base64 encoding for all bytes fields
    let bytes_fields = [
        ".governance.schemas.SignedDataRecord.payload",
        ".governance.schemas.SignedDataRecord.signature",
        ".governance.schemas.CapabilityToken.effect_parameters",
        ".governance.schemas.CapabilityToken.engine_signature",
        ".governance.schemas.ActionRequest.requested_parameters",
        ".governance.schemas.AuditReceipt.engine_signature",
        ".governance.schemas.TEEAttestation.attestation_report",
        ".governance.schemas.ZKProof.verification_key",
        ".governance.schemas.ZKProof.proof",
        ".governance.schemas.ZKProof.public_inputs",
        ".governance.schemas.ComputationProof.output_payload",
        ".governance.schemas.ComputationProof.output_hash",
    ];
    for field in bytes_fields {
        config.field_attribute(field, "#[serde(with = \"crate::base64_serde\")]");
    }

    config.compile_protos(
        &[
            "proto/capability_token.proto",
            "proto/action_request.proto",
            "proto/skill_contract.proto",
            "proto/audit_receipt.proto",
            "proto/computation_record.proto",
        ],
        &["proto/"],
    ).unwrap();
}
