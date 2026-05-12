permit(
    principal,
    action == Action::"release_medical_records",
    resource
) when {
    (principal == Agent::"records_clerk_agent_v1" ||
     principal == Agent::"physician_agent_v1") &&
    context.patient_consent_verified == true &&
    context.hipaa_compliant == true &&
    context.audit_logged == true &&
    (if context.contains_part2_data == true then
        context.part2_consent_verified == true else true)
};
