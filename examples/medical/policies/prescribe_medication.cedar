permit(
    principal,
    action == Action::"prescribe_medication",
    resource
) when {
    principal == Agent::"physician_agent_v1" &&
    context.drug_interaction_cleared == true &&
    context.dea_license_valid == true &&
    context.patient_age >= 18 &&
    (if context.is_controlled_substance == true then
        context.dea_schedule_authorized == true else true) &&
    (if context.is_transfer_patient == true then
        context.prior_actions.release_medical_records.status == "executed" else true)
};
