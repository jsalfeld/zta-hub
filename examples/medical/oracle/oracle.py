import os
import time
import json
import binascii
from flask import Flask, request, jsonify
import nacl.signing

app = Flask(__name__)

# Load Private Key
priv_hex = os.environ.get("ORACLE_PRIVATE_KEY_HEX")
if not priv_hex:
    raise RuntimeError("ORACLE_PRIVATE_KEY_HEX environment variable is required")

try:
    signing_key = nacl.signing.SigningKey(binascii.unhexlify(priv_hex))
except Exception as e:
    raise RuntimeError(f"Failed to load signing key: {e}")

def sign_payload(source_id: str, payload_dict: dict) -> dict:
    # 1. Prepare JSON payload (no whitespace for deterministic signature)
    payload_json = json.dumps(payload_dict, separators=(',', ':'))
    payload_bytes = payload_json.encode('utf-8')
    
    # 2. Sign the bytes
    signed = signing_key.sign(payload_bytes)
    signature_bytes = signed.signature
    
    # 3. Base64 encode for transport
    import base64
    payload_b64 = base64.b64encode(payload_bytes).decode('utf-8')
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    
    return {
        "source_id": source_id,
        "version_id": "v1",
        "timestamp": int(time.time()),
        "payload": payload_b64,
        "signature": signature_b64
    }

@app.route('/ehr/v1/verify', methods=['POST'])
def ehr_verify():
    req = request.json
    intent_id = req.get("intent_id")
    # Simulate EHR lookup
    payload = {
        "intent_id": intent_id,
        "patient_status": "active",
        "record_found": True,
        "patient_age": 35,
        "is_transfer_patient": False
    }
    return jsonify(sign_payload("ehr_pipeline", payload))

@app.route('/drug/v1/check', methods=['POST'])
def drug_check():
    req = request.json
    intent_id = req.get("intent_id")
    medication = req.get("medication", "")
    controlled_substances = {"oxycodone", "adderall", "morphine", "fentanyl", "hydrocodone"}
    is_controlled = medication.lower() in controlled_substances
    # Simulate check
    payload = {
        "intent_id": intent_id,
        "drug_interaction_cleared": True,
        "is_controlled_substance": is_controlled
    }
    return jsonify(sign_payload("drug_interaction_pipeline", payload))

@app.route('/dea/v1/validate', methods=['POST'])
def dea_validate():
    req = request.json
    intent_id = req.get("intent_id")
    # Simulate validate
    payload = {
        "intent_id": intent_id,
        "dea_license_valid": True,
        "dea_schedule_authorized": True
    }
    return jsonify(sign_payload("dea_license_pipeline", payload))

@app.route('/consent/v1/verify', methods=['POST'])
def consent_verify():
    req = request.json
    intent_id = req.get("intent_id")
    payload = {
        "intent_id": intent_id,
        "consent_on_file": True
    }
    return jsonify(sign_payload("patient_consent_pipeline", payload))

@app.route('/hipaa/v1/check', methods=['POST'])
def hipaa_check():
    req = request.json
    intent_id = req.get("intent_id")
    payload = {
        "intent_id": intent_id,
        "hipaa_compliant": True
    }
    return jsonify(sign_payload("hipaa_compliance_pipeline", payload))

@app.route('/audit/v1/log', methods=['POST'])
def audit_log():
    req = request.json
    intent_id = req.get("intent_id")
    payload = {
        "intent_id": intent_id,
        "pre_logged": True
    }
    return jsonify(sign_payload("audit_pipeline", payload))

if __name__ == '__main__':
    print("Starting Oracle Mock Server on port 5050...")
    app.run(host='0.0.0.0', port=5050)
