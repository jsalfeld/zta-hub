#!/bin/bash
set -e

echo "=== Starting E2E Medical Courier Pattern Test ==="

# 1. Start Postgres
echo "-> Starting PostgreSQL via docker-compose..."
cd ../../
docker-compose up postgres -d
sleep 2 # wait for db

# 2. Start Hub
echo "-> Starting Governance Hub..."
HUB_CONFIG_DIR=examples/medical DATABASE_URL=postgres://hub_admin:supersecretpassword@localhost:5432/governance_db RUST_LOG=info cargo run --bin hub_server > hub.log 2>&1 &
HUB_PID=$!
sleep 2 # wait for hub

# 3. Start Oracle Mock
echo "-> Starting Mock Oracle Server..."
cd examples/medical/oracle
# Generate a fresh keypair for the test run
KEYGEN_OUTPUT=$(python keygen.py)
export ORACLE_PRIVATE_KEY_HEX=$(echo "$KEYGEN_OUTPUT" | grep "Private key" | awk '{print $NF}')
ORACLE_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Public key" | awk '{print $NF}')
# Update trusted_sources.json with the fresh public key
cd ../
python -c "
import json
ts = json.load(open('trusted_sources.json'))
for s in ts['sources']:
    s['public_key_hex'] = '$ORACLE_PUBLIC_KEY'
json.dump(ts, open('trusted_sources.json', 'w'), indent=2)
"
cd oracle
source venv/bin/activate
python oracle.py > oracle.log 2>&1 &
ORACLE_PID=$!
sleep 2 # wait for oracle

cd ../

# Helper to cleanly shutdown
cleanup() {
    echo "-> Cleaning up processes..."
    kill $HUB_PID || true
    kill $ORACLE_PID || true
    # docker-compose down # uncomment to destroy db after test
}
trap cleanup EXIT

# 4. Courier Pattern
echo "-> Creating Intent..."
INTENT_RESPONSE=$(curl -s -X POST http://localhost:3000/v1/intent \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "prescribe_medication",
    "agent_attestation_class": "medical_agent_v1",
    "requested_parameters": {"patient_id": "P-12345", "medication": "Amoxicillin", "dosage": "500mg"}
  }')

INTENT_ID=$(echo $INTENT_RESPONSE | grep -o '"intent_id":"[^"]*' | cut -d'"' -f4)
if [ -z "$INTENT_ID" ]; then
    echo "Failed to create intent! Response: $INTENT_RESPONSE"
    exit 1
fi
echo "Got Intent ID: $INTENT_ID"

echo "-> Gathering Receipts from Oracles..."
EHR_RECEIPT=$(curl -s -X POST http://localhost:5050/ehr/v1/verify \
  -H "Content-Type: application/json" \
  -d "{\"intent_id\": \"$INTENT_ID\", \"patient_id\": \"P-12345\"}")

DRUG_RECEIPT=$(curl -s -X POST http://localhost:5050/drug/v1/check \
  -H "Content-Type: application/json" \
  -d "{\"intent_id\": \"$INTENT_ID\", \"medication\": \"Amoxicillin\"}")

DEA_RECEIPT=$(curl -s -X POST http://localhost:5050/dea/v1/validate \
  -H "Content-Type: application/json" \
  -d "{\"intent_id\": \"$INTENT_ID\"}")

echo "-> Submitting Proofs to Hub..."
EXECUTE_PAYLOAD=$(cat <<EOF
{
  "request_id": "req-$(date +%s)",
  "external_data": [
    $EHR_RECEIPT,
    $DRUG_RECEIPT,
    $DEA_RECEIPT
  ],
  "prior_execution_receipts": []
}
EOF
)

EXECUTE_RESPONSE=$(curl -s -X POST http://localhost:3000/v1/execute/$INTENT_ID \
  -H "Content-Type: application/json" \
  -d "$EXECUTE_PAYLOAD")

STATUS=$(echo $EXECUTE_RESPONSE | grep -o '"status":"[^"]*' | cut -d'"' -f4)

if [ "$STATUS" = "success" ]; then
    echo "✅ Test Passed! Governance Hub verified proofs and executed intent."
    echo "$EXECUTE_RESPONSE"
    exit 0
else
    echo "❌ Test Failed!"
    echo "$EXECUTE_RESPONSE"
    exit 1
fi
