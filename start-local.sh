#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# start-local.sh — Boots the full Zero-Trust Action Hub locally
#   1. Generates fresh Ed25519 Oracle keypair
#   2. Updates trusted_sources.json with the new public key
#   3. Starts PostgreSQL + Hub via Docker Compose
#   4. Sets up Oracle Python venv (if needed) & starts Oracle
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ORACLE_DIR="$SCRIPT_DIR/examples/medical/oracle"
CONFIG_DIR="$SCRIPT_DIR/examples/medical"
TRUSTED_SOURCES="$CONFIG_DIR/trusted_sources.json"
LOG_DIR="$SCRIPT_DIR/.logs"

ORACLE_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()  { echo -e "${CYAN}[hub]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
err()  { echo -e "${RED}[err]${NC} $*"; }

# ── Cleanup on exit ──────────────────────────────────────────
cleanup() {
    echo ""
    log "Shutting down..."
    [ -n "$ORACLE_PID" ] && kill "$ORACLE_PID" 2>/dev/null && ok "Oracle stopped"
    $DC down 2>/dev/null && ok "Docker services stopped"
    log "Done."
}
trap cleanup EXIT INT TERM

# ── Pre-flight checks ───────────────────────────────────────
log "Checking prerequisites..."

missing=()
command -v docker   >/dev/null 2>&1 || missing+=("docker")
command -v python3  >/dev/null 2>&1 || missing+=("python3")
command -v curl     >/dev/null 2>&1 || missing+=("curl")

if [ ${#missing[@]} -gt 0 ]; then
    err "Missing required tools: ${missing[*]}"
    exit 1
fi

# Determine docker compose command
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    err "Missing required tool: docker-compose"
    exit 1
fi

ok "All prerequisites found"

# ── Create log directory ─────────────────────────────────────
mkdir -p "$LOG_DIR"

# ── Step 1: Generate fresh Oracle keypair ────────────────────
log "Generating fresh Ed25519 Oracle keypair..."

# Set up venv first (needed for keygen)
if [ ! -d "$ORACLE_DIR/venv" ]; then
    log "Creating Oracle Python venv..."
    python3 -m venv "$ORACLE_DIR/venv"
fi
VENV_PYTHON="$ORACLE_DIR/venv/bin/python"
"$VENV_PYTHON" -m pip install -q -r "$ORACLE_DIR/requirements.txt"

KEYGEN_OUTPUT=$("$VENV_PYTHON" "$ORACLE_DIR/keygen.py")
ORACLE_PRIVATE_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Private key" | awk '{print $NF}')
ORACLE_PUBLIC_KEY=$(echo "$KEYGEN_OUTPUT" | grep "Public key" | awk '{print $NF}')

if [ -z "$ORACLE_PRIVATE_KEY" ] || [ -z "$ORACLE_PUBLIC_KEY" ]; then
    err "Failed to generate keypair"
    exit 1
fi

ok "Keypair generated"
log "  Public key:  ${ORACLE_PUBLIC_KEY:0:16}..."

# ── Step 2: Update trusted_sources.json ──────────────────────
log "Updating trusted_sources.json with new public key..."

cat > "$TRUSTED_SOURCES" <<EOF
{
  "sources": [
    { "source_id": "ehr_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" },
    { "source_id": "drug_interaction_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" },
    { "source_id": "dea_license_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" },
    { "source_id": "patient_consent_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" },
    { "source_id": "hipaa_compliance_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" },
    { "source_id": "audit_pipeline", "public_key_hex": "$ORACLE_PUBLIC_KEY" }
  ]
}
EOF

ok "trusted_sources.json updated"

# ── Step 3: Start PostgreSQL + Hub via Docker Compose ────────
log "Building and starting Docker services (PostgreSQL + Hub)..."

$DC up -d --build

# Wait for Hub to be healthy
log "Waiting for Hub to be ready..."
RETRIES=60
until curl -sf http://localhost:3000/v1/skills >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        err "Hub failed to start within timeout"
        err "Check logs with: $DC logs governance-hub"
        exit 1
    fi
    sleep 2
done
ok "PostgreSQL + Hub ready"

# ── Step 4: Start Oracle Mock Server ─────────────────────────
log "Starting Oracle Mock Server on :5050..."

export ORACLE_PRIVATE_KEY_HEX="$ORACLE_PRIVATE_KEY"
"$VENV_PYTHON" "$ORACLE_DIR/oracle.py" > "$LOG_DIR/oracle.log" 2>&1 &
ORACLE_PID=$!

# Wait for Oracle to respond
RETRIES=15
until curl -sf http://localhost:5050/ehr/v1/verify \
    -X POST -H "Content-Type: application/json" \
    -d '{"intent_id":"healthcheck","patient_id":"test"}' >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        err "Oracle failed to start. Check $LOG_DIR/oracle.log"
        exit 1
    fi
    sleep 1
done
ok "Oracle ready (PID $ORACLE_PID) — logs at $LOG_DIR/oracle.log"

# ── Ready ────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Zero-Trust Action Hub is running!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo "  Hub API:    http://localhost:3000"
echo "  Oracle:     http://localhost:5050"
echo "  PostgreSQL: localhost:5432"
echo ""
echo "  Logs:"
echo "    Hub:    $DC logs -f governance-hub"
echo "    Oracle: $LOG_DIR/oracle.log"
echo ""
echo "  Oracle Public Key: $ORACLE_PUBLIC_KEY"
echo ""
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop all services."
echo ""

# Keep script alive — forward signals to cleanup
wait
