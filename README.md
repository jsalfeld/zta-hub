# Zero-Trust Action Hub (ZTA)

The **Zero-Trust Action Hub** is a standalone, Zero-Trust Policy Decision Point (PDP) designed for autonomous AI agent ecosystems. It enforces cryptographic governance over high-risk agent actions using AWS Cedar policies and Ed25519 digital signatures, requiring agents to collect and present cryptographic proofs from trusted external microservices (Oracles) before any action is authorized.

This repository provides a headless, API-first infrastructure component that operates independently of any specific agent framework or business logic.

### Paper

This repository is the reference implementation for the working paper:

**Governing Actions, Not Agents: Institutional Attestation as a Governance Model for Autonomous AI Systems.** Jakob Salfeld-Nebgen (metaphora.ai), 2026. [PDF](https://arxiv.org/pdf/2606.26298)) · [arXiv:2606.26298](https://arxiv.org/abs/2606.26298)

### License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Quick Start: See It in 60 Seconds

### 1. Launch the Hub

```bash
./start-local.sh
```

This single command generates Ed25519 keys, configures trusted sources, starts PostgreSQL + the Hub via Docker Compose, launches the medical Oracle, and runs health checks. The Hub API is available at `http://localhost:3000`.

### 2. Connect an AI Agent

Copy [`CLAUDE_GEMINI_AGENTS.md`](CLAUDE_GEMINI_AGENTS.md) into your agent's system prompt (or drop it as `CLAUDE.md` in your project root for Claude Code). The file contains 11 lines that turn any LLM agent into a governed agent — it tells the agent to discover skills, read governance rules, collect Oracle proofs, and submit for evaluation.

### 3. Ask the Agent to Act

```
Prescribe 500mg Amoxicillin to patient P-12345
```

The agent will automatically:
1. **Discover** available skills from the Hub
2. **Read** the `skill.md` governance rules for `prescribe_medication`
3. **Collect** signed receipts from three independent Oracles (EHR, Drug Interaction, Patient Consent)
4. **Submit** the proof bundle to the Hub for Cedar policy evaluation
5. **Receive** an execution result — approved or denied with a cryptographic audit trail

No agent code changes. No custom integration. The agent figures out the zero-trust flow from the governance docs alone.

## Architecture: The Courier Pattern

Traditional agent architectures rely on the **Legacy Tool-Calling Pattern**. In this model, API keys sit directly with the agent, and the system blindly trusts the agent to execute tools with whatever input it decides is appropriate. The agent acts as the final decision-maker with full execution authority.

The Zero-Trust Action Hub enforces the **Courier Pattern**:
1. **No Direct Execution**: The agent cannot execute high-risk actions directly.
2. **Intent Declaration**: The agent must first declare its intent to the Hub and receive a unique `intent_id`.
3. **Cryptographic Proof Collection**: The agent acts as a courier, gathering attestations by interacting with isolated, external microservices (Oracles) and/or performing local computations. The Oracles verify specific business logic and mint cryptographic receipts (Ed25519 signatures), while computations can be verified via TEE or Zero-Knowledge proofs (see Verified Computation section). All proofs are strictly bound to the `intent_id`.
4. **Final Evaluation**: The agent submits the collection of receipts to the Zero-Trust Action Hub. The Hub evaluates the receipts against a deterministic mathematical policy written in [AWS Cedar](https://www.cedarpolicy.com/). If the receipts satisfy the policy, the Hub issues a final execution token and logs a hash-chained audit record.

### Execution Modes

Each skill can be configured with an `execution_mode`:

- **`broker_mediated`** (default): After successful policy evaluation, the Hub acts as a secure internal broker to execute the final action on behalf of the agent, mints an execution receipt, and returns the receipt to the agent.
  > [!WARNING]
  > **Current Status:** The broker layer is currently a stub that logs the capability token and returns `Ok`. Actual execution side-effects (e.g., hitting internal APIs) must be implemented in `broker/src/credential_broker.rs`.
- **`self_service_token`**: The Hub evaluates policy and returns the signed capability token directly to the agent, which then presents it to the downstream service. This is useful when the downstream service is on a different network, requires agent-local context, or the agent itself is the executor. An audit log entry is still recorded.

## How It Differs from Access Control

Access control (MCP gateways, OAuth, API keys) governs **who can call what**. The ZTA Hub governs **whether the preconditions for an action have been independently verified**. These are different layers and work together:

```
                    ┌──────────────────────────┐
                    │      Access Control       │
                    │  (MCP, OAuth, API keys)   │
                    └────────────┬──────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │          Agent            │
                    │                          │
                    │  1. Discover skill.md    │
                    │  2. Collect attestations  │
                    │  3. Submit proof bundle   │
                    └──┬───────────────────┬───┘
                       │                   │
            ┌──────────▼───────┐           │
            │     Oracles       │           │
            │                   │           │
            │  EHR ──► receipt  │           │
            │  Drug ──► receipt │           │
            │  DEA ──► receipt  │           │
            └──────────────────┘           │
                       │                   │
                  receipts                 │
                       │                   │
                       ▼                   ▼
                    ┌──────────────────────────┐
                    │         ZTA Hub           │
                    │                          │
                    │  Verify signatures       │
                    │  Check intent binding    │
                    │  Evaluate Cedar policy   │
                    │  Execute or issue token  │
                    │  Log to hash chain     │
                    └──────────────────────────┘
```

The agent goes out to the Oracles, collects signed receipts, then brings them back to the Hub. The Hub doesn't call the Oracles — that's the Courier Pattern.

In current agent architectures, compliance checks — whether implemented as guardrails, hooks, workflow DAG steps, or tool handler logic — are performed by a single party that interprets results and self-attests correctness in its own logs. The ZTA Hub uses a different trust model:

- **Multi-party attestation.** N independent Oracles each verify a condition and sign with their own Ed25519 key. No single party — including the Hub — can fabricate another's attestation.
- **Intent binding.** Every Oracle receipt is bound to a unique `intent_id`. Receipts from a different intent are rejected, preventing replay.
- **Declarative governance.** Governed actions are defined as configuration (skills + Cedar policies), not code. Oracles are reusable across actions.
- **Agent self-discovery.** Agents read governance requirements at runtime via auto-generated `skill.md` docs, rather than having compliance logic hardcoded per process.
- **Independent verifiability.** The audit trail is hash-chained and contains the original signed receipts. A third party can verify any decision by checking Oracle signatures and walking the chain. *Note: The Hub's signing key is currently ephemeral — regenerated on restart. For persistent cross-session verifiability, wire `engine_signing_key` to a KMS-backed persistent key.*
- **Action composition.** Execution receipts can be submitted as prerequisites for subsequent actions, cryptographically proving a prior action was itself governed.
- **Verified computation.** Agents can execute local computations (data transformations, ML inference) and submit TEE or Zero-Knowledge proofs of the output. The Hub verifies these proofs against a registry of approved code hashes and injects the verified output into the Cedar policy context (design-only in v0.1 — see Verified Computation section).

## Repository Structure

- `hub_server/`: The Axum-based async HTTP server that exposes the REST API for intent creation and execution.
- `engine/`: The core evaluation engine that parses and evaluates AWS Cedar policies.
- `broker/`: The execution layer that verifies the Hub Engine's internal capability tokens and performs the final side-effects (acting as the secure broker). Note: External Oracle signatures are verified upstream by the engine.
- `schemas/`: Shared data models and cryptographic structures (e.g., `SignedDataRecord`).
- `examples/`: Sample configurations demonstrating how to run the Hub for specific verticals (e.g., a Healthcare workflow).

## Integration Guide

The Hub ships with a medical example, but it is domain-agnostic. To integrate the ZTA Hub into your own system, you provide four things: **skills**, **policies**, **Oracles**, and **trusted sources**. The Hub handles everything else — cryptographic verification, policy evaluation, audit logging, and token issuance.

> [!NOTE]
> **Medical Example Context:** The included medical example (`examples/medical/oracle/oracle.py`) uses a hardcoded Python Flask server. It is meant purely to demonstrate the Ed25519 cryptographic signing flow and does not perform real EHR or Drug Interaction lookups.

Your configuration directory (pointed to by `HUB_CONFIG_DIR`) should look like this:

```
my-config/
  skills.json                # skill definitions + Oracle requirements
  trusted_sources.json       # Ed25519 public keys for each Oracle
  policies/
    my_skill.cedar           # one Cedar policy per skill
  computations/              # (optional) verified computation registry
    my_computation.json
```

### Step 1: Define Your Skills

Each skill represents a governed action. Create a `skills.json` file that declares what the action is, which Oracles must attest to it, and how it executes.

```json
{
  "skills": [
    {
      "contract": {
        "skill_id": "deploy_to_production",
        "version": "1.0.0",
        "risk_classification": "critical",
        "input_schema_json": "{\"commit_sha\":\"string\", \"service\":\"string\"}",
        "output_schema_json": "{\"status\":\"string\"}",
        "consumes_prerequisites": ["ci_passed", "staging_verified", "security_scan_clear"],
        "produces_prerequisites": []
      },
      "description": "Deploy a service to production after verifying CI, staging, and security scan.",
      "requirements": [
        {
          "source_id": "ci_pipeline",
          "data_type": "ci_passed",
          "description": "Verifies all CI checks passed for the given commit.",
          "oracle_url": "https://ci-oracle.internal/v1/verify",
          "oracle_method": "POST",
          "oracle_request_schema": "{ \"commit_sha\": \"<COMMIT_SHA>\", \"intent_id\": \"<INTENT_ID>\" }"
        },
        {
          "source_id": "staging_oracle",
          "data_type": "staging_verified",
          "description": "Confirms the commit has been deployed and smoke-tested in staging.",
          "oracle_url": "https://staging-oracle.internal/v1/check",
          "oracle_method": "POST",
          "oracle_request_schema": "{ \"commit_sha\": \"<COMMIT_SHA>\", \"intent_id\": \"<INTENT_ID>\" }"
        },
        {
          "source_id": "security_scanner",
          "data_type": "security_scan_clear",
          "description": "Confirms no critical vulnerabilities in the build artifact.",
          "oracle_url": "https://security-oracle.internal/v1/scan",
          "oracle_method": "POST",
          "oracle_request_schema": "{ \"commit_sha\": \"<COMMIT_SHA>\", \"intent_id\": \"<INTENT_ID>\" }"
        }
      ],
      "policy_file": "deploy_to_production.cedar",
      "execution_mode": "broker_mediated"
    }
  ]
}
```

**Key fields:**

| Field | Purpose |
|-------|---------|
| `contract.skill_id` | Unique identifier. Used in API calls and Cedar policies. |
| `contract.risk_classification` | Human-readable risk level (`critical`, `high`, `internal_effect`, `read_only`). Included in auto-generated `skill.md` docs. |
| `requirements[]` | The Oracles that must provide signed attestations. Each `source_id` must have a matching entry in `trusted_sources.json`. |
| `requirements[].oracle_url` | The endpoint the agent will call. The Hub does not call Oracles — the agent does (Courier Pattern). |
| `requirements[].oracle_request_schema` | Template shown to agents in the auto-generated `skill.md`. Use `<PLACEHOLDER>` tokens for dynamic values. |
| `policy_file` | Filename of the Cedar policy in the `policies/` subdirectory. |
| `execution_mode` | `"broker_mediated"` (Hub executes the action) or `"self_service_token"` (Hub returns a signed token; agent presents it downstream). |
| `downstream_url` | (Optional, for `self_service_token` mode) Where the agent should present the capability token. |

### Step 2: Write Cedar Policies

Each skill needs a corresponding [AWS Cedar](https://www.cedarpolicy.com/) policy file. The policy decides whether the action is permitted based on the **Oracle-verified context** — not the agent's claims.

```cedar
// policies/deploy_to_production.cedar
permit(
    principal,
    action == Action::"deploy_to_production",
    resource
) when {
    principal == Agent::"deploy_bot_v1" &&
    context.ci_passed == true &&
    context.staging_smoke_test_passed == true &&
    context.critical_vulnerabilities == 0 &&
    context.branch == "main"
};
```

**How context gets populated:**

The Cedar `context` object is assembled from three sources, merged in order:

1. **Oracle receipt payloads** — Each Oracle's signed JSON payload is deserialized and merged into `context`. If the EHR Oracle returns `{"patient_age": 35, "drug_interaction_cleared": true}`, then `context.patient_age` and `context.drug_interaction_cleared` become available in the policy.
2. **Verified computation outputs** — If computation proofs are submitted, their verified output is merged into `context`. Additional fields like `context.computation_verified` and `context.computations` (array) are injected automatically.
3. **Requested parameters** — The agent's original `requested_parameters` from the intent are merged last.

Prior execution receipts are placed under `context.prior_actions`, keyed by `action_type`:

```cedar
// Require that a staging deployment was previously governed
context.prior_actions.deploy_to_staging.status == "executed"
```

**Cedar basics:**
- `permit(...)` allows, `forbid(...)` denies. Default is deny.
- `principal` is `Agent::"<agent_attestation_class>"` from the request.
- `action` is `Action::"<skill_id>"`.
- `resource` is always `System::"Core"`.
- Full language reference: [cedarpolicy.com](https://www.cedarpolicy.com/)

### Step 3: Build Your Oracles

An Oracle is any HTTP service that verifies a business condition and returns a **signed attestation**. Oracles can be written in any language. The contract is simple:

1. Accept a request containing an `intent_id` and domain-specific parameters.
2. Verify whatever business logic you need (database lookup, API call, sensor reading).
3. Return a `SignedDataRecord` — the payload signed with the Oracle's Ed25519 private key.

**Python example (using PyNaCl):**

```python
import json, time, base64, binascii
import nacl.signing

signing_key = nacl.signing.SigningKey(binascii.unhexlify(PRIVATE_KEY_HEX))

def sign_payload(source_id: str, payload_dict: dict) -> dict:
    # Deterministic JSON — no whitespace. Any variation breaks signature verification.
    payload_json = json.dumps(payload_dict, separators=(',', ':'))
    payload_bytes = payload_json.encode('utf-8')

    signed = signing_key.sign(payload_bytes)

    return {
        "source_id": source_id,
        "version_id": "v1",
        "timestamp": int(time.time()),
        "payload": base64.b64encode(payload_bytes).decode('utf-8'),
        "signature": base64.b64encode(signed.signature).decode('utf-8')
    }
```

**Oracle requirements:**

| Requirement | Why |
|-------------|-----|
| Include `intent_id` in the payload | Binds the receipt to a specific action. Receipts without a matching `intent_id` are rejected as replay attacks. |
| Use deterministic JSON serialization | `json.dumps(separators=(',', ':'))` — no extra whitespace. The Hub verifies the signature over the exact payload bytes. |
| Base64-encode `payload` and `signature` | The Hub expects base64-encoded bytes in the JSON response. |
| Keep the Oracle's private key secret | The security model depends on Oracles being independent, trusted parties. A compromised key lets an attacker forge attestations for that Oracle. |

**Generating Oracle keypairs:**

The included `examples/medical/oracle/keygen.py` generates Ed25519 keypairs, or use any Ed25519 implementation. The public key (hex-encoded, 64 characters) goes into `trusted_sources.json`.

### Step 4: Register Trusted Sources

Create a `trusted_sources.json` that maps each Oracle's `source_id` to its Ed25519 public key:

```json
{
  "sources": [
    { "source_id": "ci_pipeline", "public_key_hex": "a1b2c3d4..." },
    { "source_id": "staging_oracle", "public_key_hex": "e5f6a7b8..." },
    { "source_id": "security_scanner", "public_key_hex": "c9d0e1f2..." }
  ]
}
```

- `public_key_hex` is the 64-character hex encoding of the Oracle's 32-byte Ed25519 public key.
- Every `source_id` referenced in `skills.json` requirements must have a matching entry here.
- The Hub automatically registers itself (`"governance_hub"`) as a trusted source for action composition receipts.

### Step 5: Deploy

#### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HUB_CONFIG_DIR` | `"config"` | Path to your configuration directory |
| `DATABASE_URL` | Local Postgres | PostgreSQL connection string |
| `RUST_LOG` | `"info"` | Log level (`debug`, `info`, `warn`, `error`) |

#### Docker Compose

The simplest path. Replace the config volume mount with your own configuration directory:

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: hub_admin
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  # Set in .env or environment
      POSTGRES_DB: governance_db
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U hub_admin -d governance_db"]
      interval: 5s
      timeout: 5s
      retries: 5

  governance-hub:
    build: .
    environment:
      - DATABASE_URL=postgres://hub_admin:${POSTGRES_PASSWORD}@postgres:5432/governance_db
      - HUB_CONFIG_DIR=/app/config
      - RUST_LOG=info
    ports:
      - "3000:3000"
    volumes:
      - ./my-config:/app/config        # <-- Your config directory
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
```

```bash
POSTGRES_PASSWORD=your-strong-password docker compose up -d --build
```

The Hub auto-creates its database tables (`intents`, `audit_log`) on startup. No migrations needed.

#### Local Development (without Docker)

```bash
# Prerequisites: Rust 1.77+, PostgreSQL running locally
export DATABASE_URL="postgres://user:pass@localhost:5432/governance_db"
export HUB_CONFIG_DIR=./my-config
cargo run --bin hub_server
```

### Step 6: Connect Your Agent

Copy [`CLAUDE_GEMINI_AGENTS.md`](CLAUDE_GEMINI_AGENTS.md) into your agent's system prompt. It contains 11 lines that teach any LLM agent the Courier Pattern. The agent will:

1. **Discover** skills via `GET /v1/skills`
2. **Read** the auto-generated governance docs via `GET /v1/skills/:id/skill.md` — this tells the agent exactly which Oracles to call, with request schemas
3. **Create an intent** via `POST /v1/intent` and receive an `intent_id`
4. **Collect proofs** by calling each Oracle endpoint listed in the `skill.md`
5. **Submit** the proof bundle via `POST /v1/execute/:intent_id`

No agent SDK required. Any agent that can make HTTP calls works.

### Step 7: Verified Computation (Optional)

For cases where an agent needs to run local computation (ML inference, data transformation) and the Hub needs to trust the output, you can use **Verified Computation**. This requires the agent to submit a TEE attestation or Zero-Knowledge proof alongside the computation output.

> [!WARNING]
> **Current Status:** The Hub currently ships with a `MockVerifier` for local testing. Production TEE (e.g., AWS Nitro Enclaves) and ZK (e.g., Groth16) verifiers must be implemented by fulfilling the `ComputationVerifier` trait.

**Register a computation** by placing a JSON file in `computations/`:

```json
{
  "computation_id": "dosage_calculator",
  "code_hash": "sha256-of-the-approved-binary-or-circuit",
  "version": "1.0.0",
  "audit_status": "certified",
  "consumes": ["ehr_pipeline", "drug_interaction_pipeline"],
  "description": "Calculates safe dosage based on patient weight and drug interactions."
}
```

- `code_hash` must match the hash in the agent's proof. This ensures only audited code is trusted.
- `audit_status` must be `"certified"` for the proof to be accepted.
- `consumes` restricts which Oracle data the computation may reference as inputs.

**Implement a verifier** by implementing the `ComputationVerifier` trait in Rust and registering it with `register_computation_verifier()`. The Hub ships with a `MockVerifier` for local testing — production deployments should provide a real TEE or ZK verifier.

```rust
pub trait ComputationVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &ComputationProof,
        registered_code_hash: &str,
        expected_input_hashes: &[String],
    ) -> Result<VerifiedOutput, VerificationError>;

    fn proof_type(&self) -> &str;
}
```

## API Reference

### `POST /v1/intent`

Create a new execution intent. Returns an `intent_id` and the list of required Oracle proofs.

**Request:**
```json
{
  "action_type": "deploy_to_production",
  "agent_attestation_class": "deploy_bot_v1",
  "requested_parameters": {
    "commit_sha": "abc123",
    "service": "api-gateway"
  }
}
```

**Response:**
```json
{
  "intent_id": "int-a1b2c3d4e5f6",
  "requirements": [
    { "source_id": "ci_pipeline", "data_type": "ci_passed" },
    { "source_id": "staging_oracle", "data_type": "staging_verified" },
    { "source_id": "security_scanner", "data_type": "security_scan_clear" }
  ]
}
```

### `POST /v1/execute/:intent_id`

Submit cryptographic proofs for policy evaluation. The Hub verifies all signatures, checks intent binding, evaluates the Cedar policy, and either executes the action (broker-mediated) or returns a capability token (self-service).

**Request:**
```json
{
  "request_id": "req-unique-id",
  "external_data": [
    {
      "source_id": "ci_pipeline",
      "version_id": "v1",
      "timestamp": 1715400000,
      "payload": "<base64-encoded JSON>",
      "signature": "<base64-encoded Ed25519 signature>"
    }
  ],
  "prior_execution_receipts": [],
  "computation_proofs": []
}
```

**Response (broker_mediated):**
```json
{
  "status": "success",
  "execution_receipt": {
    "source_id": "governance_hub",
    "version_id": "v1",
    "timestamp": 1715400100,
    "payload": "<base64>",
    "signature": "<base64>"
  }
}
```

**Response (self_service_token):**
```json
{
  "status": "authorized",
  "capability_token": {
    "token_id": "CT-req-unique-id",
    "action_type": "deploy_to_production",
    "audit_id": "AUDIT-req-unique-id",
    "expires_at": 0,
    "effect_parameters": "<base64>",
    "engine_signature": "<hex>"
  }
}
```

The `execution_receipt` from a broker-mediated action can be submitted as a `prior_execution_receipt` in a subsequent action, enabling governed action composition.

### `GET /v1/skills`

Returns all registered skills with their requirements, risk classifications, and execution modes.

### `GET /v1/skills/:skill_id/skill.md`

Returns auto-generated Markdown documentation for a specific skill. This is the primary interface for agents — it contains step-by-step instructions, Oracle endpoints, request schemas, and the Cedar policy. Agents read this to learn the Courier Pattern for a given action without any hardcoded integration.

### `GET /v1/computations`

Returns all registered verified computations.

### `GET /v1/computations/:computation_id`

Returns details for a specific registered computation.
