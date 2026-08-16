# Governance Tuple Primitives -- Formal Schema Specification

This document defines the formal schema for each governance tuple type in the
Governance Tuple framework. Each tuple is an atomic, append-only record that
serves as a compliance artifact for auditable agentic AI decision-making.

## Overview

The Governance Tuple framework defines five atomic record types:

| Tuple | Purpose |
|-------|---------|
| **CONTRACT** | Governing agreement specifying allowed operations and constraints |
| **DCT** | Delegation Capability Token -- HMAC-signed authorization to act |
| **DCTX** | Delegation Context -- tracks chain depth, state machine, budget |
| **EVIDENCE** | Execution artifact proving an operation was performed |
| **ATTEST** | Verification result linking evidence to a pass/fail outcome |

All tuples are written to an append-only, hash-chained JSONL log via the
`GovernanceBus`. The hash chain uses SHA-256 over each entry's canonical JSON
line, with each entry storing the hash of the prior entry in its
`previous_hash` field.

---

## CONTRACT

The CONTRACT tuple defines the governing agreement for a delegation. It
specifies what operations are permitted, what is explicitly denied, and the
risk classification of the work.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract_id` | string | Yes | Unique identifier for this contract |
| `allowed_ops` | array\<string\> | Yes | Operations permitted under this contract |
| `denied_ops` | array\<string\> | No | Operations explicitly prohibited |
| `risk_tier` | enum | Yes | One of: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `max_chain_depth` | integer | Yes | Maximum delegation chain depth (default: 3) |

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "CONTRACT",
  "required": ["contract_id", "allowed_ops", "risk_tier", "max_chain_depth"],
  "properties": {
    "contract_id": {
      "type": "string",
      "description": "Unique identifier for this contract"
    },
    "allowed_ops": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Operations permitted under this contract"
    },
    "denied_ops": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Operations explicitly prohibited"
    },
    "risk_tier": {
      "type": "string",
      "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    },
    "max_chain_depth": {
      "type": "integer",
      "minimum": 0,
      "default": 3
    }
  }
}
```

---

## DCT (Delegation Capability Token)

The DCT is an HMAC-SHA256 signed token that authorizes an agent (the subject)
to act on behalf of a delegator (the issuer) within a bounded scope defined by
resource selectors, operations, and caveats.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token_id` | string (UUID) | Yes | Unique identifier for this token |
| `issuer` | string | Yes | Agent granting the capability |
| `subject` | string | Yes | Agent receiving the capability |
| `resource_selectors` | array\<ResourceSelector\> | No | Accessible resource specifications |
| `ops_allowed` | array\<string\> | Yes | Permitted operations |
| `caveats` | array\<Caveat\> | No | Additional constraints on use |
| `expiry` | string (ISO8601) | No | Expiry timestamp; null = no expiry |
| `binding` | TokenBinding | No | Links token to specific task/contract |
| `signature` | string (hex) | Yes | HMAC-SHA256 signature |

### ResourceSelector

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resource_type` | string | Yes | Type of resource (e.g., "file", "repo") |
| `resource_id` | string | No | Resource identifier; "*" = wildcard |
| `constraints` | object | No | Additional constraints |

### Caveat

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `caveat_id` | string | Yes | Unique caveat identifier |
| `type` | enum | Yes | One of: `TIME_BOUND`, `RATE_LIMIT`, `APPROVAL_REQUIRED`, `AUDIT_REQUIRED` |
| `parameters` | object | No | Type-specific parameters |

### TokenBinding

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `task_id` | string | Yes | Task this token is bound to |
| `contract_id` | string | Yes | Contract this token is bound to |

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "DCT",
  "required": ["token_id", "issuer", "subject", "ops_allowed", "signature"],
  "properties": {
    "token_id": {"type": "string", "format": "uuid"},
    "issuer": {"type": "string"},
    "subject": {"type": "string"},
    "resource_selectors": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["resource_type"],
        "properties": {
          "resource_type": {"type": "string"},
          "resource_id": {"type": "string", "default": "*"},
          "constraints": {"type": "object"}
        }
      }
    },
    "ops_allowed": {"type": "array", "items": {"type": "string"}},
    "caveats": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["caveat_id", "type"],
        "properties": {
          "caveat_id": {"type": "string"},
          "type": {"type": "string", "enum": ["TIME_BOUND", "RATE_LIMIT", "APPROVAL_REQUIRED", "AUDIT_REQUIRED"]},
          "parameters": {"type": "object"}
        }
      }
    },
    "expiry": {"type": ["string", "null"], "format": "date-time"},
    "binding": {
      "type": ["object", "null"],
      "required": ["task_id", "contract_id"],
      "properties": {
        "task_id": {"type": "string"},
        "contract_id": {"type": "string"}
      }
    },
    "signature": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
  }
}
```

---

## DCTX (Delegation Context)

The DCTX tracks the full context of a single delegation event, including chain
depth, state machine status, budget constraints, and replan count.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `intent_id` | string | Yes | Root intent identifier (shared across delegation tree) |
| `task_id` | string | Yes | Unique identifier for this task |
| `parent_task_id` | string \| null | No | Reference to parent task (null for root) |
| `delegator_id` | string | Yes | Agent issuing the delegation |
| `delegatee_id` | string | Yes | Agent receiving the delegation |
| `contract_id` | string | Yes | Reference to CONTRACT tuple |
| `verification_id` | string \| null | No | Reference to ATTEST tuple |
| `capability_token_id` | string \| null | No | Reference to DCT tuple |
| `risk_tier` | enum | Yes | One of: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `chain_depth` | integer | Yes | Subdelegation level (0 = root) |
| `budget` | DelegationBudget | No | Resource constraints |
| `status` | enum | Yes | One of: `PROPOSED`, `ISSUED`, `RUNNING`, `EVIDENCE_READY`, `VERIFIED`, `REPLANNED`, `FAILED` |
| `created_at` | string (ISO8601) | Yes | Creation timestamp |
| `replan_count` | integer | Yes | Number of replans (default: 0) |
| `ops_allowed` | array\<string\> | No | Capabilities granted |
| `metadata` | object | No | Additional context data |

### DelegationBudget

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_tokens` | integer | 0 | Max LLM tokens (0 = unlimited) |
| `max_cost_usd` | number | 0.0 | Max cost in USD (0.0 = unlimited) |
| `max_wall_time_seconds` | integer | 0 | Max wall-clock time (0 = unlimited) |

### State Machine

```
PROPOSED -> ISSUED
ISSUED -> RUNNING
ISSUED -> FAILED
RUNNING -> EVIDENCE_READY
RUNNING -> FAILED
EVIDENCE_READY -> VERIFIED
EVIDENCE_READY -> REPLANNED
REPLANNED -> PROPOSED (subject to replan limit)
REPLANNED -> FAILED
VERIFIED (terminal)
FAILED (terminal)
```

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "DCTX",
  "required": ["intent_id", "task_id", "delegator_id", "delegatee_id", "contract_id", "risk_tier", "chain_depth", "status", "created_at"],
  "properties": {
    "intent_id": {"type": "string"},
    "task_id": {"type": "string"},
    "parent_task_id": {"type": ["string", "null"]},
    "delegator_id": {"type": "string"},
    "delegatee_id": {"type": "string"},
    "contract_id": {"type": "string"},
    "verification_id": {"type": ["string", "null"]},
    "capability_token_id": {"type": ["string", "null"]},
    "risk_tier": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
    "chain_depth": {"type": "integer", "minimum": 0},
    "budget": {
      "type": "object",
      "properties": {
        "max_tokens": {"type": "integer", "default": 0},
        "max_cost_usd": {"type": "number", "default": 0.0},
        "max_wall_time_seconds": {"type": "integer", "default": 0}
      }
    },
    "status": {"type": "string", "enum": ["PROPOSED", "ISSUED", "RUNNING", "EVIDENCE_READY", "VERIFIED", "REPLANNED", "FAILED"]},
    "created_at": {"type": "string", "format": "date-time"},
    "replan_count": {"type": "integer", "minimum": 0, "default": 0},
    "ops_allowed": {"type": "array", "items": {"type": "string"}},
    "metadata": {"type": "object"}
  }
}
```

---

## EVIDENCE

The EVIDENCE tuple records the execution artifact proving that an operation was
performed. It is produced by the delegatee agent upon completion of a task.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `task_id` | string | Yes | Task this evidence belongs to |
| `agent` | string | Yes | Agent that produced the evidence |
| `tool` | string | Yes | Tool that was invoked |
| `result_hash` | string (hex) | Yes | SHA-256 hash of the execution result |
| `duration_ms` | integer | No | Execution duration in milliseconds |

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "EVIDENCE",
  "required": ["task_id", "agent", "tool", "result_hash"],
  "properties": {
    "task_id": {"type": "string"},
    "agent": {"type": "string"},
    "tool": {"type": "string"},
    "result_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "duration_ms": {"type": "integer", "minimum": 0}
  }
}
```

---

## ATTEST

The ATTEST tuple records the verification result, linking an EVIDENCE entry to
a pass/fail outcome. It enforces the evidence-before-verify invariant: an
ATTEST must reference an existing EVIDENCE entry via `verification_id`.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `task_id` | string | Yes | Task being verified |
| `verifier` | string | Yes | Agent performing verification |
| `result` | enum | Yes | One of: `PASS`, `FAIL` |

### Cross-Links

The ATTEST entry in the governance log must include a `verification_id`
top-level field referencing the EVIDENCE entry it verifies. This is enforced
by the `GovernanceBus.append()` method.

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "ATTEST",
  "required": ["task_id", "verifier", "result"],
  "properties": {
    "task_id": {"type": "string"},
    "verifier": {"type": "string"},
    "result": {"type": "string", "enum": ["PASS", "FAIL"]}
  }
}
```

---

## Governance Log Entry Wrapper

All tuples are wrapped in a `GovernanceEntry` when written to the governance
log. The wrapper adds metadata and hash-chaining fields.

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string (ISO8601) | Yes | Entry timestamp (UTC) |
| `entry_id` | string (UUID) | Yes | Unique entry identifier |
| `intent_id` | string | Yes | Root intent identifier |
| `task_id` | string | Yes | Task identifier |
| `tuple_type` | enum | Yes | One of: `DCTX`, `CONTRACT`, `EVIDENCE`, `ATTEST`, `DCT`, `SYSTEM` |
| `tuple_data` | object | Yes | The tuple payload |
| `signature` | string \| null | Yes | HMAC signature (fail-closed enforcement) |
| `state` | string | No | Outcome state: `ok`, `blocked`, `error` |
| `drift` | number | No | Drift score (0.0 to 1.0) |
| `contract_id` | string \| null | No | Cross-link to CONTRACT entry |
| `capability_token_id` | string \| null | No | Cross-link to DCT entry |
| `verification_id` | string \| null | No | Cross-link from ATTEST to EVIDENCE |
| `amendment_of` | string \| null | No | Entry being amended (append-only correction) |
| `previous_hash` | string \| null | No | SHA-256 of prior entry's JSONL (genesis = null) |

### JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "title": "GovernanceEntry",
  "required": ["timestamp", "entry_id", "intent_id", "task_id", "tuple_type", "tuple_data", "signature"],
  "properties": {
    "timestamp": {"type": "string", "format": "date-time"},
    "entry_id": {"type": "string"},
    "intent_id": {"type": "string"},
    "task_id": {"type": "string"},
    "tuple_type": {"type": "string", "enum": ["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"]},
    "tuple_data": {"type": "object"},
    "signature": {"type": ["string", "null"]},
    "state": {"type": "string", "enum": ["ok", "blocked", "error"], "default": "ok"},
    "drift": {"type": "number", "minimum": 0.0, "maximum": 1.0, "default": 0.0},
    "contract_id": {"type": ["string", "null"]},
    "capability_token_id": {"type": ["string", "null"]},
    "verification_id": {"type": ["string", "null"]},
    "amendment_of": {"type": ["string", "null"]},
    "previous_hash": {"type": ["string", "null"]}
  }
}
```
