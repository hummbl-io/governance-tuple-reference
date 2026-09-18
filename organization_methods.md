# Organization Methods -- Institutional Context and Design Rationale

This document describes the institutional context behind the Governance Tuple
framework's design decisions. It is anonymized for peer review.

## Fail-Closed Signature Enforcement

### Design History

The Governance Tuple framework was developed in a production multi-agent AI
system where multiple autonomous agents operate concurrently, each with
delegated authority to perform actions on behalf of a human operator. The
system was initially deployed with a fail-open signature policy: if the
governance feature flag (`ENABLE_IDP`) was disabled or a signature was
missing, the system would allow operations to proceed and log a warning.

This fail-open policy was identified as a critical security gap during an
internal audit. The concern: an attacker who could suppress the feature flag
or strip signatures from governance entries could act with full authority
while leaving no auditable trace. The system was redesigned to fail-closed:

1. **Signatures are mandatory.** The `GovernanceBus.append()` method rejects
   any entry without a valid HMAC signature, returning
   `IDP_E_AUDIT_IMMUTABLE`. The only escape hatch is the explicit
   `require_signature=False` parameter, intended solely for emergency
   recovery operations.

2. **File permissions are hardened.** After each append, the governance log
   file is chmod'd to `0600` (owner read/write only). The governance directory
   is chmod'd to `0700` on initialization.

3. **Writes are atomic.** Each append uses `flush()` + `os.fsync()` to ensure
   the entry reaches disk before the method returns. This prevents partial
   writes from creating ambiguous audit records.

4. **Read-time chain validation.** When the governance bus reads entries
   (e.g., for query operations), it validates the hash chain of the file
   being read. If a break is detected, it logs an error with
   `IDP_E_CHAIN_BROKEN` and continues reading (so queries still return
   results, but the tamper is surfaced).

### Rationale

The fail-closed design reflects the principle that an audit log that can be
silently bypassed is worse than no audit log at all -- it creates a false
sense of security. By making signatures mandatory and rejecting unsigned
entries, the system ensures that every governance record is cryptographically
attributable to a known signing key.

## Lateral Authority Enforcement

### Problem

In a multi-agent system, agents can be classified into two broad categories:

- **Worker agents** that execute tasks within a delegated scope
- **Authority agents** that issue directives, decisions, or commands to other
  agents

The risk is that a worker agent could "go lateral" -- issuing authority-class
messages (directives, decisions) without possessing the delegation authority
to do so. In the original system, the governance bus did not distinguish
between worker messages and authority messages; any agent could post any
type of message.

### Solution

The `GovernanceBus.append()` method accepts an `authority_class` boolean
parameter. When `True`, the entry is treated as an authority-class message
and must satisfy two additional constraints:

1. **`capability_token_id` must be present.** The entry must cross-link to a
   DCT (Delegation Capability Token) entry in the governance log. If missing,
   the append is rejected with `IDP_E_LATERAL_AUTH`.

2. **The referenced DCT must exist.** The `capability_token_id` must
   reference an actual DCT entry in the log. If the referenced entry does not
   exist or is not of type `DCT`, the append is rejected with
   `IDP_E_DECISION_AUTH`.

This ensures that authority-class messages are always backed by a
cryptographically signed delegation token, creating an unbroken chain from
the human operator's root authority to every directive issued in the system.

### Rationale

The lateral authority enforcement prevents a class of attacks where a
compromised or misconfigured worker agent escalates its privilege by posting
authority messages. By requiring a DCT cross-link, the system ensures that
every authority message can be traced back to a specific delegation event,
which in turn can be traced back to a contract and ultimately to the human
operator.

## Trust Domains

### Risk Tiers

The framework defines four risk tiers that classify the sensitivity of
operations:

| Tier | Description | Example Operations |
|------|-------------|-------------------|
| `LOW` | Read-only, reversible | Analysis, search, summarization |
| `MEDIUM` | Write, reversible | Code edits, file creation |
| `HIGH` | Write, hard to reverse | Commits, pushes, deployments |
| `CRITICAL` | Irreversible or high-impact | Merge to main, kill switch, financial transactions |

Each risk tier has a corresponding trust-decay threshold (`tau_o`) that
governs how deep a delegation chain can extend:

| Risk Tier | tau_o | Rationale |
|-----------|-------|-----------|
| LOW | 0.15 | Low-risk operations can chain deeply (trust decays slowly) |
| MEDIUM | 0.20 | Moderate operations chain less deeply |
| HIGH | 0.25 | High-risk operations chain shallowly |
| CRITICAL | 0.40 | Critical operations chain very shallowly (near-direct only) |

### Trust-Decay Model

The dynamic depth bound is computed as:

```
delta_effective = min(delta_max, floor(tau / tau_o))
```

where:
- `delta_max` is the hard ceiling (default: 3, `DEFAULT_MAX_CHAIN_DEPTH`)
- `tau` is the Beta-distributed trust score of the delegatee
- `tau_o` is the per-risk-tier threshold

This model ensures that:
1. Low-trust agents cannot chain deeply regardless of risk tier
2. High-risk operations require high trust to chain at all
3. The hard ceiling `delta_max` is never exceeded

### Static vs. Dynamic Depth

The system supports both static and dynamic depth enforcement:

- **Static** (`can_subdelegate`): Uses `DEFAULT_MAX_CHAIN_DEPTH` as a fixed
  ceiling. Simple but does not account for trust scores.
- **Dynamic** (`create_child` with `trust_score`): Uses
  `compute_dynamic_depth` to compute a trust-aware ceiling. More precise but
  requires a trust score input.

When `trust_score` is provided to `create_child`, the dynamic model
supersedes the static model. This allows the system to tighten delegation
depth for low-trust agents or high-risk operations without changing the
global `DEFAULT_MAX_CHAIN_DEPTH` constant.

## 180-Day Retention Alignment

### EU AI Act Article 26(5)

The EU AI Act Article 26(5) requires that high-risk AI systems maintain
logging records for a minimum of six months (approximately 180 days) unless
otherwise specified by applicable Union or national law.

The Governance Tuple framework aligns with this requirement via:

1. **`DEFAULT_RETENTION_DAYS = 180`**: The default retention period for
   governance logs. Files older than 180 days are eligible for deletion by
   `enforce_retention()`.

2. **Append-only storage**: Governance logs are never modified or truncated
   in place. Old entries are preserved until the retention policy deletes
   the entire file.

3. **Hash-chained integrity**: The SHA-256 hash chain ensures that even if
   an attacker gains write access to the log file, any tampering is
   detectable via `verify_chain()`.

4. **Rotation at 10MB**: When a daily log file exceeds `ROTATION_SIZE_BYTES`
   (10 MB), it is compressed with gzip and a new file is started. This
   prevents any single file from growing unboundedly while preserving all
   entries.

### Rationale

The 180-day retention period was chosen to align with the EU AI Act's minimum
requirement while remaining practical for production systems. The
append-only, hash-chained design ensures that the audit trail is
tamper-evident for the full retention period, satisfying the Act's
record-keeping requirements for high-risk AI systems.

## Compliance Crosswalk

The `AdapterReceipt` includes a compliance crosswalk that maps each inference
event to relevant regulatory frameworks:

| Framework | Relevance |
|-----------|-----------|
| ISO 42001 | AI management system objectives and monitoring (6.2, 8.4, 9.1) |
| EU AI Act | Logging and record-keeping for high-risk AI (Art. 12) |
| NIST AI RMF | MAP 1.1, MEASURE 2.5, GOVERN 1.1 |
| SOC 2 | Threat detection and anomaly response (CC7.1, CC7.2) |
| HIPAA | Audit controls for PHI systems (164.312(b)) |
| DORA | ICT risk monitoring and reporting (Art. 10) |
| SR 11-7 | OCC/Fed model risk management |
| CMMC | Audit event capture (AU.2.042) |

This crosswalk is included in every receipt, providing a per-inference
compliance artifact that auditors can use to verify alignment with specific
regulatory requirements.
