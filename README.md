# Governance Tuple Reference Implementation

An anonymized, MIT-licensed, standalone reference implementation of the
primitives described in the paper:

> **The Governance Tuple: An Atomic Record for Auditable Agentic AI Decision-Making**

This repository lets peer reviewers verify the paper's implementation claims
without accessing the private production codebase. Every class name, method
signature, constant, and error code cited in the paper exists in this
repository at a stable, citable location.

## Quick Start

```bash
# Verify hash-chain integrity of the sample governance log
python verify_chain.py sample_governance_log.jsonl

# Run the test suite
python -m pytest tests/ -v
```

## Repository Structure

```
governance-tuple-reference/
  reference_impl/          Core Python modules (stdlib-only)
    delegation_token.py     DelegationCapabilityToken, TokenBinding,
                            ResourceSelector, Caveat, DelegationTokenManager
    delegation_context.py   DelegationContext, DelegationContextManager,
                            DelegationBudget, compute_dynamic_depth, DCTXStatus
    governance_bus.py       GovernanceBus, GovernanceEntry
    adapter_receipt.py      AdapterReceipt
    basen_tuple.py          BaseNTuple
  tests/                    Pytest test suite
    test_governance_tuple.py
  verify_chain.py           Standalone hash-chain verification script
  sample_governance_log.jsonl  50 synthetic governance entries with valid chain
  primitives.md             Formal schema spec (CONTRACT, DCT, EVIDENCE, DCTX, ATTEST)
  operationalizations.md    Paper claim -> reference impl location mapping
  organization_methods.md   Institutional context and design rationale
  index.html                Landing page for reviewers
  llms.txt                  Machine-readable project summary
  LICENSE                   MIT license
  pyproject.toml            Minimal project config (Python 3.11+, no deps)
  .gitignore
```

## Primitives

The Governance Tuple framework defines five atomic record types:

| Tuple | Purpose | Reference |
|-------|---------|-----------|
| **CONTRACT** | Governing agreement specifying allowed operations and constraints | `primitives.md` |
| **DCT** | Delegation Capability Token -- HMAC-signed authorization to act | `reference_impl/delegation_token.py` |
| **DCTX** | Delegation Context -- tracks chain depth, state machine, budget | `reference_impl/delegation_context.py` |
| **EVIDENCE** | Execution artifact proving an operation was performed | `reference_impl/governance_bus.py` |
| **ATTEST** | Verification result linking evidence to a pass/fail outcome | `reference_impl/governance_bus.py` |

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `DEFAULT_MAX_CHAIN_DEPTH` | 3 | `delegation_context.py` |
| `DEFAULT_MAX_REPLANS` | 2 | `delegation_context.py` |
| `DEFAULT_RETENTION_DAYS` | 180 | `governance_bus.py` |
| `ROTATION_SIZE_BYTES` | 10 MB | `governance_bus.py` |
| `ENABLE_IDP` | env var | all modules |

## Trust-Decay Formula

The dynamic depth bound is computed as:

```
delta_effective = min(delta_max, floor(tau / tau_o))
```

where `tau_o` is the per-risk-tier threshold:

| Risk Tier | tau_o |
|-----------|-------|
| LOW | 0.15 |
| MEDIUM | 0.20 |
| HIGH | 0.25 |
| CRITICAL | 0.40 |

## Requirements

- Python 3.11+
- No external dependencies (stdlib only)
- pytest for running tests (not required for core functionality)

## Verification

### Hash-Chain Integrity

```bash
python verify_chain.py sample_governance_log.jsonl
```

This walks every JSONL entry and confirms each entry's `previous_hash` matches
the SHA-256 of the prior entry's canonical JSON. The genesis entry must have
`previous_hash: null`.

### Test Suite

```bash
python -m pytest tests/ -v
```

Tests cover:
1. Token signing and verification (HMAC-SHA256)
2. Monotonic capability attenuation in `create_child`
3. Hash-chain integrity
4. Chain break detection
5. Dynamic depth computation (trust-decay model)
6. State machine transitions

## License

MIT -- see [LICENSE](LICENSE).

## Paper

> The Governance Tuple: An Atomic Record for Auditable Agentic AI Decision-Making

This reference implementation is anonymized for peer review. The class names,
method signatures, constants, and error codes match those cited in the paper.
