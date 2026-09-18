# Operationalizations -- Paper Claim to Reference Implementation Mapping

This document maps each implementation claim in the paper "The Governance
Tuple: An Atomic Record for Auditable Agentic AI Decision-Making" to the
specific file and line in this reference implementation where it is realized.

Reviewers can use this table to verify that every cited claim has a
corresponding, runnable implementation.

## Mapping Table

| Paper claim | Section | Reference impl location |
|---|---|---|
| DCT is HMAC-SHA256 signed | 2.2 | `reference_impl/delegation_token.py:438` (`create_token`) |
| DCT signature verification | 2.2 | `reference_impl/delegation_token.py:366` (`verify_signature`) |
| DCT expiry check | 2.2 | `reference_impl/delegation_token.py:378` (`is_expired`) |
| DCT binding to task/contract/subject | 2.2 | `reference_impl/delegation_token.py:392` (`validate_binding`) |
| DCT env-var transport (base64-urlsafe) | 2.2 | `reference_impl/delegation_token.py:320` (`to_env_string`), `:326` (`from_env_string`) |
| DCT JSON serialization roundtrip | 2.2 | `reference_impl/delegation_token.py:301` (`to_json`), `:310` (`from_json`) |
| DCT dict serialization | 2.2 | `reference_impl/delegation_token.py:211` (`to_dict`), `:129` (`from_dict` on ResourceSelector) |
| TokenBinding dataclass | 2.2 | `reference_impl/delegation_token.py:164` (`class TokenBinding`) |
| ResourceSelector dataclass | 2.2 | `reference_impl/delegation_token.py:121` (`class ResourceSelector`) |
| Caveat dataclass | 2.2 | `reference_impl/delegation_token.py:142` (`class Caveat`) |
| DelegationTokenManager class | 2.2 | `reference_impl/delegation_token.py:412` (`class DelegationTokenManager`) |
| IDP_E_DCT_VIOLATION error code | 2.2 | `reference_impl/delegation_token.py:66` |
| IDP_E_TOKEN_EXPIRED error code | 2.2 | `reference_impl/delegation_token.py:67` |
| IDP_E_TOKEN_INVALID error code | 2.2 | `reference_impl/delegation_token.py:68` |
| IDP_E_BINDING_MISMATCH error code | 2.2 | `reference_impl/delegation_token.py:69` |
| IDP_E_LATERAL_AUTH error code | 2.3 | `reference_impl/delegation_token.py:71` |
| IDP_E_DECISION_AUTH error code | 2.3 | `reference_impl/delegation_token.py:72` |
| DEFAULT_MAX_CHAIN_DEPTH = 3 | 3.1 | `reference_impl/delegation_context.py:51` |
| DEFAULT_MAX_REPLANS = 2 | 3.1 | `reference_impl/delegation_context.py:52` |
| Trust-decay formula: delta_eff = min(delta_max, floor(tau/tau_o)) | 3.2 | `reference_impl/delegation_context.py:64` (`compute_dynamic_depth`) |
| tau_LOW=0.15, tau_MEDIUM=0.20, tau_HIGH=0.25, tau_CRITICAL=0.40 | 3.2 | `reference_impl/delegation_context.py:55` (`_TAU_BY_RISK_TIER`) |
| DCTX state machine transitions | 3.3 | `reference_impl/delegation_context.py:222` (`transition`) |
| Monotonic capability attenuation in create_child | 3.4 | `reference_impl/delegation_context.py:288` (`create_child`) |
| IDP_E_CAPABILITY_ESCALATION on child op escalation | 3.4 | `reference_impl/delegation_context.py:47` |
| IDP_E_TRUST_DEPTH_EXCEEDED on dynamic depth violation | 3.2 | `reference_impl/delegation_context.py:48` |
| IDP_E_DEPTH_EXCEEDED on static depth violation | 3.1 | `reference_impl/delegation_context.py:44` |
| IDP_E_INVALID_STATE_TRANSITION on illegal transition | 3.3 | `reference_impl/delegation_context.py:45` |
| IDP_E_REPLAN_LIMIT on replan limit exceeded | 3.3 | `reference_impl/delegation_context.py:46` |
| DCTX is_terminal (VERIFIED, FAILED) | 3.3 | `reference_impl/delegation_context.py:360` (`is_terminal`) |
| DCTX is_active (ISSUED, RUNNING) | 3.3 | `reference_impl/delegation_context.py:364` (`is_active`) |
| DelegationContextManager.create_root | 3.1 | `reference_impl/delegation_context.py:384` (`create_root`) |
| DelegationContextManager.get_context | 3.1 | `reference_impl/delegation_context.py:420` (`get_context`) |
| DelegationContextManager.get_by_intent | 3.1 | `reference_impl/delegation_context.py:424` (`get_by_intent`) |
| DelegationContextManager.get_chain | 3.1 | `reference_impl/delegation_context.py:428` (`get_chain`) |
| DelegationBudget dataclass | 3.1 | `reference_impl/delegation_context.py:95` (`class DelegationBudget`) |
| GovernanceBus append-only log | 4.1 | `reference_impl/governance_bus.py:279` (`append`) |
| GovernanceBus hash-chaining (SHA-256) | 4.2 | `reference_impl/governance_bus.py:476` (`compute_entry_hash`), `:484` (`_get_last_entry_hash`) |
| GovernanceBus verify_chain | 4.2 | `reference_impl/governance_bus.py:507` (`verify_chain`) |
| GovernanceBus _append_sync (atomic write + fsync) | 4.1 | `reference_impl/governance_bus.py:417` (`_append_sync`) |
| DEFAULT_RETENTION_DAYS = 180 (EU AI Act Art 26(5)) | 4.3 | `reference_impl/governance_bus.py:117` |
| ROTATION_SIZE_BYTES = 10MB | 4.3 | `reference_impl/governance_bus.py:118` |
| DEFAULT_GOVERNANCE_DIR = Path("governance_logs") | 4.1 | `reference_impl/governance_bus.py:114` |
| enforce_retention (delete old logs) | 4.3 | `reference_impl/governance_bus.py:738` (`enforce_retention`) |
| Fail-closed signature enforcement (IDP_E_AUDIT_IMMUTABLE) | 4.1 | `reference_impl/governance_bus.py:122` |
| IDP_E_AUDIT_INCOMPLETE on write failure | 4.1 | `reference_impl/governance_bus.py:121` |
| IDP_E_EVIDENCE_REQUIRED (evidence-before-verify) | 4.1 | `reference_impl/governance_bus.py:125` |
| IDP_E_CHAIN_BROKEN on read-time chain validation | 4.2 | `reference_impl/governance_bus.py:126` |
| IDP_E_AMENDMENT_TARGET_MISSING | 4.1 | `reference_impl/governance_bus.py:123` |
| IDP_E_VERIFICATION_REF_INVALID | 4.1 | `reference_impl/governance_bus.py:124` |
| GovernanceEntry dataclass | 4.1 | `reference_impl/governance_bus.py:132` (`class GovernanceEntry`) |
| GovernanceBus query_by_intent | 4.4 | `reference_impl/governance_bus.py:593` (`query_by_intent`) |
| GovernanceBus query_by_task | 4.4 | `reference_impl/governance_bus.py:620` (`query_by_task`) |
| GovernanceBus query_by_entry_id | 4.4 | `reference_impl/governance_bus.py:644` (`query_by_entry_id`) |
| AdapterReceipt per-inference governance proof | 5.1 | `reference_impl/adapter_receipt.py:161` (`class AdapterReceipt`) |
| AdapterReceipt.generate | 5.1 | `reference_impl/adapter_receipt.py:204` (`generate`) |
| AdapterReceipt.verify | 5.1 | `reference_impl/adapter_receipt.py:294` (`verify`) |
| AdapterReceipt.save (append-only JSONL) | 5.1 | `reference_impl/adapter_receipt.py:328` (`save`) |
| BaseNTuple universal governance tuple | 5.2 | `reference_impl/basen_tuple.py:64` (`class BaseNTuple`) |
| BaseNTuple content_hash (excludes signature) | 5.2 | `reference_impl/basen_tuple.py:108` (`content_hash`) |
| BaseNTuple sign_tuple (HMAC-SHA256) | 5.2 | `reference_impl/basen_tuple.py:203` (`sign_tuple`) |
| BaseNTuple verify_tuple_signature | 5.2 | `reference_impl/basen_tuple.py:216` (`verify_tuple_signature`) |
| ENABLE_IDP env var feature flag | 6.1 | `reference_impl/delegation_token.py:48` (`_is_idp_enabled`) |
| Lateral authority enforcement (authority_class requires DCT) | 6.2 | `reference_impl/governance_bus.py:279` (`append`, `authority_class` param) |
| PII scrubbing before hash-chained append | 4.1 | `reference_impl/governance_bus.py:73` (`_scrub_pii`) |
