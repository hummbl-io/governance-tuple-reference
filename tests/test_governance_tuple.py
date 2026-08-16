# MIT License
#
# Copyright (c) 2026 The Governance Tuple Authors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Test suite for the Governance Tuple reference implementation.

Tests verify:
  (a) Token signing/verification (HMAC-SHA256)
  (b) Monotonic capability attenuation in create_child
  (c) Hash-chain integrity
  (d) Chain break detection
  (e) Dynamic depth computation (trust-decay model)
  (f) State machine transitions
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

# Ensure governance enforcement is enabled for all tests
os.environ["ENABLE_IDP"] = "true"

from reference_impl.delegation_token import (
    Caveat,
    DelegationCapabilityToken,
    DelegationTokenManager,
    ResourceSelector,
    TokenBinding,
    IDP_E_BINDING_MISMATCH,
    IDP_E_TOKEN_EXPIRED,
    IDP_E_TOKEN_INVALID,
)
from reference_impl.delegation_context import (
    DEFAULT_MAX_CHAIN_DEPTH,
    DEFAULT_MAX_REPLANS,
    DelegationBudget,
    DelegationContext,
    DelegationContextManager,
    compute_dynamic_depth,
    IDP_E_CAPABILITY_ESCALATION,
    IDP_E_DEPTH_EXCEEDED,
    IDP_E_INVALID_STATE_TRANSITION,
    IDP_E_REPLAN_LIMIT,
    IDP_E_TRUST_DEPTH_EXCEEDED,
)
from reference_impl.governance_bus import (
    DEFAULT_RETENTION_DAYS,
    GovernanceBus,
    GovernanceEntry,
    IDP_E_AUDIT_IMMUTABLE,
    IDP_E_CHAIN_BROKEN,
    IDP_E_EVIDENCE_REQUIRED,
)
from reference_impl.basen_tuple import (
    BaseNTuple,
    create_evidence_tuple,
    create_governed_tuple,
    sign_tuple,
    verify_tuple_signature,
)


# ---------------------------------------------------------------------------
# (a) Token signing and verification
# ---------------------------------------------------------------------------


class TestTokenSigning:
    """Test HMAC-SHA256 token signing and verification."""

    def test_create_and_verify_token(self):
        """Token created by manager should verify with same secret."""
        secret = b"test-secret-key-1234567890"
        manager = DelegationTokenManager(secret=secret)
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read", "write"],
            binding=binding,
        )
        assert token.signature != ""
        assert token.verify_signature(secret) is True

    def test_verify_with_wrong_secret_fails(self):
        """Token should not verify with a different secret."""
        manager = DelegationTokenManager(secret=b"correct-secret")
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        assert token.verify_signature(b"wrong-secret") is False

    def test_validate_token_valid(self):
        """validate_token should return (True, None) for a valid token."""
        secret = b"test-secret-key"
        manager = DelegationTokenManager(secret=secret)
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        valid, error = manager.validate_token(token)
        assert valid is True
        assert error is None

    def test_validate_token_invalid_signature(self):
        """validate_token should return IDP_E_TOKEN_INVALID for bad signature."""
        manager = DelegationTokenManager(secret=b"secret-1")
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        # Validate with a different manager (different secret)
        other_manager = DelegationTokenManager(secret=b"secret-2")
        valid, error = other_manager.validate_token(token)
        assert valid is False
        assert error == IDP_E_TOKEN_INVALID

    def test_token_serialization_roundtrip(self):
        """Token should survive to_json/from_json roundtrip."""
        secret = b"roundtrip-secret"
        manager = DelegationTokenManager(secret=secret)
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        selectors = [ResourceSelector(resource_type="file", resource_id="repo/*")]
        caveats = [Caveat(caveat_id="c1", type="TIME_BOUND", parameters={"hours": 2})]
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read", "write"],
            binding=binding,
            resource_selectors=selectors,
            caveats=caveats,
        )
        json_str = token.to_json()
        restored = DelegationCapabilityToken.from_json(json_str)
        assert restored.token_id == token.token_id
        assert restored.issuer == token.issuer
        assert restored.subject == token.subject
        assert restored.signature == token.signature
        assert restored.verify_signature(secret) is True

    def test_env_string_roundtrip(self):
        """Token should survive to_env_string/from_env_string roundtrip."""
        secret = b"env-secret"
        manager = DelegationTokenManager(secret=secret)
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        env_str = token.to_env_string()
        restored = DelegationCapabilityToken.from_env_string(env_str)
        assert restored.token_id == token.token_id
        assert restored.verify_signature(secret) is True

    def test_env_string_rejects_tampered_input(self):
        """from_env_string should reject non-alphabet characters."""
        with pytest.raises(ValueError):
            DelegationCapabilityToken.from_env_string("not!!!valid base64")

    def test_is_expired_false_for_future(self):
        """is_expired should return False for a token with future expiry."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
            expiry_minutes=60,
        )
        assert token.is_expired() is False

    def test_is_expired_true_for_past(self):
        """is_expired should return True for a token with past expiry."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
            expiry_minutes=-1,
        )
        assert token.is_expired() is True

    def test_validate_binding(self):
        """validate_binding should check task/contract/subject match."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="task-001", contract_id="contract-001")
        token = manager.create_token(
            issuer="agent-alpha",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        assert token.validate_binding("task-001", "contract-001", "agent-beta") is True
        assert token.validate_binding("task-002", "contract-001", "agent-beta") is False
        assert token.validate_binding("task-001", "contract-002", "agent-beta") is False
        assert token.validate_binding("task-001", "contract-001", "agent-gamma") is False


# ---------------------------------------------------------------------------
# (b) Monotonic capability attenuation in create_child
# ---------------------------------------------------------------------------


class TestCapabilityAttenuation:
    """Test monotonic capability attenuation in create_child."""

    def test_child_subset_ops_allowed(self):
        """Child with subset of parent ops should succeed."""
        parent = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            ops_allowed=("read", "write", "analyze"),
            status="ISSUED",
        )
        child, error = parent.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
            ops_allowed=("read", "write"),
        )
        assert child is not None
        assert error is None
        assert set(child.ops_allowed).issubset(set(parent.ops_allowed))

    def test_child_escalation_rejected(self):
        """Child with ops not in parent should return IDP_E_CAPABILITY_ESCALATION."""
        parent = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            ops_allowed=("read", "write"),
            status="ISSUED",
        )
        child, error = parent.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
            ops_allowed=("read", "write", "delete"),
        )
        assert child is None
        assert error == IDP_E_CAPABILITY_ESCALATION

    def test_child_inherits_parent_ops(self):
        """Child with no ops specified should inherit parent ops."""
        parent = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            ops_allowed=("read", "write"),
            status="ISSUED",
        )
        child, error = parent.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
        )
        assert child is not None
        assert error is None
        assert child.ops_allowed == parent.ops_allowed

    def test_child_chain_depth_increments(self):
        """Child chain_depth should be parent + 1."""
        parent = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            status="ISSUED",
        )
        child, error = parent.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
        )
        assert child is not None
        assert child.chain_depth == 1
        assert child.parent_task_id == parent.task_id

    def test_depth_exceeded_rejected(self):
        """Subdelegation beyond DEFAULT_MAX_CHAIN_DEPTH should fail."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            parent_task_id="task-000",
            chain_depth=DEFAULT_MAX_CHAIN_DEPTH,
            status="ISSUED",
        )
        child, error = ctx.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
        )
        assert child is None
        assert error == IDP_E_DEPTH_EXCEEDED


# ---------------------------------------------------------------------------
# (c) Hash-chain integrity
# ---------------------------------------------------------------------------


class TestHashChain:
    """Test hash-chain integrity of governance bus."""

    def test_chain_valid_for_correct_entries(self, tmp_path):
        """A properly chained log should verify as valid."""
        bus = GovernanceBus(base_dir=tmp_path)
        secret = b"test-secret"

        # Append several entries
        for i in range(5):
            ok, err = bus.append(
                intent_id="intent-001",
                task_id=f"task-{i:03d}",
                tuple_type="DCTX",
                tuple_data={"task_id": f"task-{i:03d}", "status": "PROPOSED"},
                signature=hashlib.sha256(f"sig-{i}".encode()).hexdigest(),
            )
            assert ok is True
            assert err is None

        bus.close()

        # Verify chain
        valid, breaks = bus.verify_chain(bus._get_current_file())
        assert valid is True
        assert len(breaks) == 0

    def test_genesis_entry_has_null_previous_hash(self, tmp_path):
        """First entry in a log should have previous_hash = None."""
        bus = GovernanceBus(base_dir=tmp_path)
        bus.append(
            intent_id="intent-001",
            task_id="task-001",
            tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
            signature="sig-001",
        )
        bus.close()

        filepath = bus._get_current_file()
        with open(filepath, "r") as f:
            first_line = f.readline().strip()
        data = json.loads(first_line)
        assert data.get("previous_hash") is None

    def test_compute_entry_hash_deterministic(self):
        """compute_entry_hash should be deterministic for same input."""
        line = '{"a":1,"b":2}'
        h1 = GovernanceBus.compute_entry_hash(line)
        h2 = GovernanceBus.compute_entry_hash(line)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_compute_entry_hash_differs_for_different_input(self):
        """compute_entry_hash should differ for different inputs."""
        h1 = GovernanceBus.compute_entry_hash('{"a":1}')
        h2 = GovernanceBus.compute_entry_hash('{"a":2}')
        assert h1 != h2


# ---------------------------------------------------------------------------
# (d) Chain break detection
# ---------------------------------------------------------------------------


class TestChainBreakDetection:
    """Test detection of broken hash chains."""

    def test_chain_break_detected_on_tamper(self, tmp_path):
        """Tampering with an entry should produce a chain break."""
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(5):
            bus.append(
                intent_id="intent-001",
                task_id=f"task-{i:03d}",
                tuple_type="DCTX",
                tuple_data={"index": i},
                signature=hashlib.sha256(f"sig-{i}".encode()).hexdigest(),
            )
        bus.close()

        filepath = bus._get_current_file()

        # Tamper with line 3 (0-indexed line 2 in file, but entry #3)
        with open(filepath, "r") as f:
            lines = f.readlines()

        # Modify entry 3's tuple_data
        entry3 = json.loads(lines[2])
        entry3["tuple_data"] = {"index": 999}
        lines[2] = json.dumps(entry3, sort_keys=True, separators=(",", ":")) + "\n"

        with open(filepath, "w") as f:
            f.writelines(lines)

        valid, breaks = bus.verify_chain(filepath)
        assert valid is False
        assert len(breaks) > 0
        # The break should be at line 4 (entry after the tampered one)
        break_lines = [b["line"] for b in breaks]
        assert 4 in break_lines

    def test_chain_break_on_insertion(self, tmp_path):
        """Inserting a line in the middle should break the chain."""
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(5):
            bus.append(
                intent_id="intent-001",
                task_id=f"task-{i:03d}",
                tuple_type="DCTX",
                tuple_data={"index": i},
                signature=hashlib.sha256(f"sig-{i}".encode()).hexdigest(),
            )
        bus.close()

        filepath = bus._get_current_file()
        with open(filepath, "r") as f:
            lines = f.readlines()

        # Insert a fake line after line 2
        fake = json.dumps({
            "entry_id": "fake-insert",
            "tuple_type": "DCTX",
            "tuple_data": {"fake": True},
            "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        }, sort_keys=True, separators=(",", ":"))
        lines.insert(2, fake + "\n")

        with open(filepath, "w") as f:
            f.writelines(lines)

        valid, breaks = bus.verify_chain(filepath)
        assert valid is False
        assert len(breaks) > 0

    def test_empty_log_is_valid(self, tmp_path):
        """An empty (non-existent) log file should be trivially valid."""
        bus = GovernanceBus(base_dir=tmp_path)
        filepath = tmp_path / "governance-2026-01-01.jsonl"
        valid, breaks = bus.verify_chain(filepath)
        assert valid is True
        assert len(breaks) == 0


# ---------------------------------------------------------------------------
# (e) Dynamic depth computation
# ---------------------------------------------------------------------------


class TestDynamicDepth:
    """Test the trust-decay dynamic depth model."""

    def test_low_risk_high_trust(self):
        """LOW risk tier with high trust should allow max depth."""
        # tau_LOW = 0.15, trust = 0.9 -> floor(0.9/0.15) = 6, min(3, 6) = 3
        depth = compute_dynamic_depth(0.9, "LOW")
        assert depth == 3

    def test_critical_risk_moderate_trust(self):
        """CRITICAL risk tier with moderate trust should limit depth."""
        # tau_CRITICAL = 0.40, trust = 0.8 -> floor(0.8/0.40) = 2, min(3, 2) = 2
        depth = compute_dynamic_depth(0.8, "CRITICAL")
        assert depth == 2

    def test_critical_risk_low_trust(self):
        """CRITICAL risk tier with low trust should return 0."""
        # tau_CRITICAL = 0.40, trust = 0.3 -> floor(0.3/0.40) = 0, min(3, 0) = 0
        depth = compute_dynamic_depth(0.3, "CRITICAL")
        assert depth == 0

    def test_medium_risk(self):
        """MEDIUM risk tier computation."""
        # tau_MEDIUM = 0.20, trust = 0.5 -> floor(0.5/0.20) = 2, min(3, 2) = 2
        depth = compute_dynamic_depth(0.5, "MEDIUM")
        assert depth == 2

    def test_high_risk(self):
        """HIGH risk tier computation."""
        # tau_HIGH = 0.25, trust = 0.6 -> floor(0.6/0.25) = 2, min(3, 2) = 2
        depth = compute_dynamic_depth(0.6, "HIGH")
        assert depth == 2

    def test_trust_decay_formula(self):
        """Verify the exact formula: delta_effective = min(delta_max, floor(tau/tau_o))."""
        for trust, tier, expected in [
            (1.0, "LOW", 3),       # floor(1.0/0.15)=6, min(3,6)=3
            (0.45, "LOW", 3),      # floor(0.45/0.15)=3, min(3,3)=3
            (0.44, "LOW", 2),      # floor(0.44/0.15)=2, min(3,2)=2
            (0.14, "LOW", 0),      # floor(0.14/0.15)=0
            (1.0, "CRITICAL", 2),  # floor(1.0/0.40)=2, min(3,2)=2
            (0.39, "CRITICAL", 0), # floor(0.39/0.40)=0
            (0.40, "CRITICAL", 1), # floor(0.40/0.40)=1
        ]:
            depth = compute_dynamic_depth(trust, tier)
            assert depth == expected, f"trust={trust}, tier={tier}: expected {expected}, got {depth}"

    def test_dynamic_depth_in_create_child(self):
        """create_child with trust_score should use dynamic depth."""
        parent = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            parent_task_id="task-000",
            chain_depth=2,
            risk_tier="CRITICAL",
            status="ISSUED",
        )
        # trust=0.3, CRITICAL -> dynamic_max=0, chain_depth+1=3 > 0
        child, error = parent.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
            trust_score=0.3,
        )
        assert child is None
        assert error == IDP_E_TRUST_DEPTH_EXCEEDED


# ---------------------------------------------------------------------------
# (f) State machine transitions
# ---------------------------------------------------------------------------


class TestStateMachine:
    """Test DCTX state machine transitions."""

    def test_valid_transition_proposed_to_issued(self):
        """PROPOSED -> ISSUED should succeed."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
        )
        ok, error = ctx.transition("ISSUED")
        assert ok is True
        assert error is None
        assert ctx.status == "ISSUED"

    def test_valid_transition_issued_to_running(self):
        """ISSUED -> RUNNING should succeed."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            status="ISSUED",
        )
        ok, error = ctx.transition("RUNNING")
        assert ok is True
        assert error is None
        assert ctx.status == "RUNNING"

    def test_valid_full_lifecycle(self):
        """Full lifecycle: PROPOSED -> ISSUED -> RUNNING -> EVIDENCE_READY -> VERIFIED."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
        )
        for target in ["ISSUED", "RUNNING", "EVIDENCE_READY", "VERIFIED"]:
            ok, error = ctx.transition(target)
            assert ok is True, f"Transition to {target} failed: {error}"
            assert error is None
        assert ctx.status == "VERIFIED"
        assert ctx.is_terminal() is True

    def test_invalid_transition_proposed_to_running(self):
        """PROPOSED -> RUNNING should fail (must go through ISSUED first)."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
        )
        ok, error = ctx.transition("RUNNING")
        assert ok is False
        assert error == IDP_E_INVALID_STATE_TRANSITION

    def test_invalid_transition_from_terminal(self):
        """Transition from VERIFIED (terminal) should fail."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            status="VERIFIED",
        )
        ok, error = ctx.transition("RUNNING")
        assert ok is False
        assert error == IDP_E_INVALID_STATE_TRANSITION

    def test_replan_limit_enforced(self):
        """REPLANNED -> PROPOSED should fail after DEFAULT_MAX_REPLANS replans."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            status="EVIDENCE_READY",
            replan_count=DEFAULT_MAX_REPLANS,
        )
        ok, error = ctx.transition("REPLANNED")
        assert ok is False
        assert error == IDP_E_REPLAN_LIMIT

    def test_replan_count_increments(self):
        """Transitioning to REPLANNED should increment replan_count."""
        ctx = DelegationContext(
            intent_id="intent-001",
            task_id="task-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
            chain_depth=0,
            status="EVIDENCE_READY",
            replan_count=0,
        )
        ok, error = ctx.transition("REPLANNED")
        assert ok is True
        assert ctx.replan_count == 1

    def test_is_terminal(self):
        """is_terminal should return True for VERIFIED and FAILED."""
        for status in ["VERIFIED", "FAILED"]:
            ctx = DelegationContext(
                intent_id="intent-001",
                task_id="task-001",
                delegator_id="agent-alpha",
                delegatee_id="agent-beta",
                contract_id="contract-001",
                chain_depth=0,
                status=status,
            )
            assert ctx.is_terminal() is True

        for status in ["PROPOSED", "ISSUED", "RUNNING", "EVIDENCE_READY", "REPLANNED"]:
            ctx = DelegationContext(
                intent_id="intent-001",
                task_id="task-001",
                delegator_id="agent-alpha",
                delegatee_id="agent-beta",
                contract_id="contract-001",
                chain_depth=0,
                status=status,
            )
            assert ctx.is_terminal() is False

    def test_is_active(self):
        """is_active should return True for ISSUED and RUNNING."""
        for status in ["ISSUED", "RUNNING"]:
            ctx = DelegationContext(
                intent_id="intent-001",
                task_id="task-001",
                delegator_id="agent-alpha",
                delegatee_id="agent-beta",
                contract_id="contract-001",
                chain_depth=0,
                status=status,
            )
            assert ctx.is_active() is True

        for status in ["PROPOSED", "EVIDENCE_READY", "VERIFIED", "FAILED", "REPLANNED"]:
            ctx = DelegationContext(
                intent_id="intent-001",
                task_id="task-001",
                delegator_id="agent-alpha",
                delegatee_id="agent-beta",
                contract_id="contract-001",
                chain_depth=0,
                status=status,
            )
            assert ctx.is_active() is False


# ---------------------------------------------------------------------------
# Context manager tests
# ---------------------------------------------------------------------------


class TestContextManager:
    """Test DelegationContextManager."""

    def test_create_root(self):
        """create_root should create a context with chain_depth=0."""
        mgr = DelegationContextManager()
        ctx = mgr.create_root(
            intent_id="intent-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
        )
        assert ctx.chain_depth == 0
        assert ctx.parent_task_id is None
        assert ctx.status == "PROPOSED"

    def test_get_context(self):
        """get_context should return the context by task_id."""
        mgr = DelegationContextManager()
        ctx = mgr.create_root(
            intent_id="intent-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
        )
        retrieved = mgr.get_context(ctx.task_id)
        assert retrieved is ctx

    def test_get_by_intent(self):
        """get_by_intent should return all contexts for an intent."""
        mgr = DelegationContextManager()
        ctx1 = mgr.create_root(
            intent_id="intent-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
        )
        ctx2 = mgr.create_root(
            intent_id="intent-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-gamma",
            contract_id="contract-002",
        )
        ctx3 = mgr.create_root(
            intent_id="intent-002",
            delegator_id="agent-alpha",
            delegatee_id="agent-delta",
            contract_id="contract-003",
        )
        results = mgr.get_by_intent("intent-001")
        assert len(results) == 2
        assert ctx1 in results
        assert ctx2 in results

    def test_get_chain(self):
        """get_chain should return the full delegation chain from root to task."""
        mgr = DelegationContextManager()
        root = mgr.create_root(
            intent_id="intent-001",
            delegator_id="agent-alpha",
            delegatee_id="agent-beta",
            contract_id="contract-001",
        )
        mgr._contexts[root.task_id] = root

        child, _ = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
        )
        assert child is not None
        mgr._contexts[child.task_id] = child

        grandchild, _ = child.create_child(
            delegatee_id="agent-delta",
            contract_id="contract-003",
        )
        assert grandchild is not None
        mgr._contexts[grandchild.task_id] = grandchild

        chain = mgr.get_chain(grandchild.task_id)
        assert len(chain) == 3
        assert chain[0].task_id == root.task_id
        assert chain[1].task_id == child.task_id
        assert chain[2].task_id == grandchild.task_id


# ---------------------------------------------------------------------------
# GovernanceBus enforcement tests
# ---------------------------------------------------------------------------


class TestGovernanceBusEnforcement:
    """Test governance bus enforcement rules."""

    def test_signature_required(self, tmp_path):
        """Append without signature should fail with IDP_E_AUDIT_IMMUTABLE."""
        bus = GovernanceBus(base_dir=tmp_path)
        ok, error = bus.append(
            intent_id="intent-001",
            task_id="task-001",
            tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
            signature=None,
            require_signature=True,
        )
        assert ok is False
        assert error == IDP_E_AUDIT_IMMUTABLE

    def test_attest_requires_verification_id(self, tmp_path):
        """ATTEST without verification_id should fail with IDP_E_EVIDENCE_REQUIRED."""
        bus = GovernanceBus(base_dir=tmp_path)
        ok, error = bus.append(
            intent_id="intent-001",
            task_id="task-001",
            tuple_type="ATTEST",
            tuple_data={"result": "PASS"},
            signature="some-sig",
        )
        assert ok is False
        assert error == IDP_E_EVIDENCE_REQUIRED

    def test_retention_default(self):
        """DEFAULT_RETENTION_DAYS should be 180."""
        assert DEFAULT_RETENTION_DAYS == 180


# ---------------------------------------------------------------------------
# BaseNTuple tests
# ---------------------------------------------------------------------------


class TestBaseNTuple:
    """Test BaseNTuple signing and verification."""

    def test_evidence_tuple_creation(self):
        """create_evidence_tuple should produce a Tier 1 tuple."""
        t = create_evidence_tuple(
            agent="agent-alpha",
            tool="analyzer",
            args={"input": "test"},
        )
        assert t.tier == 1
        assert t.agent == "agent-alpha"
        assert t.tool == "analyzer"
        assert t.args_hash != ""

    def test_governed_tuple_creation(self):
        """create_governed_tuple should produce a Tier 2 tuple."""
        t = create_governed_tuple(
            agent="agent-alpha",
            tool="analyzer",
            args={"input": "test"},
            contract_id="contract-001",
            dct_id="dct-001",
            dct_chain_depth=1,
        )
        assert t.tier == 2
        assert t.contract_id == "contract-001"
        assert t.dct_id == "dct-001"
        assert t.dct_chain_depth == 1

    def test_sign_and_verify(self):
        """sign_tuple and verify_tuple_signature should roundtrip."""
        t = create_evidence_tuple(
            agent="agent-alpha",
            tool="analyzer",
            args={"input": "test"},
        )
        secret = b"test-secret"
        signed = sign_tuple(t, secret)
        assert signed.signature is not None
        assert verify_tuple_signature(signed, secret) is True

    def test_verify_with_wrong_secret_fails(self):
        """verify_tuple_signature should fail with wrong secret."""
        t = create_evidence_tuple(
            agent="agent-alpha",
            tool="analyzer",
            args={"input": "test"},
        )
        signed = sign_tuple(t, b"correct-secret")
        assert verify_tuple_signature(signed, b"wrong-secret") is False

    def test_content_hash_excludes_signature(self):
        """content_hash should exclude the signature field."""
        t = create_evidence_tuple(
            agent="agent-alpha",
            tool="analyzer",
            args={"input": "test"},
        )
        h1 = t.content_hash()
        signed = sign_tuple(t, b"secret")
        h2 = signed.content_hash()
        assert h1 == h2  # content_hash excludes signature

    def test_to_dict_omits_none(self):
        """to_dict should omit None fields."""
        t = BaseNTuple(agent="alpha", tool="beta", tier=1)
        d = t.to_dict()
        assert "contract_id" not in d  # None omitted
        assert "previous_hash" not in d
        assert "signature" not in d
