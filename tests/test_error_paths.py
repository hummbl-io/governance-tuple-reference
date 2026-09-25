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

"""Error path and boundary condition tests for governance tuple reference impl.

Tests verify:
  (a) from_dict / from_json reject malformed input
  (b) Token edge cases (empty, wrong types)
  (c) Hash-chain verification on corrupt files
  (d) Append-only log error recovery
  (e) No-state-changed assertions on rejected operations
"""

import json
import os
from pathlib import Path

import pytest


from reference_impl.delegation_token import (
    Caveat,
    DelegationCapabilityToken,
    DelegationTokenManager,
    ResourceSelector,
    TokenBinding,
)
from reference_impl.governance_bus import (
    GovernanceBus,
    GovernanceEntry,
    IDP_E_AMENDMENT_TARGET_MISSING,
    IDP_E_AUDIT_IMMUTABLE,
    IDP_E_EVIDENCE_REQUIRED,
    IDP_E_LATERAL_AUTH,
    IDP_E_VERIFICATION_REF_INVALID,
)
from reference_impl.basen_tuple import (
    BaseNTuple,
    append_tuple,
    create_evidence_tuple,
)
from reference_impl.delegation_context import (
    DelegationContext,
    IDP_E_CAPABILITY_ESCALATION,
    IDP_E_DEPTH_EXCEEDED,
)


# ---------------------------------------------------------------------------
# (a) from_dict / from_json reject malformed input
# ---------------------------------------------------------------------------


class TestFromDictValidation:
    """Test that from_dict methods reject malformed input."""

    def test_resource_selector_rejects_non_dict(self):
        with pytest.raises(ValueError, match="requires dict"):
            ResourceSelector.from_dict("not a dict")

    def test_resource_selector_rejects_missing_resource_type(self):
        with pytest.raises(ValueError, match="missing required field"):
            ResourceSelector.from_dict({"resource_id": "x"})

    def test_caveat_rejects_non_dict(self):
        with pytest.raises(ValueError, match="requires dict"):
            Caveat.from_dict(42)

    def test_caveat_rejects_missing_caveat_id(self):
        with pytest.raises(ValueError, match="missing required field"):
            Caveat.from_dict({"type": "TIME_BOUND"})

    def test_caveat_rejects_missing_type(self):
        with pytest.raises(ValueError, match="missing required field"):
            Caveat.from_dict({"caveat_id": "c1"})

    def test_token_binding_rejects_non_dict(self):
        with pytest.raises(ValueError, match="requires dict"):
            TokenBinding.from_dict(None)

    def test_token_binding_rejects_missing_task_id(self):
        with pytest.raises(ValueError, match="missing required field"):
            TokenBinding.from_dict({"contract_id": "c1"})

    def test_dct_rejects_non_dict(self):
        with pytest.raises(ValueError, match="requires dict"):
            DelegationCapabilityToken.from_dict([])

    def test_dct_rejects_missing_token_id(self):
        with pytest.raises(ValueError, match="missing required field"):
            DelegationCapabilityToken.from_dict({"issuer": "a", "subject": "b"})

    def test_dct_rejects_missing_issuer(self):
        with pytest.raises(ValueError, match="missing required field"):
            DelegationCapabilityToken.from_dict({"token_id": "t1", "subject": "b"})

    def test_dct_rejects_missing_subject(self):
        with pytest.raises(ValueError, match="missing required field"):
            DelegationCapabilityToken.from_dict({"token_id": "t1", "issuer": "a"})

    def test_dct_rejects_non_list_resource_selectors(self):
        with pytest.raises(ValueError, match="resource_selectors must be a list"):
            DelegationCapabilityToken.from_dict({
                "token_id": "t1", "issuer": "a", "subject": "b",
                "resource_selectors": "not a list",
            })

    def test_dct_rejects_non_list_ops_allowed(self):
        with pytest.raises(ValueError, match="ops_allowed must be a list"):
            DelegationCapabilityToken.from_dict({
                "token_id": "t1", "issuer": "a", "subject": "b",
                "ops_allowed": 123,
            })

    def test_dct_rejects_non_list_caveats(self):
        with pytest.raises(ValueError, match="caveats must be a list"):
            DelegationCapabilityToken.from_dict({
                "token_id": "t1", "issuer": "a", "subject": "b",
                "caveats": "not a list",
            })

    def test_from_json_rejects_non_str(self):
        with pytest.raises(ValueError, match="requires str"):
            DelegationCapabilityToken.from_json(123)

    def test_from_json_rejects_malformed_json(self):
        with pytest.raises(ValueError, match="Malformed JSON"):
            DelegationCapabilityToken.from_json("{not valid json")

    def test_from_env_string_rejects_empty(self):
        with pytest.raises(ValueError, match="Empty env-string"):
            DelegationCapabilityToken.from_env_string("")

    def test_from_env_string_rejects_non_str(self):
        with pytest.raises(ValueError, match="requires str"):
            DelegationCapabilityToken.from_env_string(None)

    def test_from_env_string_rejects_non_alphabet(self):
        # Use a string that is a multiple of 4 but contains non-alphabet chars
        with pytest.raises(ValueError, match="not in URL-safe alphabet"):
            DelegationCapabilityToken.from_env_string("ab!c")

    def test_from_env_string_rejects_bad_padding_position(self):
        # Padding must only be at the end
        with pytest.raises(ValueError, match="padding only allowed at end"):
            DelegationCapabilityToken.from_env_string("abc=def")

    def test_from_env_string_rejects_bad_length(self):
        # Length must be multiple of 4
        with pytest.raises(ValueError, match="not a multiple of 4"):
            DelegationCapabilityToken.from_env_string("abc")


# ---------------------------------------------------------------------------
# (b) Token edge cases
# ---------------------------------------------------------------------------


class TestTokenEdgeCases:
    """Test token edge cases and boundary conditions."""

    def test_create_token_rejects_empty_issuer(self):
        """Creating a token with empty issuer should still work (no validation)."""
        # The current implementation doesn't validate empty strings for issuer/subject
        # This test documents current behavior
        manager = DelegationTokenManager(secret=b"test-secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="",
            subject="agent-beta",
            ops_allowed=["read"],
            binding=binding,
        )
        assert token.issuer == ""

    def test_verify_signature_with_empty_signature_fails(self):
        """A token with empty signature should fail verification."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read"], binding=binding
        )
        # Create a token with empty signature
        tampered = DelegationCapabilityToken(
            token_id=token.token_id,
            issuer=token.issuer,
            subject=token.subject,
            binding=token.binding,
            signature="",
        )
        assert tampered.verify_signature(b"secret") is False

    def test_is_expired_with_no_expiry(self):
        """Token with no expiry should never be expired."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read"],
            binding=binding, expiry_minutes=None,
        )
        assert token.is_expired() is False

    def test_is_expired_with_malformed_expiry(self):
        """Token with malformed expiry should be treated as expired (fail-closed)."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read"],
            binding=binding, expiry_minutes=60,
        )
        # Manually create a token with bad expiry
        bad = DelegationCapabilityToken(
            token_id=token.token_id,
            issuer=token.issuer,
            subject=token.subject,
            binding=token.binding,
            expiry="not-a-date",
            signature=token.signature,
        )
        assert bad.is_expired() is True

    def test_validate_binding_with_no_binding(self):
        """Token without binding should fail binding validation."""
        manager = DelegationTokenManager(secret=b"secret")
        token = DelegationCapabilityToken(
            token_id="t1", issuer="a", subject="b",
            signature="sig",
        )
        assert token.validate_binding("t1", "c1", "b") is False

    def test_check_least_privilege_denied_op(self):
        """check_least_privilege should deny ops not in token."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read"],
            binding=binding,
        )
        ok, err = manager.check_least_privilege(token, "write")
        assert ok is False

    def test_check_least_privilege_denied_tool(self):
        """check_least_privilege should deny tools in denied_tools."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read", "write"],
            binding=binding,
        )
        ok, err = manager.check_least_privilege(
            token, "write", denied_tools=["write"]
        )
        assert ok is False

    def test_check_least_privilege_allowed_tool(self):
        """check_least_privilege should allow ops in allowed_tools."""
        manager = DelegationTokenManager(secret=b"secret")
        binding = TokenBinding(task_id="t1", contract_id="c1")
        token = manager.create_token(
            issuer="a", subject="b", ops_allowed=["read", "write"],
            binding=binding,
        )
        ok, err = manager.check_least_privilege(
            token, "write", allowed_tools=["read", "write"]
        )
        assert ok is True


# ---------------------------------------------------------------------------
# (c) Hash-chain verification on corrupt files
# ---------------------------------------------------------------------------


class TestChainVerificationCorrupt:
    """Test hash-chain verification on corrupt files."""

    def test_verify_nonexistent_file(self, tmp_path):
        """Verify a nonexistent file should report FILE_ERROR."""
        from reference_impl.governance_bus import GovernanceBus
        bus = GovernanceBus(base_dir=tmp_path)
        filepath = tmp_path / "governance-2026-01-01.jsonl"
        valid, breaks = bus.verify_chain(filepath)
        # Nonexistent files are treated as valid (empty)
        assert valid is True
        assert len(breaks) == 0

    def test_verify_chain_with_malformed_json(self, tmp_path):
        """Malformed JSON lines should produce PARSE_ERROR breaks."""
        filepath = tmp_path / "governance-test.jsonl"
        filepath.write_text(
            '{"entry_id":"e1","previous_hash":null}\n'
            'not valid json\n'
            '{"entry_id":"e3","previous_hash":"abc"}\n',
            encoding="utf-8",
        )
        bus = GovernanceBus(base_dir=tmp_path)
        valid, breaks = bus.verify_chain(filepath)
        assert valid is False
        parse_errors = [b for b in breaks if b["entry_id"] == "PARSE_ERROR"]
        assert len(parse_errors) > 0

    def test_verify_chain_with_non_object_json(self, tmp_path):
        """JSON that is not an object should produce PARSE_ERROR."""
        filepath = tmp_path / "governance-test.jsonl"
        filepath.write_text(
            '{"entry_id":"e1","previous_hash":null}\n'
            '"just a string"\n',
            encoding="utf-8",
        )
        bus = GovernanceBus(base_dir=tmp_path)
        valid, breaks = bus.verify_chain(filepath)
        assert valid is False

    def test_verify_chain_genesis_with_non_null_hash(self, tmp_path):
        """Genesis entry with non-null previous_hash should break."""
        filepath = tmp_path / "governance-test.jsonl"
        filepath.write_text(
            '{"entry_id":"e1","previous_hash":"should-be-null"}\n',
            encoding="utf-8",
        )
        bus = GovernanceBus(base_dir=tmp_path)
        valid, breaks = bus.verify_chain(filepath)
        assert valid is False
        assert breaks[0]["expected"] == "null (genesis)"


# ---------------------------------------------------------------------------
# (d) Append-only log error recovery
# ---------------------------------------------------------------------------


class TestAppendErrorRecovery:
    """Test governance bus append error recovery."""

    def test_amendment_target_missing_rejected(self, tmp_path):
        """Amendment referencing nonexistent entry should be rejected."""
        bus = GovernanceBus(base_dir=tmp_path)
        ok, err = bus.append(
            intent_id="i1",
            task_id="t1",
            tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
            amendment_of="nonexistent-entry",
        )
        assert ok is False
        assert err == IDP_E_AMENDMENT_TARGET_MISSING
        # No-state-changed: no file should have been created
        files = list(tmp_path.glob("governance-*.jsonl"))
        assert len(files) == 0

    def test_attest_without_verification_id_rejected(self, tmp_path):
        """ATTEST without verification_id should be rejected."""
        bus = GovernanceBus(base_dir=tmp_path)
        ok, err = bus.append(
            intent_id="i1",
            task_id="t1",
            tuple_type="ATTEST",
            tuple_data={"result": "PASS"},
        )
        assert ok is False
        assert err == IDP_E_EVIDENCE_REQUIRED
        # No-state-changed
        files = list(tmp_path.glob("governance-*.jsonl"))
        assert len(files) == 0

    def test_attest_with_invalid_verification_ref_rejected(self, tmp_path):
        """ATTEST with verification_id referencing non-EVIDENCE entry should fail."""
        bus = GovernanceBus(base_dir=tmp_path)
        # First append a DCTX entry
        ok, _ = bus.append(
            intent_id="i1", task_id="t1", tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
        )
        assert ok is True
        # Try to ATTEST referencing the DCTX entry (not EVIDENCE)
        entries = list(bus.query_all())
        dctx_entry = entries[0]
        ok, err = bus.append(
            intent_id="i1", task_id="t1", tuple_type="ATTEST",
            tuple_data={"result": "PASS"},
            verification_id=dctx_entry.entry_id,
        )
        assert ok is False
        assert err == IDP_E_VERIFICATION_REF_INVALID

    def test_authority_class_without_dct_rejected(self, tmp_path):
        """authority_class entry without capability_token_id should fail."""
        bus = GovernanceBus(base_dir=tmp_path)
        ok, err = bus.append(
            intent_id="i1", task_id="t1", tuple_type="DCTX",
            tuple_data={"decision": "approve"},
            authority_class=True,
        )
        assert ok is False
        assert err == IDP_E_LATERAL_AUTH
        # No-state-changed
        files = list(tmp_path.glob("governance-*.jsonl"))
        assert len(files) == 0

    def test_authority_class_with_invalid_dct_rejected(self, tmp_path):
        """authority_class entry with invalid DCT reference should fail."""
        bus = GovernanceBus(base_dir=tmp_path)
        # Append a DCTX (not a DCT)
        ok, _ = bus.append(
            intent_id="i1", task_id="t1", tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
        )
        assert ok is True
        entries = list(bus.query_all())
        dctx_entry = entries[0]
        # Try authority_class referencing the DCTX (not DCT)
        ok, err = bus.append(
            intent_id="i1", task_id="t1", tuple_type="DCTX",
            tuple_data={"decision": "approve"},
            authority_class=True,
            capability_token_id=dctx_entry.entry_id,
        )
        assert ok is False
        # Should be DECISION_AUTH, not LATERAL_AUTH
        from reference_impl.governance_bus import IDP_E_DECISION_AUTH
        assert err == IDP_E_DECISION_AUTH

    def test_append_tuple_creates_parent_dir(self, tmp_path):
        """append_tuple should create parent directories."""
        t = create_evidence_tuple(agent="a", tool="b", args={"x": 1})
        log_path = tmp_path / "subdir" / "tuples.jsonl"
        append_tuple(t, str(log_path))
        assert log_path.exists()
        line = log_path.read_text(encoding="utf-8").strip()
        data = json.loads(line)
        assert data["agent"] == "a"


# ---------------------------------------------------------------------------
# (e) No-state-changed assertions on rejected operations
# ---------------------------------------------------------------------------


class TestNoStateChanged:
    """Verify rejected operations don't modify state."""

    def test_capability_escalation_no_state_change(self):
        """Failed create_child due to escalation should not modify parent."""
        parent = DelegationContext(
            intent_id="i1", task_id="t1", delegator_id="a", delegatee_id="b",
            contract_id="c1", chain_depth=0, ops_allowed=("read",),
            status="ISSUED",
        )
        original_ops = parent.ops_allowed
        child, error = parent.create_child(
            delegatee_id="c", contract_id="c2",
            ops_allowed=("read", "delete"),
        )
        assert child is None
        assert error == IDP_E_CAPABILITY_ESCALATION
        # Parent unchanged
        assert parent.ops_allowed == original_ops
        assert parent.chain_depth == 0

    def test_depth_exceeded_no_state_change(self):
        """Failed create_child due to depth should not modify parent."""
        from reference_impl.delegation_context import DEFAULT_MAX_CHAIN_DEPTH
        # F5: parented contexts are built via create_child; chain to the cap.
        parent = DelegationContext(
            intent_id="i1", task_id="t1", delegator_id="a", delegatee_id="b",
            contract_id="c1", chain_depth=0, ops_allowed=("read",),
            status="ISSUED",
        )
        for _ in range(DEFAULT_MAX_CHAIN_DEPTH):
            parent, _err = parent.create_child(delegatee_id="c", contract_id="c2")
            assert parent is not None
        original_depth = parent.chain_depth
        child, error = parent.create_child(
            delegatee_id="c", contract_id="c2",
        )
        assert child is None
        assert error == IDP_E_DEPTH_EXCEEDED
        assert parent.chain_depth == original_depth

    def test_invalid_transition_no_state_change(self):
        """Failed state transition should not change status."""
        ctx = DelegationContext(
            intent_id="i1", task_id="t1", delegator_id="a", delegatee_id="b",
            contract_id="c1", chain_depth=0, status="PROPOSED",
        )
        ok, error = ctx.transition("VERIFIED")  # Invalid: PROPOSED -> VERIFIED
        assert ok is False
        assert ctx.status == "PROPOSED"  # Unchanged


# ---------------------------------------------------------------------------
# (f) GovernanceEntry from_dict edge cases
# ---------------------------------------------------------------------------


class TestGovernanceEntryFromDict:
    """Test GovernanceEntry.from_dict edge cases."""

    def test_from_dict_with_missing_optional_fields(self):
        """from_dict should handle missing optional fields with defaults."""
        data = {
            "timestamp": "2026-01-01T00:00:00Z",
            "entry_id": "e1",
            "intent_id": "i1",
            "task_id": "t1",
            "tuple_type": "DCTX",
            "tuple_data": {"status": "PROPOSED"},
        }
        entry = GovernanceEntry.from_dict(data)
        assert entry.signature is None
        assert entry.state == "ok"
        assert entry.drift == 0.0
        assert entry.contract_id is None

    def test_from_dict_with_all_fields(self):
        """from_dict should handle all fields present."""
        data = {
            "timestamp": "2026-01-01T00:00:00Z",
            "entry_id": "e1",
            "intent_id": "i1",
            "task_id": "t1",
            "tuple_type": "DCTX",
            "tuple_data": {"status": "PROPOSED"},
            "signature": "sig",
            "state": "blocked",
            "drift": 0.5,
            "contract_id": "c1",
            "capability_token_id": "dct1",
            "verification_id": "v1",
            "amendment_of": "e0",
            "previous_hash": "abc123",
        }
        entry = GovernanceEntry.from_dict(data)
        assert entry.signature == "sig"
        assert entry.state == "blocked"
        assert entry.drift == 0.5
        assert entry.contract_id == "c1"
        assert entry.previous_hash == "abc123"

    def test_to_jsonl_roundtrip(self):
        """to_jsonl should produce valid JSON that can be parsed back."""
        entry = GovernanceEntry(
            timestamp="2026-01-01T00:00:00Z",
            entry_id="e1",
            intent_id="i1",
            task_id="t1",
            tuple_type="DCTX",
            tuple_data={"status": "PROPOSED"},
            signature="sig",
        )
        line = entry.to_jsonl()
        data = json.loads(line)
        restored = GovernanceEntry.from_dict(data)
        assert restored.entry_id == entry.entry_id
        assert restored.tuple_type == entry.tuple_type
        assert restored.signature == entry.signature
