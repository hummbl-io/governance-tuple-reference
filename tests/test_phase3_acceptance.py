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

"""Phase 3 inverted acceptance tests -- tokens and verifier (F4, F6, F8).

  T9   A DCT read back from the log verifies under K_I. v2.1 scrubbed
       tuple_data before hashing so logged tokens never verified.
  T14  Signed and hashed objects are byte-identical after passing through
       the bus. v2.1 mangled ~10% of UUIDs, ~28% of SHA-256 hex strings,
       and every stringified float cost. The bus now detects (never
       rewrites) and refuses likely-PII payloads with IDP_E_PII_DETECTED.
  G3   Tokens sign issued_at, contract_digest, parent_token_id; altering
       logged contract content breaks the digest check (F4).
  G1   verify_tuple rejects a violation of each of the 8 conditions of
       def:gt-valid individually and accepts a valid tuple (F6).
  F4   Log-before-release: a bus-backed issuer releases a token only after
       the DCT entry is durably acknowledged; append failure -> no token.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from reference_impl.delegation_token import (
    DelegationCapabilityToken,
    DelegationTokenManager,
    ResourceSelector,
    TokenBinding,
    compute_contract_digest,
    _canonical_json,
    _compute_signature,
)
from reference_impl.governance_bus import GovernanceBus, IDP_E_PII_DETECTED
from reference_impl.tuple_verifier import (
    IDP_E_TUPLE_ACTOR_MISMATCH,
    IDP_E_TUPLE_CONTRACT_DIGEST,
    IDP_E_TUPLE_CONTRACT_ID,
    IDP_E_TUPLE_EVIDENCE_TAG,
    IDP_E_TUPLE_OPS_EXCEED_CONTRACT,
    IDP_E_TUPLE_OPS_EXCEED_TOKEN,
    IDP_E_TUPLE_SELECTOR_EXCEEDED,
    IDP_E_TUPLE_SIGNATURE,
    IDP_E_TUPLE_TIME_WINDOW,
    verify_tuple,
)

ISSUER_KEY = b"issuer-secret-K_I"
WRITER_KEY = b"writer-secret-K_W"
OBSERVER_KEY = b"observer-secret-K_O"

CONTRACT = {
    "contract_id": "contract-p3",
    "ops_allowed": ["read", "write", "audit"],
    "resource_selectors": [
        {"resource_type": "repo", "resource_id": "*", "constraints": {}}
    ],
}


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _tag(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _make_token(mgr, **over):
    binding = TokenBinding(task_id="task-p3", contract_id="contract-p3")
    return mgr.create_token(
        issuer="agent-alpha",
        subject="agent-beta",
        ops_allowed=over.get("ops", ["read", "write"]),
        binding=binding,
        contract=over.get("contract", CONTRACT),
        resource_selectors=over.get(
            "selectors",
            [ResourceSelector(resource_type="repo", resource_id="repo-1")],
        ),
        expiry_minutes=over.get("expiry_minutes", 120),
        parent_token_id=over.get("parent_token_id"),
    )


def _make_evidence(token, writer_key=WRITER_KEY, **over):
    now = datetime.now(timezone.utc)
    ev = {
        "actor": over.get("actor", token.subject),
        "task_id": over.get("task_id", token.binding.task_id),
        "ops_executed": over.get("ops_executed", ["read"]),
        "resources_accessed": over.get(
            "resources_accessed",
            [{"resource_type": "repo", "resource_id": "repo-1"}],
        ),
        "t_start": over.get("t_start", _iso(now + timedelta(seconds=1))),
        "t_end": over.get("t_end", _iso(now + timedelta(minutes=30))),
    }
    if writer_key is not None:
        ev["signature"] = _tag(_canonical_json(ev), writer_key)
    return ev


class TestT9LoggedDctVerifies:
    """T9: a DCT logged through the bus verifies after read-back."""

    def test_dct_roundtrip_through_bus(self, tmp_path):
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        mgr = DelegationTokenManager(secret=ISSUER_KEY, bus=bus)
        token = _make_token(mgr)
        # Read the DCT entry back out of the log file
        log = sorted(tmp_path.glob("governance-*.jsonl"))[0]
        lines = [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
        dct_lines = [x for x in lines if x["tuple_type"] == "DCT"]
        assert len(dct_lines) == 1
        recovered = DelegationCapabilityToken.from_dict(dct_lines[0]["tuple_data"])
        assert recovered.verify_signature(ISSUER_KEY)
        assert recovered.to_dict() == token.to_dict()

    def test_full_token_payload_survives(self, tmp_path):
        """UUIDs, hex signatures, and digests must pass through unaltered."""
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        payload = {
            "token_id": str(uuid.uuid4()),
            "signature": hashlib.sha256(b"x").hexdigest(),
            "contract_digest": hashlib.sha256(b"c").hexdigest(),
            "request_id": uuid.uuid4().hex,
            "name": "service-account",   # v2.1 field-name wiping hit this
            "token": "opaque-bearer",    # and this
            "cost_usd": "0.0287",        # stringified float: 100% mangled in v2.1
            "rel": "v1.2.3-artifact",    # dotted non-IP id
        }
        ok, err = bus.append("i", "t", "DCT", dict(payload))
        assert ok, err
        log = sorted(tmp_path.glob("governance-*.jsonl"))[0]
        entry = json.loads(log.read_text().splitlines()[-1])
        assert entry["tuple_data"] == payload  # byte-identical


class TestT14ByteIdenticalPassThrough:
    """T14: hashed content is never rewritten; PII is refused, not scrubbed."""

    @pytest.mark.parametrize(
        "value",
        [
            str(uuid.uuid4()),                          # UUID
            hashlib.sha256(b"digest").hexdigest(),       # SHA-256 hex
            uuid.uuid4().hex,                            # 32-hex id
            "0.0287",                                    # stringified float
            "agent-alpha-9f546874",                      # dashed id
            "session-2026-09-25T16:21:25Z",              # timestamp-ish
            "ABCDEF0123456789abcdef0123456789",          # uppercase hex
        ],
    )
    def test_identifiers_pass_through_unchanged(self, tmp_path, value):
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        ok, err = bus.append("i", "t", "EVIDENCE", {"v": value})
        assert ok, f"{value!r} wrongly flagged: {err}"
        log = sorted(tmp_path.glob("governance-*.jsonl"))[0]
        entry = json.loads(log.read_text().splitlines()[-1])
        assert entry["tuple_data"]["v"] == value

    @pytest.mark.parametrize(
        "value,label",
        [
            ("user@example.com", "email"),
            ("call 555-123-4567 now", "phone"),
            ("+1 555-123-4567", "phone"),
            ("ssn 123-45-6789", "ssn"),
            ("host 192.168.0.1", "ip"),
        ],
    )
    def test_pii_refused_not_scrubbed(self, tmp_path, value, label):
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        ok, err = bus.append("i", "t", "EVIDENCE", {"note": value})
        assert not ok
        assert err == IDP_E_PII_DETECTED
        # Nothing was written -- no silent rewrite, no PII in the chain
        logs = list(tmp_path.glob("governance-*.jsonl"))
        assert not logs or not logs[0].read_text().strip()

    def test_field_name_allowlist_gone(self, tmp_path):
        """Keys named name/token/secret no longer trigger rewriting or
        rejection -- F8 removed field-name allowlists entirely."""
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        data = {"name": "svc", "token": "tok-9f546874", "secret": "s3ssion"}
        ok, err = bus.append("i", "t", "DCTX", dict(data))
        assert ok, err
        log = sorted(tmp_path.glob("governance-*.jsonl"))[0]
        entry = json.loads(log.read_text().splitlines()[-1])
        assert entry["tuple_data"] == data


class TestG3SignedPayload:
    """G3/F4: issued_at, contract_digest, parent_token_id are signed."""

    def test_signed_fields_present_and_covered(self):
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        token = _make_token(mgr, parent_token_id="tok-parent-1")
        assert token.issued_at and token.contract_digest and token.parent_token_id
        assert token.nonce
        assert token.contract_digest == compute_contract_digest(CONTRACT)
        assert token.verify_signature(ISSUER_KEY)
        # Forging any F4 field breaks the signature
        for field, val in (
            ("issued_at", _iso(datetime.now(timezone.utc) - timedelta(days=1))),
            ("contract_digest", compute_contract_digest({"contract_id": "other"})),
            ("parent_token_id", "tok-forged"),
            ("nonce", "0" * 32),
        ):
            forged = dict(token.to_dict(include_signature=True))
            forged[field] = val
            ft = DelegationCapabilityToken.from_dict(forged)
            assert not ft.verify_signature(ISSUER_KEY), field

    def test_contract_alteration_breaks_digest(self):
        """Altering the logged contract breaks the token's digest binding."""
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        token = _make_token(mgr)
        tampered = dict(CONTRACT)
        tampered["ops_allowed"] = ["read", "write", "audit", "admin"]
        assert token.contract_digest != compute_contract_digest(tampered)

    def test_uniqueness_nonce_differs(self):
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        t1, t2 = _make_token(mgr), _make_token(mgr)
        assert t1.nonce != t2.nonce and t1.token_id != t2.token_id


class TestF4LogBeforeRelease:
    """F4: issuer releases a token only after W acknowledges the log entry."""

    def test_token_logged_before_return(self, tmp_path):
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        mgr = DelegationTokenManager(secret=ISSUER_KEY, bus=bus)
        token = _make_token(mgr)
        dcts = [e for e in bus.query_all(tuple_type="DCT")]
        assert len(dcts) == 1
        assert dcts[0].tuple_data["token_id"] == token.token_id
        assert dcts[0].contract_id == "contract-p3"

    def test_append_failure_no_release(self):
        class _RefusingBus:
            def append(self, **kw):
                return False, "IDP_E_SIMULATED_FAILURE"

        mgr = DelegationTokenManager(secret=ISSUER_KEY, bus=_RefusingBus())
        with pytest.raises(RuntimeError, match="IDP_E_LOG_BEFORE_RELEASE"):
            _make_token(mgr)

    def test_no_bus_still_issues(self):
        """Detached manager (no bus) still issues -- tests/tooling path."""
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        token = _make_token(mgr)
        assert token.verify_signature(ISSUER_KEY)


class TestG1VerifyTuple:
    """G1: verify_tuple accepts a valid tuple; rejects each condition."""

    def _valid(self):
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        token = _make_token(mgr)
        evidence = _make_evidence(token)
        return token, evidence

    def test_valid_tuple_accepted(self):
        token, evidence = self._valid()
        ok, err = verify_tuple(CONTRACT, token, evidence, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert ok, err

    def test_c1_bad_issuer_signature(self):
        token, evidence = self._valid()
        ok, err = verify_tuple(CONTRACT, token, evidence, b"wrong-key",
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_SIGNATURE

    def test_c2_contract_id_mismatch(self):
        token, evidence = self._valid()
        bad = dict(CONTRACT, contract_id="contract-other")
        ok, err = verify_tuple(bad, token, evidence, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_CONTRACT_ID

    def test_c3_contract_digest_mismatch(self):
        token, evidence = self._valid()
        bad = dict(CONTRACT, ops_allowed=["read", "write", "audit", "x"])
        # Same contract_id so we isolate condition 3... but digest differs
        ok, err = verify_tuple(CONTRACT | {"note": "added"}, token, evidence,
                               ISSUER_KEY, writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_CONTRACT_DIGEST

    def test_c4_time_window_violations(self):
        token, _ = self._valid()
        now = datetime.now(timezone.utc)
        # issued_at AFTER t_start (token minted after execution began)
        ev = _make_evidence(token, t_start=_iso(now - timedelta(hours=1)))
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_TIME_WINDOW
        # t_end past expiry (120min default)
        ev = _make_evidence(token, t_end=_iso(now + timedelta(hours=5)))
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_TIME_WINDOW
        # No wall-clock (the v2.1 audit-clock bug): an old-but-in-window
        # tuple still verifies -- issued_at/expiry are compared to E's
        # times, never to datetime.now().
        old_start = now - timedelta(days=3)
        stale = DelegationCapabilityToken(
            token_id=token.token_id, issuer=token.issuer,
            subject=token.subject,
            resource_selectors=token.resource_selectors,
            ops_allowed=token.ops_allowed, caveats=token.caveats,
            expiry=_iso(now + timedelta(days=30)), binding=token.binding,
            issued_at=_iso(old_start),
            contract_digest=token.contract_digest, nonce=token.nonce,
        )
        stale = DelegationCapabilityToken.from_dict(
            stale.to_dict() | {"signature":
                _compute_signature(stale.to_dict(), ISSUER_KEY)})
        ev = _make_evidence(stale,
                            t_start=_iso(old_start + timedelta(seconds=1)),
                            t_end=_iso(old_start + timedelta(minutes=1)))
        ok, err = verify_tuple(CONTRACT, stale, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert ok, err

    def test_c5_ops_exceed_contract(self):
        # Token bound to the narrow contract but granted broader ops --
        # digest matches (c3 passes), ops exceed (c5 fails).
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        narrow = dict(CONTRACT, ops_allowed=["read"])
        token = _make_token(mgr, contract=narrow)
        evidence = _make_evidence(token, ops_executed=["read"])
        ok, err = verify_tuple(narrow, token, evidence, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_OPS_EXCEED_CONTRACT

    def test_c5_ops_exceed_token(self):
        token, _ = self._valid()
        ev = _make_evidence(token, ops_executed=["read", "admin"])
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_OPS_EXCEED_TOKEN

    def test_c6_selector_exceeded(self):
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        # Contract narrows to repo-1 only; token claims wildcard under it.
        narrow = dict(CONTRACT, resource_selectors=[
            {"resource_type": "repo", "resource_id": "repo-1", "constraints": {}}
        ])
        token = _make_token(mgr, contract=narrow, selectors=[
            ResourceSelector(resource_type="repo", resource_id="*")
        ])
        ev = _make_evidence(token)
        ok, err = verify_tuple(narrow, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_SELECTOR_EXCEEDED
        # Accessed resource outside token scope
        token2 = _make_token(mgr)
        ev2 = _make_evidence(token2, resources_accessed=[
            {"resource_type": "db", "resource_id": "prod"}
        ])
        ok, err = verify_tuple(CONTRACT, token2, ev2, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_SELECTOR_EXCEEDED

    def test_c7_actor_mismatch(self):
        token, _ = self._valid()
        ev = _make_evidence(token, actor="agent-gamma")
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_ACTOR_MISMATCH
        ev = _make_evidence(token, task_id="task-other")
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_ACTOR_MISMATCH

    def test_c8_evidence_tag(self):
        token, _ = self._valid()
        # Untagged evidence
        ev = _make_evidence(token, writer_key=None)
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=WRITER_KEY)
        assert not ok and err == IDP_E_TUPLE_EVIDENCE_TAG
        # Wrong key
        ev = _make_evidence(token)
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               writer_key=b"forged")
        assert not ok and err == IDP_E_TUPLE_EVIDENCE_TAG
        # Observer-tagged evidence also satisfies condition 8
        ev = _make_evidence(token, writer_key=None)
        ev["observer_tag"] = _tag(_canonical_json(ev), OBSERVER_KEY)
        ok, err = verify_tuple(CONTRACT, token, ev, ISSUER_KEY,
                               observer_key=OBSERVER_KEY)
        assert ok, err

    def test_entry_evidence_form(self, tmp_path):
        """Condition 8 accepts a writer-tagged GovernanceEntry as E."""
        mgr = DelegationTokenManager(secret=ISSUER_KEY)
        token = _make_token(mgr)
        bus = GovernanceBus(base_dir=str(tmp_path), enable_async=False)
        ev_fields = _make_evidence(token, writer_key=None)
        ok, err = bus.append("i", token.binding.task_id, "EVIDENCE", ev_fields)
        assert ok, err
        entry = next(bus.query_all(tuple_type="EVIDENCE"))
        # Verify the entry's writer tag with the bus's key
        ok, err = verify_tuple(CONTRACT, token, entry, ISSUER_KEY,
                               writer_key=bus._writer_key)
        assert ok, err
