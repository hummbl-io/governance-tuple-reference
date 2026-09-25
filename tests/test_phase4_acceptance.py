"""Phase 4 acceptance -- F7 observer evidence / G4 phantom detection.

G4: An agent-posted witness without a valid K_O tag is rejected; a
phantom claim is flagged; a truthful claim within tau is not.

These tests invert the A4 phantom-delivery defect: v2.1 had no observer
principal at all, so an agent could claim delivery of an artifact that
was never produced and nothing flagged it.
"""

from __future__ import annotations

import hashlib
import json
import os

os.environ.setdefault("ENABLE_IDP", "true")

from reference_impl.delegation_token import (
    DelegationTokenManager,
    ResourceSelector,
    TokenBinding,
)
from reference_impl.governance_bus import (
    IDP_E_OBSERVER_TAG,
    GovernanceBus,
)
from reference_impl.observer import Observer, flag_phantoms, observer_tag_for
from reference_impl.tuple_verifier import (
    IDP_E_TUPLE_EVIDENCE_TAG,
    verify_tuple,
)

K_O = bytes.fromhex("ab" * 32)
OTHER_KEY = bytes.fromhex("cd" * 32)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# G4a -- the writer refuses unauthenticated witnesses
# ---------------------------------------------------------------------------


class TestWitnessGate:
    def test_untagged_witness_rejected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path, observer_key=K_O)
        ok, err = bus.append(
            "i", "t", "WITNESS",
            {"artifact_id": "a1", "artifact_hash": _hash(b"x"),
             "ref": "run-1", "observer_id": "observer",
             "ts": "2026-01-01T00:00:00Z"},
        )
        assert not ok
        assert err == IDP_E_OBSERVER_TAG

    def test_forged_tag_witness_rejected(self, tmp_path):
        """An agent computing the tag with a wrong key fails."""
        bus = GovernanceBus(base_dir=tmp_path, observer_key=K_O)
        w = {"artifact_id": "a1", "artifact_hash": _hash(b"x"),
             "ref": "run-1", "observer_id": "attacker",
             "ts": "2026-01-01T00:00:00Z"}
        w["observer_tag"] = observer_tag_for(OTHER_KEY, w)
        ok, err = bus.append("i", "t", "WITNESS", w)
        assert not ok
        assert err == IDP_E_OBSERVER_TAG

    def test_witness_rejected_without_observer_config(self, tmp_path):
        """No K_O configured -> no witness can be valid -> reject."""
        bus = GovernanceBus(base_dir=tmp_path)
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"x"), "run-1")
        ok, err = bus.append("i", "t", "WITNESS", w)
        assert not ok
        assert err == IDP_E_OBSERVER_TAG

    def test_observer_witness_accepted_via_shared_key_file(self, tmp_path):
        """Observer persists .observer_key; bus picks it up; witness
        appends cleanly and the chain still verifies."""
        obs = Observer(base_dir=tmp_path)
        bus = GovernanceBus(base_dir=tmp_path)
        assert bus._observer_key == obs.key
        w = obs.emit_witness("a1", _hash(b"artifact-bytes"), "run-7")
        ok, err = bus.append("i", "t", "WITNESS", w)
        assert ok, err
        valid, breaks = bus.verify_log()
        assert valid, breaks

    def test_observer_tag_survives_logging_byte_identical(self, tmp_path):
        """F7 x F8: the logged tuple_data still carries the intact O tag
        (the bus must not rewrite it)."""
        obs = Observer(base_dir=tmp_path)
        bus = GovernanceBus(base_dir=tmp_path)
        w = obs.emit_witness("a2", _hash(b"bytes"), "run-9")
        ok, _ = bus.append("i", "t", "WITNESS", w)
        assert ok
        log = sorted(tmp_path.glob("governance-*.jsonl"))[0]
        entry = json.loads(log.read_text().splitlines()[-1])
        assert entry["tuple_data"] == w
        assert obs.verify(entry["tuple_data"])


# ---------------------------------------------------------------------------
# G4b -- phantom-delivery detection (thm:gt-phantom)
# ---------------------------------------------------------------------------


def _claim(artifact_id="a1", digest=None, claimed_at="2026-01-01T00:00:10Z"):
    return {
        "artifact_id": artifact_id,
        "artifact_digest": digest if digest is not None else _hash(b"body"),
        "claimed_at": claimed_at,
        "agent": "agent-1",
    }


class TestPhantomDetection:
    def test_claim_without_witness_flagged(self):
        flagged = flag_phantoms([_claim()], [], K_O, tau_seconds=60)
        assert flagged and flagged[0][1] == "no_witness"

    def test_witness_with_wrong_digest_flagged(self):
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"different"), "r")
        flagged = flag_phantoms([_claim()], [w], K_O, tau_seconds=60)
        assert flagged[0][1] == "hash_mismatch"

    def test_forged_tag_witness_flagged(self):
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"body"), "r")
        w["observer_tag"] = observer_tag_for(OTHER_KEY, w)
        flagged = flag_phantoms([_claim()], [w], K_O, tau_seconds=60)
        assert flagged[0][1] == "tag_invalid"

    def test_witness_outside_tau_flagged(self):
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"body"), "r",
                             ts="2026-01-01T00:30:00Z")
        flagged = flag_phantoms([_claim()], [w], K_O, tau_seconds=60)
        assert flagged[0][1] == "outside_tau"

    def test_truthful_claim_within_tau_passes(self):
        """Completeness: O witnessed the artifact near the claim time."""
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"body"), "r",
                             ts="2026-01-01T00:00:05Z")
        flagged = flag_phantoms([_claim()], [w], K_O, tau_seconds=60)
        assert flagged == []

    def test_claim_without_timestamp_flagged(self):
        obs = Observer(key=K_O)
        w = obs.emit_witness("a1", _hash(b"body"), "r",
                             ts="2026-01-01T00:00:05Z")
        c = _claim()
        del c["claimed_at"]
        flagged = flag_phantoms([c], [w], K_O, tau_seconds=60)
        assert flagged[0][1] == "outside_tau"


# ---------------------------------------------------------------------------
# G4c -- claims and witnesses through the real bus end-to-end
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_claims_and_witnesses_through_bus(self, tmp_path):
        obs = Observer(base_dir=tmp_path)
        bus = GovernanceBus(base_dir=tmp_path)
        digest = _hash(b"delivered-artifact")
        w = obs.emit_witness("a1", digest, "run-11",
                             ts="2026-01-01T00:00:05Z")
        ok, _ = bus.append("i", "t", "WITNESS", w)
        assert ok
        ok, _ = bus.append("i", "t", "CLAIM", _claim(digest=digest))
        assert ok
        # replay from disk: claim + witness round-trip through the chain
        claims = [e.tuple_data for e in bus.query_all()
                  if e.tuple_type == "CLAIM"]
        witnesses = [e.tuple_data for e in bus.query_all()
                     if e.tuple_type == "WITNESS"]
        flagged = flag_phantoms(claims, witnesses, obs.key,
                                tau_seconds=60)
        assert flagged == []

    def test_phantom_claim_through_bus_flagged(self, tmp_path):
        """A4 scenario: agent claims a delivery O never witnessed."""
        obs = Observer(base_dir=tmp_path)
        bus = GovernanceBus(base_dir=tmp_path)
        ok, _ = bus.append("i", "t", "CLAIM", _claim())
        assert ok
        claims = [e.tuple_data for e in bus.query_all()
                  if e.tuple_type == "CLAIM"]
        witnesses = [e.tuple_data for e in bus.query_all()
                     if e.tuple_type == "WITNESS"]
        flagged = flag_phantoms(claims, witnesses, obs.key,
                                tau_seconds=60)
        assert len(flagged) == 1
        assert flagged[0][1] == "no_witness"


# ---------------------------------------------------------------------------
# G4d -- observer-tagged evidence in verify_tuple (condition 8, O path)
# ---------------------------------------------------------------------------


class TestObserverEvidenceTuple:
    def _mint(self, bus):
        issuer = DelegationTokenManager(secret=b"issuer-secret", bus=bus)
        contract = {
            "contract_id": "c-1",
            "ops_allowed": ["read"],
            "resource_selectors": [
                {"resource_type": "file", "resource_id": "*"}
            ],
        }
        token = issuer.create_token(
            issuer="issuer-1", subject="agent-1", ops_allowed=["read"],
            binding=TokenBinding(task_id="task-1", contract_id="c-1"),
            expiry_minutes=60, contract=contract,
            resource_selectors=[
                ResourceSelector(resource_type="file", resource_id="*")
            ],
        )
        return contract, token

    def test_observer_evidence_passes(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        contract, token = self._mint(bus)
        obs = Observer(key=K_O)
        e = obs.emit_evidence(
            actor="agent-1", task_id="task-1", ops_executed=["read"],
            resources_accessed=[{"resource_type": "file",
                                 "resource_id": "f1"}],
            t_start=token.issued_at,
            t_end=token.issued_at,
        )
        ok, err = verify_tuple(contract, token, e,
                               issuer_secret=b"issuer-secret",
                               observer_key=K_O)
        assert ok, err

    def test_wrong_observer_key_fails_condition8(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        contract, token = self._mint(bus)
        obs = Observer(key=K_O)
        e = obs.emit_evidence(
            actor="agent-1", task_id="task-1", ops_executed=["read"],
            resources_accessed=[], t_start=token.issued_at,
            t_end=token.issued_at,
        )
        ok, err = verify_tuple(contract, token, e,
                               issuer_secret=b"issuer-secret",
                               observer_key=OTHER_KEY)
        assert not ok
        assert err == IDP_E_TUPLE_EVIDENCE_TAG

    def test_agent_forced_evidence_without_tag_fails(self, tmp_path):
        """Untagged dict evidence: no valid W or O tag -> cond 8 fails."""
        bus = GovernanceBus(base_dir=tmp_path)
        contract, token = self._mint(bus)
        e = {"actor": "agent-1", "task_id": "task-1",
             "ops_executed": ["read"], "resources_accessed": [],
             "t_start": token.issued_at, "t_end": token.issued_at}
        ok, err = verify_tuple(contract, token, e,
                               issuer_secret=b"issuer-secret",
                               writer_key=b"w", observer_key=K_O)
        assert not ok
        assert err == IDP_E_TUPLE_EVIDENCE_TAG
