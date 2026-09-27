"""T15 -- the published sample must be a product of this bus.

Gate (remediation master §8): sample regenerated through the fixed bus;
at least one complete linked (C, D, E) tuple; test secret published;
bus leaves it unchanged.

The v2.1 sample failed all of these: 4 entries would have been altered
by the scrubber, 0 EVIDENCE entries linked to a DCT or CONTRACT,
CONTRACT used `allowed_ops`, DCTs lacked expiry/signature, and the
signing secret was unpublished.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("ENABLE_IDP", "true")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from reference_impl.delegation_token import (  # noqa: E402
    DelegationCapabilityToken,
    compute_contract_digest,
)
from reference_impl.governance_bus import _detect_pii  # noqa: E402
from reference_impl.observer import flag_phantoms  # noqa: E402
from reference_impl.tuple_verifier import verify_tuple  # noqa: E402
from verify_chain import verify_entries  # noqa: E402

SAMPLE = REPO / "sample_governance_log.jsonl"
KEYS = REPO / "sample_keys.json"


def _load() -> tuple[list[dict], dict]:
    entries = [json.loads(ln) for ln in
               SAMPLE.read_text(encoding="utf-8").splitlines() if ln.strip()]
    keys = json.loads(KEYS.read_text(encoding="utf-8"))
    return entries, keys


def _by_type(entries, t):
    return [e for e in entries if e.get("tuple_type") == t]


class TestSampleIntegrity:
    def test_chain_verifies_with_published_writer_key(self):
        entries, keys = _load()
        # Rows must carry the exact raw line the hash chain binds to.
        rows = [
            (ln, e, "sample", i + 1)
            for i, (ln, e) in enumerate(zip(
                SAMPLE.read_text(encoding="utf-8").splitlines(), entries))
        ]
        ok, breaks = verify_entries(
            rows, writer_key=bytes.fromhex(keys["writer_key_hex (K_W)"]))
        assert ok, breaks

    def test_every_entry_tagged_and_sequenced(self):
        entries, _ = _load()
        for e in entries:
            assert e.get("signature"), e.get("entry_id")
            assert isinstance(e.get("seq"), int)
        seqs = [e["seq"] for e in entries]
        assert seqs == sorted(seqs) == list(range(1, len(entries) + 1))

    def test_bus_leaves_sample_unchanged(self):
        """F8/T15: no entry's tuple_data trips the PII detector -- the
        bus stores payloads byte-identical (no scrubber remains)."""
        entries, _ = _load()
        for e in entries:
            assert _detect_pii(e.get("tuple_data") or {}) == [], e


class TestSampleSchema:
    def test_contract_uses_ops_allowed(self):
        entries, _ = _load()
        for c in _by_type(entries, "CONTRACT"):
            td = c["tuple_data"]
            assert "ops_allowed" in td
            assert "allowed_ops" not in td

    def test_dct_carries_f4_payload(self):
        entries, keys = _load()
        dcts = _by_type(entries, "DCT")
        assert dcts
        for d in dcts:
            td = d["tuple_data"]
            for field_name in ("issued_at", "contract_digest",
                               "parent_token_id", "nonce", "expiry",
                               "signature", "resource_selectors"):
                assert field_name in td, field_name
            token = DelegationCapabilityToken.from_dict(td)
            assert token.verify_signature(
                keys["issuer_secret_utf8 (K_I)"].encode("utf-8"))


class TestLinkedTuple:
    def _tuple(self):
        entries, keys = _load()
        contract_e = _by_type(entries, "CONTRACT")[0]
        dct_e = _by_type(entries, "DCT")[0]
        ev_e = next(
            e for e in _by_type(entries, "EVIDENCE")
            if e.get("capability_token_id") == dct_e.get("entry_id"))
        return contract_e["tuple_data"], dct_e["tuple_data"], \
            ev_e["tuple_data"], keys

    def test_evidence_links_dct_and_contract(self):
        entries, _ = _load()
        dct_ids = {e["entry_id"] for e in _by_type(entries, "DCT")}
        c_ids = {e["tuple_data"].get("contract_id")
                 for e in _by_type(entries, "CONTRACT")}
        linked = [e for e in _by_type(entries, "EVIDENCE")
                  if e.get("capability_token_id") in dct_ids
                  and e.get("contract_id") in c_ids]
        assert linked, "no EVIDENCE entry links a DCT and CONTRACT"

    def test_complete_tuple_verifies(self):
        contract_td, dct_td, ev_td, keys = self._tuple()
        token = DelegationCapabilityToken.from_dict(dct_td)
        assert token.contract_digest == compute_contract_digest(contract_td)
        ok, err = verify_tuple(
            contract_td, token, ev_td,
            issuer_secret=keys["issuer_secret_utf8 (K_I)"].encode("utf-8"),
            observer_key=bytes.fromhex(keys["observer_key_hex (K_O)"]),
        )
        assert ok, err

    def test_attest_references_evidence(self):
        entries, _ = _load()
        ev_ids = {e["entry_id"] for e in _by_type(entries, "EVIDENCE")}
        attest = _by_type(entries, "ATTEST")
        assert attest
        assert all(a.get("verification_id") in ev_ids for a in attest)

    def test_witness_covers_claim(self):
        entries, keys = _load()
        claims = [e["tuple_data"] for e in _by_type(entries, "CLAIM")]
        witnesses = [e["tuple_data"] for e in _by_type(entries, "WITNESS")]
        assert claims and witnesses
        flagged = flag_phantoms(
            claims, witnesses,
            bytes.fromhex(keys["observer_key_hex (K_O)"]),
            tau_seconds=3600)
        assert flagged == [], flagged


class TestKeysPublished:
    def test_keys_file_has_all_three(self):
        _, keys = _load()
        assert "TEST-ONLY" in keys["_warning"]
        assert len(keys["writer_key_hex (K_W)"]) == 64
        assert len(keys["observer_key_hex (K_O)"]) == 64
        assert keys["issuer_secret_utf8 (K_I)"]
