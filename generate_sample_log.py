#!/usr/bin/env python3
"""Regenerate sample_governance_log.jsonl through the remediated bus (T15).

The v2.1 sample was not produced by its own bus: four entries would have
been altered by the scrubber, no EVIDENCE entry linked to a DCT or
CONTRACT, CONTRACT used `allowed_ops` instead of `ops_allowed`, DCTs
lacked selectors/expiry/signature, and the signing secret was never
published.

This script emits a complete scenario through the hardened writer:

    CONTRACT -> DCTX (PROPOSED -> EXECUTING) -> DCT (log-before-release)
    -> EVIDENCE (observer-tagged) -> WITNESS -> CLAIM -> ATTEST

and consolidates the day's segments into sample_governance_log.jsonl.
Test keys (K_W, K_O, K_I) are written to sample_keys.json so the sample
is independently checkable:

    GT_BUS_WRITER_KEY=<writer_key_hex> python verify_chain.py sample_governance_log.jsonl

These keys are TEST-ONLY; they protect nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("ENABLE_IDP", "true")

from reference_impl.delegation_context import DelegationContextManager
from reference_impl.delegation_token import (
    DelegationTokenManager,
    ResourceSelector,
    TokenBinding,
)
from reference_impl.governance_bus import GovernanceBus
from reference_impl.observer import Observer, flag_phantoms

# Published test secrets (T15). NOT production keys.
K_W = bytes.fromhex("aa" * 32)
K_O = bytes.fromhex("bb" * 32)
K_I = b"sample-issuer-secret-test-only"

SAMPLE_PATH = Path("sample_governance_log.jsonl")
KEYS_PATH = Path("sample_keys.json")


def main() -> int:
    contract = {
        "contract_id": "contract-sample-001",
        "ops_allowed": ["read", "write"],
        "resource_selectors": [
            {"resource_type": "repo", "resource_id": "repo-sample"},
        ],
        "parties": ["issuer-alpha", "agent-beta"],
        "terms": "sample contract for remediation demo",
    }

    with tempfile.TemporaryDirectory(prefix="gt-sample-") as tmp:
        bus = GovernanceBus(base_dir=tmp, writer_key=K_W,
                            observer_key=K_O)
        obs = Observer(observer_id="observer-sample", key=K_O)
        intent = "intent-sample-001"

        # 1. CONTRACT -- ops_allowed, not allowed_ops (T15)
        ok, err = bus.append(intent, "task-contract", "CONTRACT", contract,
                             contract_id=contract["contract_id"])
        assert ok, err

        # 2. DCTX lifecycle: PROPOSED -> ISSUED -> RUNNING ->
        # EVIDENCE_READY -> VERIFIED (one entry per state)
        ctx_mgr = DelegationContextManager()
        ctx = ctx_mgr.create_root(
            intent_id=intent, delegator_id="issuer-alpha",
            delegatee_id="agent-beta",
            contract_id=contract["contract_id"],
            ops_allowed=("read", "write"), risk_tier="MEDIUM",
        )
        for status in ("ISSUED", "RUNNING"):
            ok, err = bus.append(intent, ctx.task_id, "DCTX",
                                 ctx.to_dict(),
                                 contract_id=contract["contract_id"])
            assert ok, err
            ok2, err2 = ctx.transition(status)
            assert ok2, err2

        # 3. DCT -- log-before-release: token exists only after the bus
        # acknowledges the DCT entry.
        mgr = DelegationTokenManager(secret=K_I, bus=bus)
        token = mgr.create_token(
            issuer="issuer-alpha", subject="agent-beta",
            ops_allowed=["read", "write"],
            binding=TokenBinding(task_id=ctx.task_id,
                                 contract_id=contract["contract_id"]),
            expiry_minutes=120, contract=contract,
            resource_selectors=[
                ResourceSelector(resource_type="repo",
                                 resource_id="repo-sample")
            ],
            intent_id=intent,
        )
        dct_entry = next(
            e for e in bus.query_all()
            if e.tuple_type == "DCT"
            and e.tuple_data.get("token_id") == token.token_id
        )

        # 4. EVIDENCE -- emitted by observer O under K_O, linked to the
        # DCT entry and the contract (T15: evidence_linked > 0).
        evidence = obs.emit_evidence(
            actor="agent-beta", task_id=ctx.task_id,
            ops_executed=["read", "write"],
            resources_accessed=[{"resource_type": "repo",
                                 "resource_id": "repo-sample"}],
            t_start=token.issued_at,
            t_end=token.issued_at,
            note="sample evidence for linked tuple",
        )
        ok, err = bus.append(
            intent, ctx.task_id, "EVIDENCE", evidence,
            contract_id=contract["contract_id"],
            capability_token_id=dct_entry.entry_id,
        )
        assert ok, err
        ev_entry = next(
            e for e in bus.query_all()
            if e.tuple_type == "EVIDENCE"
            and e.capability_token_id == dct_entry.entry_id
        )

        # 5. WITNESS over the delivered artifact + the agent's CLAIM
        artifact_hash = hashlib.sha256(b"sample-artifact-v1").hexdigest()
        w = obs.emit_witness("artifact-sample-1", artifact_hash,
                             ref=f"evidence:{ev_entry.entry_id}")
        ok, err = bus.append(intent, ctx.task_id, "WITNESS", w)
        assert ok, err
        claim = {
            "artifact_id": "artifact-sample-1",
            "artifact_digest": artifact_hash,
            "claimed_at": w["ts"],
            "agent": "agent-beta",
        }
        ok, err = bus.append(intent, ctx.task_id, "CLAIM", claim)
        assert ok, err

        # 6. ATTEST referencing the EVIDENCE entry
        ok, err = bus.append(
            intent, ctx.task_id, "ATTEST",
            {"verdict": "verified", "verifier": "sample-run",
             "checked": "DCT bound, ops within scope, resources matched"},
            verification_id=ev_entry.entry_id,
        )
        assert ok, err

        # 7. DCTX completes: EVIDENCE_READY -> VERIFIED
        for status in ("EVIDENCE_READY", "VERIFIED"):
            ok2, err2 = ctx.transition(status)
            assert ok2, err2
            ok, err = bus.append(intent, ctx.task_id, "DCTX",
                                 ctx.to_dict(),
                                 contract_id=contract["contract_id"])
            assert ok, err

        # Phantom check on the emitted claim (should be empty)
        flagged = flag_phantoms([claim], [w], K_O, tau_seconds=60)
        assert not flagged, flagged

        # Close before reading so Windows releases the file handle.
        bus.close()

        # Consolidate segments into the published sample file
        lines: list[str] = []
        for seg in sorted(Path(tmp).glob("governance-*.jsonl")):
            lines.extend(ln for ln in
                         seg.read_text(encoding="utf-8").splitlines()
                         if ln.strip())

    SAMPLE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    KEYS_PATH.write_text(json.dumps({
        "_warning": "TEST-ONLY keys for verifying the sample log. "
                    "They protect nothing.",
        "writer_key_hex (K_W)": K_W.hex(),
        "observer_key_hex (K_O)": K_O.hex(),
        "issuer_secret_utf8 (K_I)": K_I.decode("utf-8"),
    }, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {SAMPLE_PATH} ({len(lines)} entries) + {KEYS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
