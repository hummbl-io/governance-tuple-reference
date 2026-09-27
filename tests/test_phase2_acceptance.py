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

"""Phase 2 inverted acceptance tests -- delegation contexts (F5, F10).

Every test inverts a defect reproduced by the adversarial harness
(gt_repro.py) against the unremediated reference implementation:

  T10a  create_root left ops_allowed unset; empty set must grant NOTHING.
  T10b  create_child skipped the subset check when either op set was empty
        ("read -> () -> delete,admin" escalated). Empty is a floor, not a
        bypass.
  T10c  Direct DelegationContext(parent_task_id=...) construction forged
        parented contexts without any parent check. Construction now
        requires _parent_context (create_child) or _rehydrate (from_dict).
  T10d  The dataclass was mutable: ctx.ops_allowed could be rebound after
        creation. DelegationContext/DelegationBudget are now frozen.
  T11   EVIDENCE_READY -> FAILED was missing: at the replan limit a task
        could neither replan nor fail -- VERIFIED was the only exit.
  T12   compute_dynamic_depth used floating-point floor (0.6 // 0.20 == 2,
        not 3) and fell back to LOW for unknown tiers (fail-open).
        Now: fixed-point integer floor; unknown tier -> 0.
        The second depth model in delegation_token.py is deleted.
  G5    10,000 random delegation trees (fixed seeds) never escalate ops.
"""

import random
from dataclasses import FrozenInstanceError

import pytest

from reference_impl.delegation_context import (
    DEFAULT_MAX_CHAIN_DEPTH,
    DEFAULT_MAX_REPLANS,
    DelegationBudget,
    DelegationContext,
    DelegationContextManager,
    IDP_E_CAPABILITY_ESCALATION,
    IDP_E_INVALID_STATE_TRANSITION,
    IDP_E_REPLAN_LIMIT,
    compute_dynamic_depth,
    _TAU_BY_RISK_TIER,
)

OPS_POOL = ("read", "write", "delete", "admin", "deploy", "audit")


def _root(ops=("read", "write", "delete", "admin"), tier="MEDIUM"):
    return DelegationContext(
        intent_id="intent-p2",
        task_id="task-root",
        delegator_id="agent-alpha",
        delegatee_id="agent-beta",
        contract_id="contract-001",
        chain_depth=0,
        risk_tier=tier,
        ops_allowed=ops,
        status="ISSUED",
    )


class TestT10aEmptyRootGrantsNothing:
    """T10a: () grants nothing -- a capability-free root cannot mint ops."""

    def test_empty_root_rejects_any_child_ops(self):
        root = _root(ops=())
        child, error = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
            ops_allowed=("read",),
        )
        assert child is None
        assert error == IDP_E_CAPABILITY_ESCALATION

    def test_empty_root_permits_only_empty_child(self):
        root = _root(ops=())
        child, error = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="contract-002",
            ops_allowed=(),
        )
        assert error is None
        assert child is not None
        assert child.ops_allowed == ()

    def test_manager_create_root_default_is_empty(self):
        mgr = DelegationContextManager()
        ctx = mgr.create_root("i", "a", "b", "c")
        assert ctx.ops_allowed == ()
        child, error = ctx.create_child(
            delegatee_id="x", contract_id="c2", ops_allowed=("read",)
        )
        assert child is None
        assert error == IDP_E_CAPABILITY_ESCALATION


class TestT10bEmptySetIsFloorNotBypass:
    """T10b: the read -> () -> delete,admin escalation is closed."""

    def test_empty_intermediate_cannot_escalate(self):
        root = _root(ops=("read",))
        mid, err = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="c2",
            ops_allowed=(),
        )
        assert err is None and mid is not None
        leaf, err = mid.create_child(
            delegatee_id="agent-delta",
            contract_id="c3",
            ops_allowed=("delete", "admin"),
        )
        assert leaf is None
        assert err == IDP_E_CAPABILITY_ESCALATION

    def test_nonempty_parent_allows_empty_child(self):
        root = _root(ops=("read", "write"))
        child, err = root.create_child(
            delegatee_id="agent-gamma", contract_id="c2", ops_allowed=()
        )
        assert err is None
        assert child.ops_allowed == ()

    def test_child_ops_must_subset_parent(self):
        root = _root(ops=("read", "write"))
        child, err = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="c2",
            ops_allowed=("read", "admin"),
        )
        assert child is None
        assert err == IDP_E_CAPABILITY_ESCALATION


class TestT10cConstructorDiscipline:
    """T10c: parented construction is checked against the parent."""

    def test_direct_parented_construction_rejected(self):
        with pytest.raises(ValueError, match="IDP_E_CAPABILITY_ESCALATION"):
            DelegationContext(
                intent_id="intent-p2",
                task_id="task-forged",
                delegator_id="agent-beta",
                delegatee_id="agent-gamma",
                contract_id="contract-002",
                parent_task_id="task-root",
                chain_depth=1,
                ops_allowed=("delete", "admin"),
            )

    def test_parented_construction_with_wrong_parent_rejected(self):
        root = _root(ops=("read",))
        other = _root(ops=("read", "write"))
        object.__setattr__(other, "task_id", "task-other")
        with pytest.raises(ValueError, match="IDP_E_CAPABILITY_ESCALATION"):
            DelegationContext(
                intent_id="intent-p2",
                task_id="task-forged",
                delegator_id="agent-beta",
                delegatee_id="agent-gamma",
                contract_id="contract-002",
                parent_task_id="task-root",
                chain_depth=1,
                ops_allowed=("read",),
                _parent_context=other,  # task_id mismatch
            )
        with pytest.raises(ValueError, match="IDP_E_CAPABILITY_ESCALATION"):
            DelegationContext(
                intent_id="intent-p2",
                task_id="task-forged2",
                delegator_id="agent-beta",
                delegatee_id="agent-gamma",
                contract_id="contract-002",
                parent_task_id="task-root",
                chain_depth=1,
                ops_allowed=("read", "admin"),  # superset of parent
                _parent_context=root,
            )

    def test_depth_must_be_parent_plus_one(self):
        root = _root(ops=("read",))
        with pytest.raises(ValueError, match="IDP_E_DEPTH_EXCEEDED"):
            DelegationContext(
                intent_id="intent-p2",
                task_id="task-forged",
                delegator_id="agent-beta",
                delegatee_id="agent-gamma",
                contract_id="contract-002",
                parent_task_id="task-root",
                chain_depth=3,  # skips levels
                ops_allowed=("read",),
                _parent_context=root,
            )

    def test_legitimate_child_via_create_child_succeeds(self):
        root = _root(ops=("read", "write"))
        child, err = root.create_child(
            delegatee_id="agent-gamma",
            contract_id="c2",
            ops_allowed=("read",),
        )
        assert err is None
        assert child.ops_allowed == ("read",)
        assert child.parent_task_id == root.task_id

    def test_from_dict_rehydrates_parented_entries(self):
        """Logged DCTs round-trip: attenuation was enforced at write time."""
        root = _root(ops=("read", "write"))
        child, _ = root.create_child(
            delegatee_id="agent-gamma", contract_id="c2", ops_allowed=("read",)
        )
        clone = DelegationContext.from_dict(child.to_dict())
        assert clone.task_id == child.task_id
        assert clone.parent_task_id == child.parent_task_id
        assert clone.ops_allowed == child.ops_allowed


class TestT10dFrozenContexts:
    """T10d: no post-creation mutation of capability or lifecycle fields."""

    def test_ops_allowed_immutable(self):
        ctx = _root(ops=("read",))
        with pytest.raises(FrozenInstanceError):
            ctx.ops_allowed = ("admin",)

    def test_status_immutable_from_outside(self):
        ctx = _root()
        with pytest.raises(FrozenInstanceError):
            ctx.status = "VERIFIED"

    def test_budget_frozen(self):
        with pytest.raises(FrozenInstanceError):
            DelegationBudget().max_tokens = 999

    def test_state_machine_still_mutates_internally(self):
        ctx = _root()
        ok, err = ctx.transition("RUNNING")
        assert ok and err is None
        assert ctx.status == "RUNNING"


class TestT11EvidenceReadyToFailed:
    """T11: EVIDENCE_READY -> FAILED; FAILED is terminal; replan cap intact."""

    def _at_evidence_ready(self):
        ctx = _root()
        for target in ("RUNNING", "EVIDENCE_READY"):
            ok, err = ctx.transition(target)
            assert ok, f"{ctx.status}->{target}: {err}"
        return ctx

    def test_evidence_ready_to_failed_allowed(self):
        ctx = self._at_evidence_ready()
        ok, err = ctx.transition("FAILED")
        assert ok and err is None
        assert ctx.is_terminal()

    def test_failed_is_terminal(self):
        ctx = self._at_evidence_ready()
        ctx.transition("FAILED")
        for target in ("PROPOSED", "RUNNING", "VERIFIED", "REPLANNED"):
            ok, err = ctx.transition(target)
            assert not ok
            assert err == IDP_E_INVALID_STATE_TRANSITION

    def test_failed_allowed_at_replan_limit(self):
        """The T11 trap: at the replan cap, FAILED must remain reachable."""
        ctx = self._at_evidence_ready()
        for _ in range(DEFAULT_MAX_REPLANS):
            ok, err = ctx.transition("REPLANNED")
            assert ok
            ok, err = ctx.transition("PROPOSED")
            assert ok
            ok, err = ctx.transition("ISSUED")
            assert ok
            ok, err = ctx.transition("RUNNING")
            assert ok
            ok, err = ctx.transition("EVIDENCE_READY")
            assert ok
        assert ctx.replan_count == DEFAULT_MAX_REPLANS
        # Replan is exhausted...
        ok, err = ctx.transition("REPLANNED")
        assert not ok
        assert err == IDP_E_REPLAN_LIMIT
        # ...but FAILED is still reachable (was impossible in v2.1).
        ok, err = ctx.transition("FAILED")
        assert ok and err is None
        assert ctx.status == "FAILED"

    def test_verified_still_terminal(self):
        ctx = self._at_evidence_ready()
        ok, _ = ctx.transition("VERIFIED")
        assert ok
        ok, err = ctx.transition("FAILED")
        assert not ok
        assert err == IDP_E_INVALID_STATE_TRANSITION


class TestT12IntegerFloorDepth:
    """T12: fixed-point integer floor; unknown tier -> 0; one depth model."""

    def test_repro_edge_case_medium_06(self):
        """The v2.1 float floor returned 2 for 0.6/0.20; true floor is 3."""
        assert compute_dynamic_depth(0.6, "MEDIUM") == 3

    def test_unknown_tier_fails_closed(self):
        for tier in ("CRIT", "UNKNOWN", "low", "", "MEDIUM "):
            assert compute_dynamic_depth(0.99, tier) == 0, tier

    def test_grid_matches_integer_formula(self):
        """Integer-floor depth matches int(round(t*1e4))//int(round(tau*1e4))
        on a grid of (t, tau) -- the remediation-spec formula verbatim."""
        for tier, tau in _TAU_BY_RISK_TIER.items():
            scaled_tau = int(round(tau * 10_000))
            for i in range(0, 10001, 25):
                trust = i / 10_000
                expected = min(
                    DEFAULT_MAX_CHAIN_DEPTH,
                    int(round(trust * 10_000)) // scaled_tau,
                )
                assert compute_dynamic_depth(trust, tier) == expected, (
                    f"trust={trust}, tier={tier}"
                )

    def test_second_depth_model_deleted(self):
        """delegation_token.py must not carry a competing depth model."""
        import reference_impl.delegation_token as dt

        assert not hasattr(dt, "depth_bound_lookup")
        assert not hasattr(dt, "_DEPTH_BOUNDS")


class TestG5RandomDelegationTrees:
    """G5: 10,000 random delegation trees (fixed seed) never escalate ops."""

    def test_random_trees_never_escalate(self):
        rng = random.Random(20260925)
        escalations = 0
        trees = 10_000
        for _ in range(trees):
            root_ops = tuple(
                op for op in OPS_POOL if rng.random() < 0.7
            )
            mgr = DelegationContextManager()
            root = mgr.create_root(
                intent_id="i",
                delegator_id="a",
                delegatee_id="b",
                contract_id="c",
                ops_allowed=root_ops,
            )
            frontier = [root]
            depth = 0
            while frontier and depth <= DEFAULT_MAX_CHAIN_DEPTH:
                nxt = []
                for node in frontier:
                    for _ in range(rng.randint(0, 2)):
                        # Random op request: sometimes a strict subset,
                        # sometimes containing ops outside the parent set.
                        ops = tuple(
                            op for op in OPS_POOL if rng.random() < 0.4
                        )
                        child, err = node.create_child(
                            delegatee_id="x",
                            contract_id="c",
                            ops_allowed=ops,
                        )
                        if child is None:
                            # Rejection is only legitimate for escalation or
                            # depth -- never silently.
                            assert err in (
                                IDP_E_CAPABILITY_ESCALATION,
                                "IDP_E_DEPTH_EXCEEDED",
                            )
                            continue
                        assert set(child.ops_allowed).issubset(
                            set(node.ops_allowed)
                        )
                        if not set(ops).issubset(set(node.ops_allowed)):
                            escalations += 1
                        nxt.append(child)
                frontier = nxt
                depth += 1
        assert escalations == 0

    def test_attenuation_is_transitively_monotonic(self):
        """Child ops subset holds transitively: leaf ops subset of root ops."""
        rng = random.Random(7)
        for _ in range(500):
            root_ops = tuple(op for op in OPS_POOL if rng.random() < 0.8)
            node = _root(ops=root_ops)
            chain = [node]
            while node.chain_depth < DEFAULT_MAX_CHAIN_DEPTH:
                sub = tuple(
                    op for op in node.ops_allowed if rng.random() < 0.6
                )
                node, err = node.create_child(
                    delegatee_id="x", contract_id="c", ops_allowed=sub
                )
                assert node is not None
                chain.append(node)
            leaf = chain[-1]
            assert set(leaf.ops_allowed).issubset(set(root_ops))
