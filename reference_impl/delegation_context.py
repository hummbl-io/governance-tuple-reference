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

"""Delegation Context (DCTX) implementation.

Implements the Delegation Context tuple with chain depth tracking,
state machine enforcement, and dynamic trust-decay depth computation.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


def _is_idp_enabled() -> bool:
    """Check if the governance feature flag is enabled (runtime check)."""
    return os.environ.get("ENABLE_IDP", "true").lower() == "true"


# Error codes
IDP_E_DEPTH_EXCEEDED = "IDP_E_DEPTH_EXCEEDED"
IDP_E_INVALID_STATE_TRANSITION = "IDP_E_INVALID_STATE_TRANSITION"
IDP_E_REPLAN_LIMIT = "IDP_E_REPLAN_LIMIT"
IDP_E_CAPABILITY_ESCALATION = "IDP_E_CAPABILITY_ESCALATION"
IDP_E_TRUST_DEPTH_EXCEEDED = "IDP_E_TRUST_DEPTH_EXCEEDED"

# Default constants
DEFAULT_MAX_CHAIN_DEPTH = 3
DEFAULT_MAX_REPLANS = 2

# Trust-decay depth thresholds per risk tier (matches paper formula)
# delta_effective(o, t) = min(delta_max, floor(t_score / tau_o))
_TAU_BY_RISK_TIER: dict[str, float] = {
    "LOW": 0.15,
    "MEDIUM": 0.20,
    "HIGH": 0.25,
    "CRITICAL": 0.40,
}


def compute_dynamic_depth(
    trust_score: float, risk_tier: str, delta_max: int = DEFAULT_MAX_CHAIN_DEPTH
) -> int:
    """Compute effective delegation depth using trust-decay model.

    Implements the paper formula: delta_effective = min(delta_max, floor(t_score / tau_o))

    F5: the floor is computed in fixed-point integers
    (int(round(t*10000)) // int(round(tau*10000))) -- never float floor or
    round(t/tau), which are fail-open on binary representation edges.
    Unknown risk tiers return 0 (fail-closed; the v2.1 LOW fallback was
    fail-open).

    Args:
        trust_score: Beta trust score tau in [0.0, 1.0]
        risk_tier: One of LOW, MEDIUM, HIGH, CRITICAL
        delta_max: Hard ceiling (default 3)

    Returns:
        Maximum permitted chain depth for this delegatee and operation class.
    """
    tau = _TAU_BY_RISK_TIER.get(risk_tier)
    if tau is None:
        return 0  # unknown tier -> no delegation depth (fail-closed)
    scaled_t = int(round(trust_score * 10_000))
    scaled_tau = int(round(tau * 10_000))
    return min(delta_max, scaled_t // scaled_tau)


DCTXStatus = Literal[
    "PROPOSED",
    "ISSUED",
    "RUNNING",
    "EVIDENCE_READY",
    "VERIFIED",
    "REPLANNED",
    "FAILED",
]


@dataclass(frozen=True)
class DelegationBudget:
    """Budget constraints for delegation."""

    max_tokens: int = 0
    max_cost_usd: float = 0.0
    max_wall_time_seconds: int = 0

    def is_exceeded(self, tokens: int = 0, cost: float = 0.0, seconds: int = 0) -> bool:
        """Check if current usage exceeds budget."""
        if self.max_tokens > 0 and tokens > self.max_tokens:
            return True
        if self.max_cost_usd > 0.0 and cost > self.max_cost_usd:
            return True
        return bool(self.max_wall_time_seconds > 0 and seconds > self.max_wall_time_seconds)


@dataclass(frozen=True)
class DelegationContext:
    """Delegation Context Tuple (DCTX).

    Frozen (F5/T10d): no field may be rebound after construction; the state
    machine mutates status/replan_count internally via object.__setattr__.

    Represents the full context of a single delegation event with
    chain depth tracking and state machine enforcement.

    Fields:
        intent_id: Root intent identifier (shared across delegation tree)
        task_id: Unique identifier for this specific task
        parent_task_id: Reference to parent task (null for root)
        delegator_id: Agent issuing the delegation
        delegatee_id: Agent receiving the delegation
        contract_id: Reference to CONTRACT tuple
        verification_id: Reference to ATTEST tuple (null until verified)
        capability_token_id: Reference to DCT tuple
        risk_tier: Risk classification (LOW/MEDIUM/HIGH/CRITICAL)
        chain_depth: Number of subdelegation levels (0 = root)
        budget: Resource constraints
        status: Current delegation state
        created_at: ISO8601 timestamp
        replan_count: Number of replans executed
        metadata: Additional context data
    """

    intent_id: str
    task_id: str
    delegator_id: str
    delegatee_id: str
    contract_id: str
    parent_task_id: str | None = None
    verification_id: str | None = None
    capability_token_id: str | None = None
    risk_tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    chain_depth: int = 0
    budget: DelegationBudget = field(default_factory=DelegationBudget)
    status: DCTXStatus = "PROPOSED"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    replan_count: int = 0
    ops_allowed: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    # Construction provenance (F5/T10c). _parent_context is supplied only by
    # create_child; _rehydrate marks a log-deserialized entry whose
    # attenuation was already enforced at write time. Neither is serialized.
    _parent_context: "DelegationContext | None" = field(
        default=None, repr=False, compare=False
    )
    _rehydrate: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self):
        """Validate invariants after initialization."""
        if _is_idp_enabled():
            if self.chain_depth > DEFAULT_MAX_CHAIN_DEPTH:
                raise ValueError(
                    f"IDP_E_DEPTH_EXCEEDED: chain_depth {self.chain_depth} > max {DEFAULT_MAX_CHAIN_DEPTH}"
                )
            if self.parent_task_id is not None and self.chain_depth == 0:
                raise ValueError("Non-root task must have chain_depth > 0")
            if self.parent_task_id is None and self.chain_depth != 0:
                raise ValueError("Root task must have chain_depth = 0")
            if self.parent_task_id is not None and not self._rehydrate:
                # F5/T10c: a parented context must carry its parent so the
                # attenuation invariant can be checked at construction.
                parent = self._parent_context
                if parent is None:
                    raise ValueError(
                        "IDP_E_CAPABILITY_ESCALATION: parented contexts must "
                        "be created via create_child (or _rehydrate=True for "
                        "log deserialization)"
                    )
                if parent.task_id != self.parent_task_id:
                    raise ValueError(
                        "IDP_E_CAPABILITY_ESCALATION: _parent_context.task_id "
                        "does not match parent_task_id"
                    )
                if parent.intent_id != self.intent_id:
                    raise ValueError(
                        "IDP_E_CAPABILITY_ESCALATION: child intent_id must "
                        "match parent intent_id"
                    )
                if self.chain_depth != parent.chain_depth + 1:
                    raise ValueError(
                        "IDP_E_DEPTH_EXCEEDED: child chain_depth must be "
                        "parent.chain_depth + 1"
                    )
                if not set(self.ops_allowed).issubset(set(parent.ops_allowed)):
                    raise ValueError(
                        "IDP_E_CAPABILITY_ESCALATION: child ops_allowed must "
                        "be a subset of parent ops_allowed"
                    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "intent_id": self.intent_id,
            "task_id": self.task_id,
            "parent_task_id": self.parent_task_id,
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "contract_id": self.contract_id,
            "verification_id": self.verification_id,
            "capability_token_id": self.capability_token_id,
            "risk_tier": self.risk_tier,
            "chain_depth": self.chain_depth,
            "budget": {
                "max_tokens": self.budget.max_tokens,
                "max_cost_usd": self.budget.max_cost_usd,
                "max_wall_time_seconds": self.budget.max_wall_time_seconds,
            },
            "status": self.status,
            "created_at": self.created_at,
            "replan_count": self.replan_count,
            "ops_allowed": list(self.ops_allowed),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DelegationContext:
        """Deserialize from dictionary."""
        budget_data = data.get("budget", {})
        budget = DelegationBudget(
            max_tokens=budget_data.get("max_tokens", 0),
            max_cost_usd=budget_data.get("max_cost_usd", 0.0),
            max_wall_time_seconds=budget_data.get("max_wall_time_seconds", 0),
        )
        return cls(
            intent_id=data["intent_id"],
            task_id=data["task_id"],
            delegator_id=data["delegator_id"],
            delegatee_id=data["delegatee_id"],
            contract_id=data["contract_id"],
            parent_task_id=data.get("parent_task_id"),
            verification_id=data.get("verification_id"),
            capability_token_id=data.get("capability_token_id"),
            risk_tier=data.get("risk_tier", "MEDIUM"),
            chain_depth=data.get("chain_depth", 0),
            budget=budget,
            status=data.get("status", "PROPOSED"),
            created_at=data.get("created_at"),
            replan_count=data.get("replan_count", 0),
            ops_allowed=tuple(data.get("ops_allowed", ())),
            metadata=data.get("metadata", {}),
            # Log-deserialized entries were attenuation-checked when created;
            # the verifier re-checks ops subsets at read time (F6).
            _rehydrate=True,
        )

    def transition(self, new_status: DCTXStatus) -> tuple[bool, str | None]:
        """Execute state machine transition.

        Valid transitions:
        PROPOSED -> ISSUED
        ISSUED -> RUNNING
        RUNNING -> EVIDENCE_READY
        EVIDENCE_READY -> VERIFIED
        EVIDENCE_READY -> REPLANNED
        REPLANNED -> PROPOSED (with replan_count check)
        REPLANNED -> FAILED
        ISSUED -> FAILED
        RUNNING -> FAILED

        Args:
            new_status: Target state

        Returns:
            Tuple of (success, error_code)
        """
        if not _is_idp_enabled():
            self.status = new_status
            return True, None

        valid_transitions: dict[DCTXStatus, list[DCTXStatus]] = {
            "PROPOSED": ["ISSUED"],
            "ISSUED": ["RUNNING", "FAILED"],
            "RUNNING": ["EVIDENCE_READY", "FAILED"],
            "EVIDENCE_READY": ["VERIFIED", "REPLANNED", "FAILED"],
            "REPLANNED": ["PROPOSED", "FAILED"],
            "VERIFIED": [],
            "FAILED": [],
        }

        allowed = valid_transitions.get(self.status, [])
        if new_status not in allowed:
            return False, IDP_E_INVALID_STATE_TRANSITION

        if self.status == "EVIDENCE_READY" and new_status == "REPLANNED":
            if self.replan_count >= DEFAULT_MAX_REPLANS:
                return False, IDP_E_REPLAN_LIMIT

        # Frozen dataclass: internal state-machine fields mutate via
        # object.__setattr__; external rebinding raises FrozenInstanceError.
        if new_status == "REPLANNED":
            object.__setattr__(self, "replan_count", self.replan_count + 1)

        object.__setattr__(self, "status", new_status)
        return True, None

    def can_subdelegate(
        self, max_depth: int = DEFAULT_MAX_CHAIN_DEPTH
    ) -> tuple[bool, str | None]:
        """Check if this task can be subdelegated (bounded chain depth).

        Args:
            max_depth: Maximum allowed chain depth

        Returns:
            Tuple of (can_subdelegate, error_code)
        """
        if not _is_idp_enabled():
            return True, None

        if self.chain_depth + 1 > max_depth:
            return False, IDP_E_DEPTH_EXCEEDED
        return True, None

    def create_child(
        self,
        delegatee_id: str,
        contract_id: str,
        risk_tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
        budget: DelegationBudget | None = None,
        ops_allowed: tuple[str, ...] | None = None,
        trust_score: float | None = None,
    ) -> tuple[DelegationContext | None, str | None]:
        """Create child delegation context (subdelegation).

        Enforces monotonic capability attenuation and bounded chain depth.
        When trust_score is provided, uses dynamic trust-decay depth model;
        otherwise falls back to static DEFAULT_MAX_CHAIN_DEPTH.

        Args:
            delegatee_id: Agent receiving subdelegation
            contract_id: Contract for child task
            risk_tier: Child risk tier (default: same as parent)
            budget: Child budget (default: same as parent)
            ops_allowed: Child operations (must be subset of parent's; default: same as parent)
            trust_score: Optional Beta trust score tau in [0.0, 1.0].

        Returns:
            Tuple of (child_context, error_code). Error codes:
            - IDP_E_DEPTH_EXCEEDED: Would exceed static max chain depth
            - IDP_E_TRUST_DEPTH_EXCEEDED: Would exceed dynamic trust-decay depth
            - IDP_E_CAPABILITY_ESCALATION: Child ops not subset of parent ops
        """
        if not _is_idp_enabled():
            return None, None

        resolved_risk = risk_tier or self.risk_tier
        if trust_score is not None:
            dynamic_max = compute_dynamic_depth(trust_score, resolved_risk)
            if self.chain_depth + 1 > dynamic_max:
                return None, IDP_E_TRUST_DEPTH_EXCEEDED
        else:
            can_sub, error = self.can_subdelegate()
            if not can_sub:
                return None, error

        # Monotonic capability attenuation (F5/T10b): child ops must be a
        # subset of parent ops, unconditionally. The v2.1 guard
        # `if self.ops_allowed and child_ops` skipped the check whenever
        # either side was empty -- `read -> () -> delete,admin` escalated.
        # The empty set grants no operations: () permits only () children.
        child_ops = ops_allowed if ops_allowed is not None else self.ops_allowed
        if not set(child_ops).issubset(set(self.ops_allowed)):
            return None, IDP_E_CAPABILITY_ESCALATION

        return (
            DelegationContext(
                intent_id=self.intent_id,
                task_id=str(uuid.uuid4()),
                parent_task_id=self.task_id,
                delegator_id=self.delegatee_id,
                delegatee_id=delegatee_id,
                contract_id=contract_id,
                risk_tier=risk_tier or self.risk_tier,
                chain_depth=self.chain_depth + 1,
                budget=budget
                or DelegationBudget(
                    max_tokens=self.budget.max_tokens,
                    max_cost_usd=self.budget.max_cost_usd,
                    max_wall_time_seconds=self.budget.max_wall_time_seconds,
                ),
                ops_allowed=child_ops,
                status="PROPOSED",
                _parent_context=self,
            ),
            None,
        )

    def is_terminal(self) -> bool:
        """Check if task is in terminal state."""
        return self.status in ("VERIFIED", "FAILED")

    def is_active(self) -> bool:
        """Check if task is actively running."""
        return self.status in ("ISSUED", "RUNNING")


class DelegationContextManager:
    """Manager for DCTX lifecycle operations.

    Tracks active delegations and enforces invariants.
    """

    def __init__(self, max_depth: int = DEFAULT_MAX_CHAIN_DEPTH):
        """Initialize context manager.

        Args:
            max_depth: Maximum delegation chain depth (default: 3)
        """
        self._max_depth = max_depth
        self._contexts: dict[str, DelegationContext] = {}

    def create_root(
        self,
        intent_id: str,
        delegator_id: str,
        delegatee_id: str,
        contract_id: str,
        ops_allowed: tuple[str, ...] = (),
        risk_tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM",
        budget: DelegationBudget | None = None,
    ) -> DelegationContext:
        """Create root delegation context (chain_depth = 0).

        F5/T10a: the root's ops_allowed is the delegator's granted op set --
        the attenuation baseline every descendant must subset. The empty
        set grants no operations: children of an empty-ops root can only
        carry () themselves.

        Args:
            intent_id: Root intent identifier
            delegator_id: Agent issuing delegation
            delegatee_id: Agent receiving delegation
            contract_id: Contract ID
            ops_allowed: Operations granted at the root (default () --
                explicit but grants nothing; pass the delegator's op set
                for delegation to be meaningful)
            risk_tier: Risk classification
            budget: Resource constraints

        Returns:
            New root DelegationContext
        """
        ctx = DelegationContext(
            intent_id=intent_id,
            task_id=str(uuid.uuid4()),
            delegator_id=delegator_id,
            delegatee_id=delegatee_id,
            contract_id=contract_id,
            risk_tier=risk_tier,
            chain_depth=0,
            budget=budget or DelegationBudget(),
            status="PROPOSED",
            ops_allowed=tuple(ops_allowed),
        )
        self._contexts[ctx.task_id] = ctx
        return ctx

    def get_context(self, task_id: str) -> DelegationContext | None:
        """Get context by task ID."""
        return self._contexts.get(task_id)

    def get_by_intent(self, intent_id: str) -> list[DelegationContext]:
        """Get all contexts for an intent."""
        return [ctx for ctx in self._contexts.values() if ctx.intent_id == intent_id]

    def get_chain(self, task_id: str) -> list[DelegationContext]:
        """Get full delegation chain from root to task."""
        chain = []
        current = self._contexts.get(task_id)
        while current:
            chain.append(current)
            if current.parent_task_id is None:
                break
            current = self._contexts.get(current.parent_task_id)
        return list(reversed(chain))
