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

"""Complete Governance Tuple verification -- F6 (def:gt-valid).

verify_tuple decides all 8 conditions of a valid (C, D, E) tuple:

  1. D verifies under K_I (issuer signature).
  2. D.contract_id = C.id.
  3. D.contract_digest = H(canon(C)).
  4. D.issued_at <= E.t_start and E.t_end < D.expiry -- times are taken
     from E; datetime.now() is never consulted (the v2.1 audit-clock bug
     invalidated every tuple older than 120 minutes at audit time).
  5. D.ops subset of C.ops and E.ops subset of D.ops.
  6. D.sel is no broader than C.sel, and D matches every resource in E.res.
  7. E.actor = D.subject and E.task_id = D.task_id.
  8. E carries a valid tag from the writer W or an observer O.

Contract shape: dict with "contract_id", "ops_allowed" (list), and
optional "resource_selectors" (list of {resource_type, resource_id,
constraints}). Evidence shape: a GovernanceEntry whose tuple_data carries
{actor, task_id, ops_executed, resources_accessed, t_start, t_end}, or a
plain dict with those fields plus "signature" (writer tag over the
canonical dict) or "observer_tag" (observer-MACed, verified under K_O).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

from reference_impl.delegation_token import (
    DelegationCapabilityToken,
    ResourceSelector,
    _canonical_json,
    compute_contract_digest,
)

# Error codes (one per violated condition -- G1 requires individual rejection)
IDP_E_TUPLE_SIGNATURE = "IDP_E_TUPLE_SIGNATURE"          # 1
IDP_E_TUPLE_CONTRACT_ID = "IDP_E_TUPLE_CONTRACT_ID"      # 2
IDP_E_TUPLE_CONTRACT_DIGEST = "IDP_E_TUPLE_CONTRACT_DIGEST"  # 3
IDP_E_TUPLE_TIME_WINDOW = "IDP_E_TUPLE_TIME_WINDOW"      # 4
IDP_E_TUPLE_OPS_EXCEED_CONTRACT = "IDP_E_TUPLE_OPS_EXCEED_CONTRACT"  # 5a
IDP_E_TUPLE_OPS_EXCEED_TOKEN = "IDP_E_TUPLE_OPS_EXCEED_TOKEN"        # 5b
IDP_E_TUPLE_SELECTOR_EXCEEDED = "IDP_E_TUPLE_SELECTOR_EXCEEDED"      # 6
IDP_E_TUPLE_ACTOR_MISMATCH = "IDP_E_TUPLE_ACTOR_MISMATCH"            # 7
IDP_E_TUPLE_EVIDENCE_TAG = "IDP_E_TUPLE_EVIDENCE_TAG"                # 8


def _parse_iso(value: str | None) -> datetime | None:
    """Parse an ISO8601 timestamp; None/invalid -> None."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _selector_covers(
    contract_selectors: list[dict[str, Any]],
    token_selectors: tuple[ResourceSelector, ...],
) -> bool:
    """Condition 6a: every token selector must be covered by a contract
    selector (token selectors are no broader than the contract's).

    Coverage: same resource_type AND (contract resource_id == "*" or equal)
    AND contract constraints are all present in the token's constraints
    (the token may constrain further but never loosen).
    Wildcard handling: a token with no selectors means wildcard-any, which
    only an empty/wildcard contract covers.
    """
    token_is_wild = not token_selectors
    contract_is_wild = not contract_selectors
    if token_is_wild:
        return contract_is_wild
    for tsel in token_selectors:
        covered = False
        for csel in contract_selectors:
            if csel.get("resource_type") != tsel.resource_type:
                continue
            c_rid = csel.get("resource_id", "*")
            if c_rid != "*" and c_rid != tsel.resource_id:
                continue
            c_cons = csel.get("constraints") or {}
            if all(tsel.constraints.get(k) == v for k, v in c_cons.items()):
                covered = True
                break
        if not covered:
            return False
    return True


def _selector_matches_resource(
    token_selectors: tuple[ResourceSelector, ...], resource: dict[str, Any]
) -> bool:
    """Condition 6b: a token selector matches an accessed resource."""
    rtype = resource.get("resource_type")
    rid = resource.get("resource_id")
    if not token_selectors:  # empty selector set = wildcard-any (v2.1 default)
        return True
    for sel in token_selectors:
        if sel.resource_type != rtype:
            continue
        if sel.resource_id == "*" or sel.resource_id == rid:
            return True
    return False


def _evidence_fields(evidence: Any) -> dict[str, Any]:
    """Normalize evidence into the field dict + tag + tag payload."""
    # GovernanceEntry: tag is entry.signature over entry._tag_payload()
    if hasattr(evidence, "_tag_payload") and hasattr(evidence, "tuple_data"):
        return {
            "fields": evidence.tuple_data,
            "tag": getattr(evidence, "signature", None),
            "payload": evidence._tag_payload(),
        }
    # Plain dict: "signature" or "observer_tag" over canon(dict sans tag keys)
    if isinstance(evidence, dict):
        fields = {k: v for k, v in evidence.items()
                  if k not in ("signature", "observer_tag")}
        tag = evidence.get("signature") or evidence.get("observer_tag")
        return {"fields": fields, "tag": tag,
                "payload": _canonical_json(fields)}
    return {"fields": {}, "tag": None, "payload": b""}


def verify_tuple(
    contract: dict[str, Any],
    token: DelegationCapabilityToken,
    evidence: Any,
    issuer_secret: bytes,
    writer_key: bytes | None = None,
    observer_key: bytes | None = None,
) -> tuple[bool, str | None]:
    """Verify a complete (C, D, E) governance tuple -- all 8 conditions.

    Args:
        contract: Contract dict; must contain contract_id and ops_allowed.
        token: The DCT (D).
        evidence: EVIDENCE entry (E) -- GovernanceEntry or dict.
        issuer_secret: K_I, the issuer's HMAC key (condition 1).
        writer_key: K_W, the bus writer's tag key (condition 8, W path).
        observer_key: K_O, an observer's tag key (condition 8, O path).

    Returns:
        (True, None) if all conditions hold, else (False, error_code).
    """
    # 1. D verifies under K_I
    if not token.verify_signature(issuer_secret):
        return False, IDP_E_TUPLE_SIGNATURE

    # 2. D.contract_id = C.id
    contract_id = contract.get("contract_id")
    bound = token.binding.contract_id if token.binding else None
    if not contract_id or bound != contract_id:
        return False, IDP_E_TUPLE_CONTRACT_ID

    # 3. D.contract_digest = H(canon(C))
    if not token.contract_digest or token.contract_digest != compute_contract_digest(contract):
        return False, IDP_E_TUPLE_CONTRACT_DIGEST

    ev = _evidence_fields(evidence)
    fields = ev["fields"]

    # 4. D.issued_at <= E.t_start and E.t_end < D.expiry (times from E)
    issued_at = _parse_iso(token.issued_at)
    t_start = _parse_iso(fields.get("t_start"))
    t_end = _parse_iso(fields.get("t_end"))
    if issued_at is None or t_start is None or t_end is None:
        return False, IDP_E_TUPLE_TIME_WINDOW
    if not (issued_at <= t_start):
        return False, IDP_E_TUPLE_TIME_WINDOW
    expiry = _parse_iso(token.expiry)
    if expiry is not None and not (t_end < expiry):
        return False, IDP_E_TUPLE_TIME_WINDOW

    # 5. D.ops subset of C.ops and E.ops subset of D.ops
    c_ops = set(contract.get("ops_allowed") or [])
    if not set(token.ops_allowed).issubset(c_ops):
        return False, IDP_E_TUPLE_OPS_EXCEED_CONTRACT
    e_ops = set(fields.get("ops_executed") or [])
    if not e_ops.issubset(set(token.ops_allowed)):
        return False, IDP_E_TUPLE_OPS_EXCEED_TOKEN

    # 6. D.sel no broader than C.sel; D matches every resource in E.res
    c_sels = contract.get("resource_selectors") or []
    if not _selector_covers(c_sels, token.resource_selectors):
        return False, IDP_E_TUPLE_SELECTOR_EXCEEDED
    for res in fields.get("resources_accessed") or []:
        if not _selector_matches_resource(token.resource_selectors, res):
            return False, IDP_E_TUPLE_SELECTOR_EXCEEDED

    # 7. E.actor = D.subject and E.task_id = D.task_id
    if fields.get("actor") != token.subject:
        return False, IDP_E_TUPLE_ACTOR_MISMATCH
    bound_task = token.binding.task_id if token.binding else None
    if fields.get("task_id") != bound_task:
        return False, IDP_E_TUPLE_ACTOR_MISMATCH

    # 8. E carries a valid tag from W or observer O
    tag = ev["tag"]
    payload = ev["payload"]
    tagged = False
    for key in (writer_key, observer_key):
        if key is None or not tag:
            continue
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(tag), expected):
            tagged = True
            break
    if not tagged:
        return False, IDP_E_TUPLE_EVIDENCE_TAG

    return True, None
