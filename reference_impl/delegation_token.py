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

"""Delegation Capability Token (DCT) implementation.

Implements HMAC-SHA256 signed Delegation Capability Tokens. All operations are
stdlib-only and feature-flagged behind the ENABLE_IDP environment variable.

The DCT is the cryptographic capability primitive that authorizes an agent to
act on behalf of a delegator within a bounded scope.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

logger = logging.getLogger(__name__)


def _is_idp_enabled() -> bool:
    """Check if the governance feature flag is enabled (runtime check).

    Fail-closed signature enforcement: governance validation is mandatory.
    Set ENABLE_IDP=false ONLY for emergency bypass (logs warning).
    """
    enabled = os.environ.get("ENABLE_IDP", "true").lower() == "true"
    if not enabled:
        logger.warning(
            "ENABLE_IDP=false: governance validation BYPASSED. "
            "This is an emergency-only setting and creates security risk."
        )
    return enabled


# Error codes
IDP_E_DCT_VIOLATION = "IDP_E_DCT_VIOLATION"
IDP_E_TOKEN_EXPIRED = "IDP_E_TOKEN_EXPIRED"
IDP_E_TOKEN_INVALID = "IDP_E_TOKEN_INVALID"
IDP_E_BINDING_MISMATCH = "IDP_E_BINDING_MISMATCH"
# Lateral authority enforcement
IDP_E_LATERAL_AUTH = "IDP_E_LATERAL_AUTH"
IDP_E_DECISION_AUTH = "IDP_E_DECISION_AUTH"


class LateralAuthError(ValueError):
    """Raised when an authority-class bus message is posted without a valid delegation_ref.

    See the lateral authority enforcement design in the paper.
    """

    def __init__(self, code: str, message_type: str, detail: str = "") -> None:
        self.code = code
        self.message_type = message_type
        super().__init__(f"{code}: {message_type} requires delegation_ref. {detail}".strip())


# Trust-decay depth bounds per operation class.
# tau(i+1) = tau(i) * (1 - rho) where rho is the per-hop decay rate.
_DEPTH_BOUNDS: dict[str, tuple[float, int]] = {
    "routine_analysis": (0.2, 10),
    "code_edit": (0.5, 4),
    "commit_push": (0.7, 2),
    "merge_kill_switch": (0.9, 1),
    "decision_directive": (0.9, 1),
}


def depth_bound_lookup(op_class: str, trust: float) -> int:
    """Return the maximum allowed invocation depth for an operation class at a given trust score.

    Implements the trust-decay model: invocation chains deepen only as long as
    tau remains above T_min for the operation class. At or below T_min,
    DEPTH_BOUND = 0 (no further delegation permitted regardless of configured bound).

    Args:
        op_class: Operation class key.
        trust: Current trust score tau in [0.0, 1.0].

    Returns:
        Maximum permitted invocation depth. Returns 0 if trust is at or below
        T_min for the class, or if op_class is unrecognized (fail-closed).
    """
    entry = _DEPTH_BOUNDS.get(op_class)
    if entry is None:
        return 0
    t_min, bound = entry
    return bound if trust > t_min else 0


@dataclass(frozen=True)
class ResourceSelector:
    """Resource selector for DCT specifying accessible resources."""

    resource_type: str
    resource_id: str = "*"
    constraints: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ResourceSelector:
        if not isinstance(d, dict):
            raise ValueError(f"ResourceSelector.from_dict requires dict, got {type(d).__name__}")
        if "resource_type" not in d:
            raise ValueError("ResourceSelector.from_dict missing required field 'resource_type'")
        return cls(
            resource_type=d["resource_type"],
            resource_id=d.get("resource_id", "*"),
            constraints=dict(d.get("constraints") or {}),
        )


@dataclass(frozen=True)
class Caveat:
    """Caveat constraining DCT capability use."""

    caveat_id: str
    type: Literal["TIME_BOUND", "RATE_LIMIT", "APPROVAL_REQUIRED", "AUDIT_REQUIRED"]
    parameters: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Caveat:
        if not isinstance(d, dict):
            raise ValueError(f"Caveat.from_dict requires dict, got {type(d).__name__}")
        for required in ("caveat_id", "type"):
            if required not in d:
                raise ValueError(f"Caveat.from_dict missing required field '{required}'")
        return cls(
            caveat_id=d["caveat_id"],
            type=d["type"],
            parameters=dict(d.get("parameters") or {}),
        )


@dataclass(frozen=True)
class TokenBinding:
    """Binding linking DCT to specific task and contract.

    Enforces binding invariants via task/contract/subject binding.
    """

    task_id: str
    contract_id: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TokenBinding:
        if not isinstance(d, dict):
            raise ValueError(f"TokenBinding.from_dict requires dict, got {type(d).__name__}")
        for required in ("task_id", "contract_id"):
            if required not in d:
                raise ValueError(f"TokenBinding.from_dict missing required field '{required}'")
        return cls(task_id=d["task_id"], contract_id=d["contract_id"])


@dataclass(frozen=True)
class DelegationCapabilityToken:
    """HMAC-SHA256 signed delegation capability token.

    Token is immutable after creation (frozen dataclass).

    Fields:
        token_id: Unique UUID for this token
        issuer: Agent granting the capability
        subject: Agent receiving the capability
        resource_selectors: List of accessible resource specifications
        ops_allowed: Permitted operations (e.g., "read", "write")
        caveats: Additional constraints on use
        expiry: ISO8601 timestamp or None for no expiry
        binding: Links token to specific task/contract
        signature: HMAC-SHA256 signature for integrity
    """

    token_id: str
    issuer: str
    subject: str
    resource_selectors: tuple[ResourceSelector, ...] = field(default_factory=tuple)
    ops_allowed: tuple[str, ...] = field(default_factory=tuple)
    caveats: tuple[Caveat, ...] = field(default_factory=tuple)
    expiry: str | None = None
    binding: TokenBinding | None = None
    signature: str = ""

    def to_dict(self, *, include_signature: bool = False) -> dict[str, Any]:
        """Serialize token to dictionary.

        Args:
            include_signature: If True, include the HMAC signature in the output.
                Default False for the signing path (signature is computed over
                the unsigned dict). Set True for serialization roundtrip.
        """
        d: dict[str, Any] = {
            "token_id": self.token_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "resource_selectors": [
                {
                    "resource_type": r.resource_type,
                    "resource_id": r.resource_id,
                    "constraints": r.constraints,
                }
                for r in self.resource_selectors
            ],
            "ops_allowed": list(self.ops_allowed),
            "caveats": [
                {"caveat_id": c.caveat_id, "type": c.type, "parameters": c.parameters}
                for c in self.caveats
            ],
            "expiry": self.expiry,
            "binding": (
                {
                    "task_id": self.binding.task_id,
                    "contract_id": self.binding.contract_id,
                }
                if self.binding
                else None
            ),
        }
        if include_signature:
            d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DelegationCapabilityToken:
        """Reconstruct a token from a dict (inverse of to_dict(include_signature=True)).

        Strict: raises ValueError on missing required fields. Does not validate
        the signature -- callers must validate via DelegationTokenManager.
        """
        if not isinstance(d, dict):
            raise ValueError(
                f"DelegationCapabilityToken.from_dict requires dict, got {type(d).__name__}"
            )
        for required in ("token_id", "issuer", "subject"):
            if required not in d:
                raise ValueError(
                    f"DelegationCapabilityToken.from_dict missing required field '{required}'"
                )

        selectors_raw = d.get("resource_selectors") or []
        if not isinstance(selectors_raw, list):
            raise ValueError(
                f"resource_selectors must be a list, got {type(selectors_raw).__name__}"
            )
        resource_selectors = tuple(ResourceSelector.from_dict(s) for s in selectors_raw)

        ops_raw = d.get("ops_allowed") or []
        if not isinstance(ops_raw, list):
            raise ValueError(f"ops_allowed must be a list, got {type(ops_raw).__name__}")
        ops_allowed = tuple(str(o) for o in ops_raw)

        caveats_raw = d.get("caveats") or []
        if not isinstance(caveats_raw, list):
            raise ValueError(f"caveats must be a list, got {type(caveats_raw).__name__}")
        caveats = tuple(Caveat.from_dict(c) for c in caveats_raw)

        binding_raw = d.get("binding")
        binding: TokenBinding | None = None
        if binding_raw is not None:
            binding = TokenBinding.from_dict(binding_raw)

        return cls(
            token_id=d["token_id"],
            issuer=d["issuer"],
            subject=d["subject"],
            resource_selectors=resource_selectors,
            ops_allowed=ops_allowed,
            caveats=caveats,
            expiry=d.get("expiry"),
            binding=binding,
            signature=d.get("signature", ""),
        )

    def to_json(self) -> str:
        """Serialize to compact canonical JSON (with signature)."""
        return json.dumps(
            self.to_dict(include_signature=True),
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, s: str) -> DelegationCapabilityToken:
        """Deserialize from JSON. Inverse of to_json()."""
        if not isinstance(s, str):
            raise ValueError(f"from_json requires str, got {type(s).__name__}")
        try:
            d = json.loads(s)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON: {exc}") from exc
        return cls.from_dict(d)

    def to_env_string(self) -> str:
        """Serialize to base64-urlsafe ASCII string suitable for env-var transport."""
        raw = self.to_json().encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @classmethod
    def from_env_string(cls, s: str) -> DelegationCapabilityToken:
        """Deserialize from base64-urlsafe env-var string. Inverse of to_env_string().

        Strict alphabet pre-check for tamper detection at the env-var transport layer.

        Raises:
            ValueError: Non-alphabet input, malformed base64, malformed JSON,
                or missing fields.
        """
        if not isinstance(s, str):
            raise ValueError(f"from_env_string requires str, got {type(s).__name__}")
        if not s:
            raise ValueError("Empty env-string is not a valid base64 token")
        _allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_="
        )
        first_pad = s.find("=")
        if first_pad != -1 and any(ch != "=" for ch in s[first_pad:]):
            raise ValueError("Invalid base64-urlsafe token: '=' padding only allowed at end")
        if len(s) % 4 != 0:
            raise ValueError(
                f"Invalid base64-urlsafe token: length {len(s)} is not a multiple of 4"
            )
        bad = next((ch for ch in s if ch not in _allowed), None)
        if bad is not None:
            raise ValueError(
                f"Invalid base64-urlsafe token: character {bad!r} not in URL-safe alphabet"
            )
        try:
            raw = base64.urlsafe_b64decode(s.encode("ascii"))
        except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
            raise ValueError(f"Malformed base64-urlsafe token: {exc}") from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Token bytes are not valid UTF-8: {exc}") from exc
        return cls.from_json(text)

    def verify_signature(self, secret: bytes) -> bool:
        """Verify HMAC-SHA256 signature matches token content.

        Args:
            secret: Shared secret for HMAC verification

        Returns:
            True if signature is valid, False otherwise
        """
        expected = _compute_signature(self.to_dict(), secret)
        return hmac.compare_digest(self.signature, expected)

    def is_expired(self) -> bool:
        """Check if token has expired.

        Returns:
            True if expiry is set and passed, False otherwise
        """
        if self.expiry is None:
            return False
        try:
            expiry_dt = datetime.fromisoformat(self.expiry.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) >= expiry_dt
        except (ValueError, TypeError):
            return True

    def validate_binding(self, task_id: str, contract_id: str, subject: str) -> bool:
        """Validate token is bound to expected task/contract/subject.

        Args:
            task_id: Expected task ID
            contract_id: Expected contract ID
            subject: Expected subject (delegatee) ID

        Returns:
            True if all bindings match, False otherwise
        """
        if self.binding is None:
            return False
        return (
            self.binding.task_id == task_id
            and self.binding.contract_id == contract_id
            and self.subject == subject
        )


class DelegationTokenManager:
    """Manager for creating and validating DCTs.

    Implements DCT token lifecycle with HMAC-SHA256 signing.
    All operations are feature-flagged via ENABLE_IDP.
    """

    def __init__(self, secret: bytes | None = None):
        """Initialize token manager with signing secret.

        Args:
            secret: HMAC secret. If None, reads from DCT_SECRET env var
                    or generates ephemeral key (not recommended for production).
        """
        if secret is None:
            secret_str = os.environ.get("DCT_SECRET")
            if secret_str:
                secret = secret_str.encode("utf-8")
            else:
                logger.warning(
                    "DCT_SECRET not set, using ephemeral key. "
                    "Tokens will be invalid after process restart."
                )
                secret = os.urandom(32)
        self._secret = secret

    def create_token(
        self,
        issuer: str,
        subject: str,
        ops_allowed: list[str],
        binding: TokenBinding,
        resource_selectors: list[ResourceSelector] | None = None,
        caveats: list[Caveat] | None = None,
        expiry_minutes: int | None = 120,
    ) -> DelegationCapabilityToken:
        """Create a new HMAC-SHA256 signed DCT.

        Args:
            issuer: Agent granting the capability
            subject: Agent receiving the capability
            ops_allowed: List of permitted operations
            binding: Task/contract binding for the token
            resource_selectors: Accessible resources (default: all)
            caveats: Constraints on use (default: none)
            expiry_minutes: Minutes until expiry (None = no expiry, default: 120)

        Returns:
            Signed DelegationCapabilityToken

        Raises:
            RuntimeError: If ENABLE_IDP is False
        """
        if not _is_idp_enabled():
            raise RuntimeError("Governance is disabled. Set ENABLE_IDP=true to create tokens.")

        expiry = None
        if expiry_minutes is not None:
            expiry_dt = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
            expiry = expiry_dt.isoformat().replace("+00:00", "Z")

        token = DelegationCapabilityToken(
            token_id=str(uuid.uuid4()),
            issuer=issuer,
            subject=subject,
            resource_selectors=tuple(resource_selectors or []),
            ops_allowed=tuple(ops_allowed),
            caveats=tuple(caveats or []),
            expiry=expiry,
            binding=binding,
            signature="",
        )

        sig = _compute_signature(token.to_dict(), self._secret)

        return DelegationCapabilityToken(
            token_id=token.token_id,
            issuer=token.issuer,
            subject=token.subject,
            resource_selectors=token.resource_selectors,
            ops_allowed=token.ops_allowed,
            caveats=token.caveats,
            expiry=token.expiry,
            binding=token.binding,
            signature=sig,
        )

    def validate_token(
        self,
        token: DelegationCapabilityToken,
        expected_task_id: str | None = None,
        expected_contract_id: str | None = None,
        expected_subject: str | None = None,
    ) -> tuple[bool, str | None]:
        """Validate a DCT for use.

        Performs signature verification, expiry check, and optional binding validation.

        Args:
            token: The DCT to validate
            expected_task_id: If provided, validate binding to this task
            expected_contract_id: If provided, validate binding to this contract
            expected_subject: If provided, validate token subject matches

        Returns:
            Tuple of (is_valid, error_code). Error codes:
            - IDP_E_TOKEN_INVALID: Signature verification failed
            - IDP_E_TOKEN_EXPIRED: Token has expired
            - IDP_E_BINDING_MISMATCH: Task/contract/subject binding mismatch
        """
        if not _is_idp_enabled():
            return True, None

        if not token.verify_signature(self._secret):
            return False, IDP_E_TOKEN_INVALID

        if token.is_expired():
            return False, IDP_E_TOKEN_EXPIRED

        if expected_task_id or expected_contract_id or expected_subject:
            task_id = expected_task_id if expected_task_id else (token.binding.task_id if token.binding else "")
            contract_id = expected_contract_id if expected_contract_id else (token.binding.contract_id if token.binding else "")
            subject = expected_subject or token.subject

            if not token.validate_binding(task_id, contract_id, subject):
                return False, IDP_E_BINDING_MISMATCH

        return True, None

    def validate_env_token(
        self,
        env_string: str,
        expected_task_id: str | None = None,
        expected_contract_id: str | None = None,
        expected_subject: str | None = None,
    ) -> tuple[bool, str | None, DelegationCapabilityToken | None]:
        """Validate a token serialized as a base64-urlsafe env-var string.

        Returns the token object as the third element on success.

        Args:
            env_string: Base64-urlsafe-encoded token (per to_env_string()).
            expected_task_id: Optional binding check.
            expected_contract_id: Optional binding check.
            expected_subject: Optional binding check.

        Returns:
            Tuple of (is_valid, error_code, token). On success: (True, None, token).
            On any failure: (False, error_code, None).
        """
        if not _is_idp_enabled():
            try:
                token = DelegationCapabilityToken.from_env_string(env_string)
                return True, None, token
            except ValueError:
                return True, None, None

        try:
            token = DelegationCapabilityToken.from_env_string(env_string)
        except ValueError:
            return False, IDP_E_TOKEN_INVALID, None

        is_valid, error = self.validate_token(
            token,
            expected_task_id=expected_task_id,
            expected_contract_id=expected_contract_id,
            expected_subject=expected_subject,
        )
        if not is_valid:
            return False, error, None
        return True, None, token

    def check_least_privilege(
        self,
        token: DelegationCapabilityToken,
        requested_op: str,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        """Check if requested operation complies with Least Privilege.

        Args:
            token: The DCT authorizing the operation
            requested_op: Operation being requested (e.g., "write_file")
            allowed_tools: Contract's allowed_tools list (None = any allowed)
            denied_tools: Contract's denied_tools list (None = none denied)

        Returns:
            Tuple of (is_allowed, error_code). Error codes:
            - IDP_E_DCT_VIOLATION: Operation not in ops_allowed or violates constraints
        """
        if not _is_idp_enabled():
            return True, None

        if requested_op not in token.ops_allowed:
            return False, IDP_E_DCT_VIOLATION

        if allowed_tools is not None and requested_op not in allowed_tools:
            return False, IDP_E_DCT_VIOLATION

        if denied_tools is not None and requested_op in denied_tools:
            return False, IDP_E_DCT_VIOLATION

        return True, None


def _compute_signature(data: dict[str, Any], secret: bytes) -> str:
    """Compute HMAC-SHA256 signature for token data.

    Args:
        data: Token dictionary (excluding signature field)
        secret: HMAC secret key

    Returns:
        Hex-encoded HMAC-SHA256 signature
    """
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# Module-level singleton for convenience
_default_manager: DelegationTokenManager | None = None
_default_manager_lock = threading.Lock()


def get_token_manager() -> DelegationTokenManager:
    """Get default token manager instance."""
    global _default_manager
    if _default_manager is None:
        with _default_manager_lock:
            if _default_manager is None:
                _default_manager = DelegationTokenManager()
    return _default_manager
