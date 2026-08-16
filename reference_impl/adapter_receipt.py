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

"""AdapterReceipt -- per-inference governance proof.

Emitted by every certified adapter on each AI inference call.
The receipt is the compliance artifact: a cryptographically signed,
append-only record proving that the inference was made under a governed
contract, with known risk classification, delegation authority, and outcome.

Compliance crosswalk (per receipt):
  ISO 42001 6.2, 8.4, 9.1 -- AI management system objectives and monitoring
  EU AI Act Art. 12       -- logging and record-keeping for high-risk AI
  NIST AI RMF MAP 1.1 / MEASURE 2.5 / GOVERN 1.1
  SOC 2 CC7.1, CC7.2      -- threat detection and anomaly response
  HIPAA 164.312(b)        -- audit controls for PHI systems
  DORA Art. 10            -- ICT risk monitoring and reporting
  SR 11-7 Model Inventory -- OCC/Fed model risk management
  CMMC AU.2.042           -- audit event capture

Design:
  - Pure stdlib (hashlib, hmac, json, os, uuid, datetime, pathlib)
  - No third-party dependencies
  - Append-only writes
  - Signs over canonical JSON via HMAC-SHA256 using BUS_SIGNING_SECRET
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_COMPLIANCE_CROSSWALK: dict[str, Any] = {
    "iso_42001": {
        "clauses": ["6.2", "8.4", "9.1"],
        "evidence": "model_id, model_version, risk_classification, contract_id, timestamp_utc",
    },
    "eu_ai_act": {
        "articles": ["Art.12"],
        "risk_category": None,
    },
    "nist_ai_rmf": {
        "functions": ["GOVERN", "MAP", "MEASURE"],
        "subcategories": ["MAP 1.1", "MEASURE 2.5", "GOVERN 1.1"],
    },
    "soc2": {
        "criteria": ["CC7.1", "CC7.2"],
    },
    "hipaa": {
        "sections": ["164.312(b)"],
        "phi_processed": None,
    },
    "dora": {
        "articles": ["Art.10"],
    },
    "sr_11_7": {
        "sections": ["Model Inventory", "Ongoing Monitoring"],
    },
    "cmmc": {
        "practices": ["AU.2.042"],
        "level": 2,
    },
}

RECEIPT_VERSION = "1.0"

VALID_RISK_CLASSIFICATIONS = frozenset({"low", "medium", "high", "critical"})
VALID_OUTCOMES = frozenset({"approved", "flagged", "rejected", "routed"})


def _utc_now() -> str:
    """Return current UTC timestamp in ISO 8601 Z format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 of raw bytes. Returns 'sha256:<64 hex chars>'."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _sha256_text(text: str) -> str:
    """Compute SHA-256 of UTF-8 encoded text. Returns 'sha256:<64 hex chars>'."""
    return _sha256_bytes(text.encode("utf-8"))


def _sha256_obj(obj: Any) -> str:
    """Compute SHA-256 of canonical JSON of an object."""
    return _sha256_text(json.dumps(obj, sort_keys=True, separators=(",", ":")))


def _canonical_json(obj: dict[str, Any], exclude_key: str | None = None) -> str:
    """Serialize dict to canonical JSON (sorted keys, no extra whitespace).

    Optionally excludes one top-level key (used to hash receipt sans
    cryptographic_commitment).
    """
    if exclude_key is not None:
        obj = {k: v for k, v in obj.items() if k != exclude_key}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _hmac_sign(message: str, secret: str) -> str:
    """HMAC-SHA256 hex-digest of message using secret."""
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _hmac_verify(message: str, signature: str, secret: str) -> bool:
    """Constant-time HMAC-SHA256 verification."""
    expected = _hmac_sign(message, secret)
    return hmac.compare_digest(expected, signature)


def _validate_hash_field(value: str, field: str) -> None:
    """Raise ValueError if value is not a valid sha256:<hex> string."""
    if not (value.startswith("sha256:") and len(value) == 71 and
            all(c in "0123456789abcdef" for c in value[7:])):
        raise ValueError(
            f"{field} must be 'sha256:<64 hex chars>', got: {value!r}"
        )


def _validate_semver(value: str, field: str) -> None:
    """Raise ValueError if value does not match x.y.z[-pre] pattern."""
    parts = value.split("-", 1)
    core = parts[0].split(".")
    if len(core) != 3 or not all(p.isdigit() for p in core):
        raise ValueError(
            f"{field} must be semantic version (x.y.z[-pre]), got: {value!r}"
        )


class AdapterReceipt:
    """AdapterReceipt v1.0 -- per-inference governance proof.

    Each certified adapter instantiates one AdapterReceipt and calls generate()
    once per inference event. The receipt handles hashing, signing, and
    append-only storage.

    Signing secret:
        Pass signing_secret to __init__, or set the BUS_SIGNING_SECRET
        environment variable. If neither is set, receipts are generated
        without a cryptographic signature (signature field absent).
        Unsigned receipts are valid for internal use but insufficient
        for external audit claims.
    """

    def __init__(
        self,
        adapter_id: str,
        adapter_version: str,
        signing_secret: str | None = None,
        signing_key_id: str = "v1",
    ) -> None:
        """Initialize the receipt writer for a specific adapter.

        Args:
            adapter_id: Stable identifier for the adapter.
            adapter_version: Semver string (e.g., '1.0.0').
            signing_secret: HMAC-SHA256 signing key. Falls back to the
                BUS_SIGNING_SECRET environment variable. If absent,
                receipts are generated unsigned.
            signing_key_id: Key rotation identifier (default 'v1').
        """
        if not adapter_id:
            raise ValueError("adapter_id must be a non-empty string")
        _validate_semver(adapter_version, "adapter_version")

        self.adapter_id = adapter_id
        self.adapter_version = adapter_version
        self.signing_key_id = signing_key_id
        self._secret: str | None = signing_secret or os.environ.get(
            "BUS_SIGNING_SECRET"
        )

    def generate(
        self,
        model_id: str,
        model_version: str,
        input_data: Any,
        output_data: Any,
        risk_classification: str,
        contract_id: str,
        dct_subject: str,
        dct_chain_depth: int,
        outcome: str,
        eu_ai_act_risk_category: str | None = None,
        phi_processed: bool | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate a signed AdapterReceipt for one inference event.

        Args:
            model_id: Model identifier (e.g., 'gpt-4o', 'claude-opus-4-6').
            model_version: Version string from provider API.
            input_data: The full input payload (hashed, not stored).
            output_data: The full output payload (hashed, not stored).
            risk_classification: One of low / medium / high / critical.
            contract_id: Contract ID authorizing this call.
            dct_subject: Delegation token subject (acting agent identity).
            dct_chain_depth: Integer depth of delegation chain (0 = human-direct).
            outcome: One of approved / flagged / rejected / routed.
            eu_ai_act_risk_category: Optional EU AI Act risk category override.
            phi_processed: Optional HIPAA flag.
            metadata: Optional dict with operational fields.

        Returns:
            Fully-formed, signed AdapterReceipt dict.

        Raises:
            ValueError: If any required field fails validation.
        """
        if risk_classification not in VALID_RISK_CLASSIFICATIONS:
            raise ValueError(
                f"risk_classification must be one of {sorted(VALID_RISK_CLASSIFICATIONS)}, "
                f"got: {risk_classification!r}"
            )
        if outcome not in VALID_OUTCOMES:
            raise ValueError(
                f"outcome must be one of {sorted(VALID_OUTCOMES)}, "
                f"got: {outcome!r}"
            )
        if not model_id:
            raise ValueError("model_id must be a non-empty string")
        if not model_version:
            raise ValueError("model_version must be a non-empty string")
        if not contract_id:
            raise ValueError("contract_id must be a non-empty string")
        if not dct_subject:
            raise ValueError("dct_subject must be a non-empty string")
        if not isinstance(dct_chain_depth, int) or dct_chain_depth < 0:
            raise ValueError(
                f"dct_chain_depth must be a non-negative integer, got: {dct_chain_depth!r}"
            )

        input_hash = _sha256_obj(input_data)
        output_hash = _sha256_obj(output_data)

        crosswalk = _build_crosswalk(eu_ai_act_risk_category, phi_processed)

        receipt: dict[str, Any] = {
            "receipt_id": str(uuid.uuid4()),
            "receipt_version": RECEIPT_VERSION,
            "timestamp_utc": _utc_now(),
            "model_id": model_id,
            "model_version": model_version,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "risk_classification": risk_classification,
            "contract_id": contract_id,
            "dct_subject": dct_subject,
            "dct_chain_depth": dct_chain_depth,
            "outcome": outcome,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "compliance_crosswalk": crosswalk,
        }

        if metadata:
            receipt["metadata"] = _clean_metadata(metadata)

        receipt = self._commit(receipt)

        return receipt

    def verify(self, receipt: dict[str, Any]) -> bool:
        """Verify the cryptographic commitment on a receipt.

        Checks:
          1. receipt_hash matches canonical JSON of receipt (minus commitment).
          2. If signature present and signing_secret known, HMAC verifies.

        Args:
            receipt: A previously generated receipt dict.

        Returns:
            True if the receipt is internally consistent and (if signed) the
            signature verifies. False if any check fails.
        """
        commitment = receipt.get("cryptographic_commitment", {})
        stored_hash = commitment.get("receipt_hash")
        if not stored_hash:
            return False

        expected_hash = _sha256_text(
            _canonical_json(receipt, exclude_key="cryptographic_commitment")
        )
        if expected_hash != stored_hash:
            return False

        stored_sig = commitment.get("signature")
        if stored_sig and self._secret:
            return _hmac_verify(stored_hash, stored_sig, self._secret)

        if stored_sig or self._secret:
            return False

        return True

    def save(self, receipt: dict[str, Any], path: str | Path) -> Path:
        """Append receipt as a JSONL record to path (append-only).

        Creates parent directories if they do not exist. Never overwrites
        or truncates existing content.

        Args:
            receipt: Finalized receipt dict.
            path: Destination JSONL path.

        Returns:
            Resolved Path of the written file.
        """
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        line = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        with open(destination, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        return destination.resolve()

    def _commit(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Compute receipt_hash and optionally HMAC-sign. Returns updated receipt."""
        receipt = dict(receipt)

        canonical = _canonical_json(receipt, exclude_key="cryptographic_commitment")
        receipt_hash = _sha256_text(canonical)

        commitment: dict[str, Any] = {
            "receipt_hash": receipt_hash,
        }

        if self._secret:
            sig = _hmac_sign(receipt_hash, self._secret)
            commitment["signature"] = sig
            commitment["signing_key_id"] = self.signing_key_id
            commitment["signature_valid"] = True

        receipt["cryptographic_commitment"] = commitment
        return receipt


def _build_crosswalk(
    eu_ai_act_risk_category: str | None,
    phi_processed: bool | None,
) -> dict[str, Any]:
    """Build a compliance crosswalk dict with caller-supplied overrides."""
    import copy

    crosswalk = copy.deepcopy(DEFAULT_COMPLIANCE_CROSSWALK)

    if eu_ai_act_risk_category is not None:
        crosswalk["eu_ai_act"]["risk_category"] = eu_ai_act_risk_category
    else:
        crosswalk["eu_ai_act"].pop("risk_category", None)

    if phi_processed is not None:
        crosswalk["hipaa"]["phi_processed"] = phi_processed
    else:
        crosswalk["hipaa"].pop("phi_processed", None)

    return crosswalk


def _clean_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Strip unknown keys from metadata to avoid schema violations."""
    allowed = {
        "session_id", "trace_id", "latency_ms", "token_input", "token_output",
        "tags", "claim_verification",
        "kill_switch_blocked", "kill_switch_mode", "kill_switch_reason",
    }
    return {k: v for k, v in metadata.items() if k in allowed}
