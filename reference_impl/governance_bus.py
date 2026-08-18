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

"""Governance Bus -- append-only audit log for governance tuples.

Implements the governance event store with hash-chaining, rotation, and
retention. All governance tuples (DCTX, CONTRACT, EVIDENCE, ATTEST, DCT)
are written to an append-only JSONL log with rotation and retention.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Inline PII redaction (replaces external scrubber dependency)
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, str]] = [
    # Email addresses
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[REDACTED:email]"),
    # Phone numbers (US and international)
    (r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}", "[REDACTED:phone]"),
    # SSN-like patterns
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED:ssn]"),
    # IPv4 addresses
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED:ip]"),
]

_PII_KEYS = frozenset({
    "email", "phone", "ssn", "address", "name", "password",
    "api_key", "token", "secret", "credential",
})


def _scrub_pii(data: Any) -> Any:
    """Inline PII redaction function.

    Replaces PII (emails, phones, SSNs, IPs) with redaction markers,
    and redacts values for known sensitive keys. Recurses into dicts
    and lists.
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if isinstance(key, str) and key.lower() in _PII_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = _scrub_pii(value)
        return result
    if isinstance(data, list):
        return [_scrub_pii(item) for item in data]
    if isinstance(data, str):
        scrubbed = data
        for pattern, replacement in _PII_PATTERNS:
            scrubbed = re.sub(pattern, replacement, scrubbed)
        return scrubbed
    return data


def _is_idp_enabled() -> bool:
    """Check if the governance feature flag is enabled (runtime check).

    Fail-closed signature enforcement: governance audit is mandatory.
    Set ENABLE_IDP=false ONLY for emergency bypass (logs warning).
    """
    enabled = os.environ.get("ENABLE_IDP", "true").lower() == "true"
    if not enabled:
        logger.warning(
            "ENABLE_IDP=false: Governance audit BYPASSED. "
            "This is an emergency-only setting and creates compliance risk."
        )
    return enabled


# Default paths
DEFAULT_GOVERNANCE_DIR = Path("governance_logs")

# Retention configuration
DEFAULT_RETENTION_DAYS = 180  # EU AI Act Art 26(5) requires minimum 6 months
ROTATION_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

# Error codes
IDP_E_AUDIT_INCOMPLETE = "IDP_E_AUDIT_INCOMPLETE"
IDP_E_AUDIT_IMMUTABLE = "IDP_E_AUDIT_IMMUTABLE"
IDP_E_AMENDMENT_TARGET_MISSING = "IDP_E_AMENDMENT_TARGET_MISSING"
IDP_E_VERIFICATION_REF_INVALID = "IDP_E_VERIFICATION_REF_INVALID"
IDP_E_EVIDENCE_REQUIRED = "IDP_E_EVIDENCE_REQUIRED"
IDP_E_CHAIN_BROKEN = "IDP_E_CHAIN_BROKEN"
IDP_E_LATERAL_AUTH = "IDP_E_LATERAL_AUTH"
IDP_E_DECISION_AUTH = "IDP_E_DECISION_AUTH"


@dataclass(frozen=True)
class GovernanceEntry:
    """Single entry in the governance audit log.

    Wraps any governance tuple with metadata for audit trail.

    Cross-link fields (contract_id, capability_token_id, verification_id)
    are top-level to enable direct traversal without inspecting tuple_data.
    The amendment_of field enables structural amendment tracking.
    """

    timestamp: str
    entry_id: str
    intent_id: str
    task_id: str
    tuple_type: Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"]
    tuple_data: dict[str, Any]
    signature: str | None = None
    state: str = "ok"
    drift: float = 0.0
    contract_id: str | None = None
    capability_token_id: str | None = None
    verification_id: str | None = None
    amendment_of: str | None = None
    previous_hash: str | None = None

    def to_jsonl(self) -> str:
        """Serialize to JSONL line."""
        data: dict[str, Any] = {
            "timestamp": self.timestamp,
            "entry_id": self.entry_id,
            "intent_id": self.intent_id,
            "task_id": self.task_id,
            "tuple_type": self.tuple_type,
            "tuple_data": self.tuple_data,
            "signature": self.signature,
            "state": self.state,
            "drift": self.drift,
        }
        if self.contract_id is not None:
            data["contract_id"] = self.contract_id
        if self.capability_token_id is not None:
            data["capability_token_id"] = self.capability_token_id
        if self.verification_id is not None:
            data["verification_id"] = self.verification_id
        if self.amendment_of is not None:
            data["amendment_of"] = self.amendment_of
        if self.previous_hash is not None:
            data["previous_hash"] = self.previous_hash
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernanceEntry:
        """Deserialize from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            entry_id=data["entry_id"],
            intent_id=data["intent_id"],
            task_id=data["task_id"],
            tuple_type=data["tuple_type"],
            tuple_data=data["tuple_data"],
            signature=data.get("signature"),
            state=data.get("state", "ok"),
            drift=data.get("drift", 0.0),
            contract_id=data.get("contract_id"),
            capability_token_id=data.get("capability_token_id"),
            verification_id=data.get("verification_id"),
            amendment_of=data.get("amendment_of"),
            previous_hash=data.get("previous_hash"),
        )


class GovernanceBus:
    """Append-only governance audit log for governance tuples.

    Implements audit completeness with:
    - Atomic append-only writes
    - Daily file rotation
    - 180-day retention (EU AI Act Art 26(5) minimum 6 months)
    - Query by intent_id or task_id
    - Optional async buffering
    - Hash-chaining for tamper-evidence

    Thread-safe for concurrent writes.
    """

    def __init__(
        self,
        base_dir: Path | str | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        enable_async: bool = False,
    ):
        """Initialize governance bus.

        Args:
            base_dir: Directory for audit logs (default: governance_logs)
            retention_days: Days to retain logs (default: 180)
            enable_async: Enable async write buffering (default: False)
        """
        if base_dir is None:
            base_dir = DEFAULT_GOVERNANCE_DIR
        self._base_dir = Path(base_dir)
        self._retention_days = retention_days
        self._enable_async = enable_async

        self._base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._base_dir, 0o700)
        except OSError as e:
            logger.debug("Could not set governance dir permissions: %s", e)

        self._lock = threading.RLock()
        self._buffer: list[GovernanceEntry] = []
        self._buffer_lock = threading.RLock()
        self._current_file: Path | None = None
        self._file_handle: Any = None

    def _get_current_file(self) -> Path:
        """Get current log file path (daily rotation)."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._base_dir / f"governance-{today}.jsonl"

    def _rotate_if_needed(self) -> None:
        """Check and perform file rotation if needed."""
        current = self._get_current_file()

        if self._current_file != current:
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            self._current_file = current

        if current.exists() and current.stat().st_size > ROTATION_SIZE_BYTES:
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            compressed = current.with_suffix(".jsonl.gz")
            with open(current, "rb") as f_in, gzip.open(compressed, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            current.unlink()

    def _open_file(self) -> Any:
        """Open current log file for appending."""
        if self._file_handle is None or self._file_handle.closed:
            self._current_file = self._get_current_file()
            self._file_handle = open(self._current_file, "a", encoding="utf-8")
        return self._file_handle

    def append(
        self,
        intent_id: str,
        task_id: str,
        tuple_type: Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"],
        tuple_data: dict[str, Any],
        signature: str | None = None,
        require_signature: bool = True,
        state: str = "ok",
        drift: float = 0.0,
        contract_id: str | None = None,
        capability_token_id: str | None = None,
        verification_id: str | None = None,
        amendment_of: str | None = None,
        authority_class: bool = False,
    ) -> tuple[bool, str | None]:
        """Append entry to governance log.

        Fail-closed signature enforcement: signatures are mandatory for audit
        integrity.

        Args:
            intent_id: Root intent identifier
            task_id: Task identifier
            tuple_type: Type of governance tuple
            tuple_data: The tuple data
            signature: HMAC signature (required unless require_signature=False)
            require_signature: If True (default), rejects entries without signatures
            state: Outcome state ("ok", "blocked", "error")
            drift: Drift score (0.0 to 1.0)
            contract_id: Cross-link to governing CONTRACT entry
            capability_token_id: Cross-link to authorizing DCT entry
            verification_id: Cross-link from ATTEST to EVIDENCE entry
            amendment_of: entry_id of the entry being amended (append-only correction)
            authority_class: If True, requires capability_token_id referencing a valid DCT
                (lateral authority enforcement).

        Returns:
            Tuple of (success, error_code). Error codes:
            - IDP_E_AUDIT_INCOMPLETE: Write failed
            - IDP_E_AUDIT_IMMUTABLE: Signature required but missing
            - IDP_E_AMENDMENT_TARGET_MISSING: amendment_of references nonexistent entry
            - IDP_E_EVIDENCE_REQUIRED: ATTEST without verification_id
            - IDP_E_LATERAL_AUTH: authority_class entry without capability_token_id
            - IDP_E_DECISION_AUTH: authority_class entry with invalid DCT reference
        """
        if not _is_idp_enabled():
            logger.warning(
                "Governance append while governance disabled - entry not audited"
            )
            return True, None

        # Fail-closed signature enforcement
        if require_signature and not signature:
            logger.error(
                "Governance entry rejected: signature required but not provided. "
                "Set require_signature=False only for emergency recovery."
            )
            return False, IDP_E_AUDIT_IMMUTABLE

        # Evidence-before-verify: ATTEST tuples must reference EVIDENCE
        if tuple_type == "ATTEST" and verification_id is None:
            logger.error(
                "Governance entry rejected: ATTEST tuple requires verification_id "
                "(evidence-before-verify invariant)."
            )
            return False, IDP_E_EVIDENCE_REQUIRED

        # Referential integrity: verification_id must reference existing EVIDENCE entry
        if tuple_type == "ATTEST" and verification_id is not None:
            ref_entry = self.query_by_entry_id(verification_id)
            if ref_entry is None or ref_entry.tuple_type != "EVIDENCE":
                logger.error(
                    "Governance entry rejected: verification_id %s does not reference "
                    "an existing EVIDENCE entry (referential integrity).",
                    verification_id,
                )
                return False, IDP_E_VERIFICATION_REF_INVALID

        # Amendment validation: referenced entry must exist
        if amendment_of is not None:
            found = False
            for entry in self._query(lambda e: e.entry_id == amendment_of):
                found = True
                break
            if not found:
                logger.error(
                    "Governance entry rejected: amendment_of references "
                    f"nonexistent entry {amendment_of}."
                )
                return False, IDP_E_AMENDMENT_TARGET_MISSING

        # Lateral authority enforcement
        if authority_class:
            if capability_token_id is None:
                logger.error(
                    "Governance entry rejected: authority_class entry requires "
                    "capability_token_id (lateral authority enforcement)."
                )
                return False, IDP_E_LATERAL_AUTH
            ref_dct = self.query_by_entry_id(capability_token_id)
            if ref_dct is None or ref_dct.tuple_type != "DCT":
                logger.error(
                    "Governance entry rejected: capability_token_id %s does not "
                    "reference an existing DCT entry (lateral authority enforcement).",
                    capability_token_id,
                )
                return False, IDP_E_DECISION_AUTH

        # PII scrub: sanitize tuple_data before it enters the hash-chained log.
        scrubbed_data = _scrub_pii(tuple_data)

        # Hash-chaining: link to prior entry for tamper-evident audit trail
        with self._lock:
            prev_hash = self._get_last_entry_hash()

        entry = GovernanceEntry(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            entry_id=self._generate_entry_id(),
            intent_id=intent_id,
            task_id=task_id,
            tuple_type=tuple_type,
            tuple_data=scrubbed_data,
            signature=signature,
            state=state,
            drift=drift,
            contract_id=contract_id,
            capability_token_id=capability_token_id,
            verification_id=verification_id,
            amendment_of=amendment_of,
            previous_hash=prev_hash,
        )

        if self._enable_async:
            return self._append_async(entry)
        else:
            return self._append_sync(entry)

    def _append_sync(self, entry: GovernanceEntry) -> tuple[bool, str | None]:
        """Synchronous append with atomic write and permission hardening."""
        with self._lock:
            try:
                self._rotate_if_needed()
                f = self._open_file()
                f.write(entry.to_jsonl() + "\n")
                f.flush()
                os.fsync(f.fileno())

                # Harden file permissions on governance logs
                if self._current_file:
                    try:
                        self._current_file.chmod(0o600)
                    except OSError as e:
                        logger.warning("Failed to harden governance log permissions: %s", e)

                return True, None
            except (IOError, OSError):
                return False, IDP_E_AUDIT_INCOMPLETE

    def _append_async(self, entry: GovernanceEntry) -> tuple[bool, str | None]:
        """Async append to buffer (flushed periodically)."""
        with self._buffer_lock:
            self._buffer.append(entry)
            if len(self._buffer) >= 100:
                return self._flush_buffer()
            return True, None

    def _flush_buffer(self) -> tuple[bool, str | None]:
        """Flush async buffer to disk with permission hardening."""
        with self._lock, self._buffer_lock:
            if not self._buffer:
                return True, None

            try:
                self._rotate_if_needed()
                f = self._open_file()
                for entry in self._buffer:
                    f.write(entry.to_jsonl() + "\n")
                f.flush()
                os.fsync(f.fileno())

                if self._current_file:
                    try:
                        self._current_file.chmod(0o600)
                    except OSError as e:
                        logger.warning("Failed to harden governance log permissions: %s", e)

                self._buffer.clear()
                return True, None
            except (IOError, OSError):
                return False, IDP_E_AUDIT_INCOMPLETE

    def _generate_entry_id(self) -> str:
        """Generate unique entry ID."""
        return str(uuid.uuid4())

    @staticmethod
    def compute_entry_hash(jsonl_line: str) -> str:
        """Compute SHA-256 hash of a JSONL entry line.

        This is the hash that the *next* entry stores in its previous_hash
        field, creating a tamper-evident chain.
        """
        return hashlib.sha256(jsonl_line.encode("utf-8")).hexdigest()

    def _get_last_entry_hash(self) -> str | None:
        """Read the last entry from the current log file and return its hash.

        Returns None if the log is empty or doesn't exist yet (genesis entry).
        """
        current = self._get_current_file()
        if not current.exists():
            return None

        last_line = None
        try:
            with open(current, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
        except (IOError, OSError):
            return None

        if last_line is None:
            return None
        return self.compute_entry_hash(last_line)

    def verify_chain(self, filepath: Path | None = None) -> tuple[bool, list[dict]]:
        """Verify hash-chain integrity of a governance log file.

        Walks every entry in order and confirms each entry's previous_hash
        matches the SHA-256 of the prior entry's canonical JSONL. Reports
        all breaks found.

        Args:
            filepath: Specific log file to verify. Defaults to current day's file.

        Returns:
            Tuple of (chain_valid, breaks) where breaks is a list of dicts:
            [{"line": int, "entry_id": str, "expected": str, "actual": str}]
        """
        if filepath is None:
            filepath = self._get_current_file()

        if not filepath.exists():
            return True, []

        breaks: list[dict] = []
        prev_line: str | None = None
        line_num = 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for raw_line in f:
                    stripped = raw_line.strip()
                    if not stripped:
                        continue
                    line_num += 1

                    try:
                        data = json.loads(stripped)
                    except json.JSONDecodeError:
                        breaks.append({
                            "line": line_num,
                            "entry_id": "PARSE_ERROR",
                            "expected": "valid JSON",
                            "actual": "malformed",
                        })
                        prev_line = stripped
                        continue

                    if data is None or not isinstance(data, dict):
                        breaks.append({
                            "line": line_num,
                            "entry_id": "PARSE_ERROR",
                            "expected": "JSON object",
                            "actual": str(data),
                        })
                        prev_line = stripped
                        continue

                    entry_prev_hash = data.get("previous_hash")

                    if line_num == 1:
                        if entry_prev_hash is not None:
                            breaks.append({
                                "line": 1,
                                "entry_id": data.get("entry_id", "UNKNOWN"),
                                "expected": "null (genesis)",
                                "actual": entry_prev_hash,
                            })
                    else:
                        expected_hash = self.compute_entry_hash(prev_line) if prev_line else None
                        if entry_prev_hash != expected_hash:
                            breaks.append({
                                "line": line_num,
                                "entry_id": data.get("entry_id", "UNKNOWN"),
                                "expected": expected_hash or "null",
                                "actual": entry_prev_hash or "null",
                            })

                    prev_line = stripped

        except (IOError, OSError) as e:
            breaks.append({
                "line": 0,
                "entry_id": "FILE_ERROR",
                "expected": "readable file",
                "actual": str(e),
            })

        return len(breaks) == 0, breaks

    def query_by_intent(
        self,
        intent_id: str,
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
        since: str | None = None,
    ) -> Iterator[GovernanceEntry]:
        """Query entries by intent_id.

        Args:
            intent_id: Intent to query
            tuple_type: Optional filter by tuple type
            since: Optional ISO8601 timestamp filter

        Yields:
            GovernanceEntry objects matching query
        """
        if not _is_idp_enabled():
            return

        yield from self._query(
            lambda e: e.intent_id == intent_id,
            tuple_type=tuple_type,
            since=since,
        )

    def query_by_task(
        self,
        task_id: str,
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
    ) -> Iterator[GovernanceEntry]:
        """Query entries by task_id.

        Args:
            task_id: Task to query
            tuple_type: Optional filter by tuple type

        Yields:
            GovernanceEntry objects matching query
        """
        if not _is_idp_enabled():
            return

        yield from self._query(
            lambda e: e.task_id == task_id,
            tuple_type=tuple_type,
        )

    def query_by_entry_id(self, entry_id: str) -> GovernanceEntry | None:
        """Query a single entry by its entry_id."""
        if not _is_idp_enabled():
            return None
        for entry in self._query(lambda e: e.entry_id == entry_id):
            return entry
        return None

    def query_by_contract(
        self,
        contract_id: str,
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
    ) -> Iterator[GovernanceEntry]:
        """Query entries by contract_id cross-link."""
        if not _is_idp_enabled():
            return
        yield from self._query(
            lambda e: e.contract_id == contract_id,
            tuple_type=tuple_type,
        )

    def query_amendments(self, entry_id: str) -> Iterator[GovernanceEntry]:
        """Query all amendments to a given entry."""
        if not _is_idp_enabled():
            return
        yield from self._query(lambda e: e.amendment_of == entry_id)

    def query_all(
        self,
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
        since: str | None = None,
    ) -> Iterator[GovernanceEntry]:
        """Yield every governance entry (gated by ENABLE_IDP)."""
        if not _is_idp_enabled():
            return
        yield from self._query(lambda e: True, tuple_type=tuple_type, since=since)

    def _query(
        self,
        predicate: Callable[[GovernanceEntry], bool],
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
        since: str | None = None,
    ) -> Iterator[GovernanceEntry]:
        """Internal query implementation."""
        files = sorted(self._base_dir.glob("governance-*.jsonl*"), reverse=True)

        for filepath in files:
            if filepath.suffix == ".gz":
                opener = partial(gzip.open, filepath, "rt", encoding="utf-8")
            else:
                opener = partial(open, filepath, "r", encoding="utf-8")
                chain_valid, breaks = self.verify_chain(filepath)
                if not chain_valid:
                    logger.error(
                        "%s: %d chain break(s) detected during read -- "
                        "governance log may have been tampered with. "
                        "error_code=%s breaks=%s",
                        filepath.name,
                        len(breaks),
                        IDP_E_CHAIN_BROKEN,
                        breaks[:3],
                    )

            try:
                with opener() as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            entry = GovernanceEntry.from_dict(data)

                            if not predicate(entry):
                                continue
                            if tuple_type and entry.tuple_type != tuple_type:
                                continue
                            if since and entry.timestamp < since:
                                continue

                            yield entry
                        except (json.JSONDecodeError, KeyError, TypeError) as e:
                            logger.warning("Corrupted governance entry in %s: %s", filepath, e)
                            continue
            except (IOError, OSError) as e:
                logger.warning("Unreadable governance log %s: %s", filepath, e)
                continue

    def enforce_retention(self) -> int:
        """Enforce retention policy by deleting old logs.

        Returns:
            Number of files deleted
        """
        if not _is_idp_enabled():
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        deleted = 0

        for filepath in self._base_dir.glob("governance-*.jsonl*"):
            try:
                date_str = filepath.stem.split("-")[1:4]
                file_date = datetime(
                    int(date_str[0]),
                    int(date_str[1]),
                    int(date_str[2]),
                    tzinfo=timezone.utc,
                )
                if file_date < cutoff:
                    filepath.unlink()
                    deleted += 1
            except (ValueError, IndexError):
                continue

        return deleted

    def close(self) -> None:
        """Close file handles and flush buffers."""
        if self._enable_async:
            self._flush_buffer()

        with self._lock:
            if self._file_handle and not self._file_handle.closed:
                self._file_handle.close()
                self._file_handle = None

    def __enter__(self) -> GovernanceBus:
        """Context manager entry."""
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.close()
