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

Implements the governance event store with a single global hash chain,
a single-writer discipline (keyed MAC tags), write-once monotonic
archives, retention tombstones, and checkpoint export for external
anchoring. All governance tuples (DCTX, CONTRACT, EVIDENCE, ATTEST, DCT,
SYSTEM) are written to an append-only JSONL log.

Remediates defects T1-T9, T13-T14 of the v2.1 reference implementation
(see GOVERNANCE_TUPLE_KRINEIA_MERGED_REMEDIATION_MASTER v1.1, fixes
F1, F2, F3, F9, F11).
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
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII detection -- F8 (scrubber rule)
#
# v2.1 rewrote tuple_data in place before hashing: UUID tails became
# [REDACTED:phone], dotted ids became [REDACTED:ip], and a field-name
# allowlist (_PII_KEYS) wiped `name`/`token` values. Any signed or hashed
# object (DCT, digest-bearing CONTRACT) no longer verified after logging
# (T9), and ~10% of UUIDs / ~28% of SHA-256 hex strings were mangled (T14).
#
# F8: the bus never modifies tuple_data. PII handling is the caller's job --
# redact at the source before signing or hashing, or store a separate
# unauthenticated redacted view. The bus's role is detection: content
# matching high-confidence PII patterns is refused with IDP_E_PII_DETECTED
# so no unredacted PII ever enters the immutable chain. Structural
# identifiers (UUIDs, hex digests) are masked before scanning -- not a
# field-name allowlist: masking applies to any string regardless of key.
# ---------------------------------------------------------------------------

# Structural identifier shapes masked before PII scanning so identifiers
# are never mistaken for PII. Not content rewriting -- detection only.
_STRUCT_MASK_PATTERNS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b[0-9a-fA-F]{64}\b"),                # SHA-256 hex
    re.compile(r"\b[0-9a-fA-F]{32}\b"),                # 32-hex ids
]

_PII_PATTERNS: list[tuple[str, str]] = [
    # Email addresses
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "email"),
    # Phone numbers (US national and international), word-bounded
    (r"(?<![\w-])(\+\d{1,3}[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", "phone"),
    # SSN-like patterns
    (r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])", "ssn"),
    # IPv4 addresses
    (r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "ip"),
]


def _detect_pii(data: Any, _hits: list[str] | None = None) -> list[str]:
    """Detect likely PII in payload data. Returns labels of patterns found.

    Read-only: never modifies or returns a rewritten copy of the data.
    Callers redact at the source (F8); the bus refuses flagged payloads.
    """
    hits = _hits if _hits is not None else []
    if isinstance(data, dict):
        for value in data.values():
            _detect_pii(value, hits)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _detect_pii(item, hits)
    elif isinstance(data, str):
        masked = data
        for pat in _STRUCT_MASK_PATTERNS:
            masked = pat.sub("X", masked)
        for pattern, label in _PII_PATTERNS:
            if re.search(pattern, masked) and label not in hits:
                hits.append(label)
    return hits


def _is_idp_enabled() -> bool:
    """Check if the governance feature flag is enabled (runtime check).

    Fail-closed signature enforcement: governance audit is mandatory.
    Set ENABLE_IDP=false ONLY for emergency bypass; the bus records a
    tagged SYSTEM entry marking the bypass before refusing the append.
    """
    return os.environ.get("ENABLE_IDP", "true").lower() == "true"


# Default paths
DEFAULT_GOVERNANCE_DIR = Path("governance_logs")

# Retention configuration
DEFAULT_RETENTION_DAYS = 180  # EU AI Act Art 26(6) deployer log retention
ROTATION_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

# Head-state sidecar (F1): the writer's persisted (seq, head_hash).
HEAD_STATE_FILENAME = "head.json"

# Writer key file (F3): symmetric MAC key held by the writer only.
WRITER_KEY_FILENAME = ".writer_key"
WRITER_KEY_ENV = "GT_BUS_WRITER_KEY"

# Error codes
IDP_E_AUDIT_INCOMPLETE = "IDP_E_AUDIT_INCOMPLETE"
IDP_E_AUDIT_IMMUTABLE = "IDP_E_AUDIT_IMMUTABLE"
IDP_E_AMENDMENT_TARGET_MISSING = "IDP_E_AMENDMENT_TARGET_MISSING"
IDP_E_VERIFICATION_REF_INVALID = "IDP_E_VERIFICATION_REF_INVALID"
IDP_E_EVIDENCE_REQUIRED = "IDP_E_EVIDENCE_REQUIRED"
IDP_E_PII_DETECTED = "IDP_E_PII_DETECTED"
IDP_E_SYSTEM_FORGED = "IDP_E_SYSTEM_FORGED"
IDP_E_CHAIN_BROKEN = "IDP_E_CHAIN_BROKEN"
IDP_E_LATERAL_AUTH = "IDP_E_LATERAL_AUTH"
IDP_E_DECISION_AUTH = "IDP_E_DECISION_AUTH"
IDP_E_CALLER_SIGNATURE = "IDP_E_CALLER_SIGNATURE"
IDP_E_GOVERNANCE_DISABLED = "IDP_E_GOVERNANCE_DISABLED"
IDP_E_HEAD_MISMATCH = "IDP_E_HEAD_MISMATCH"

_LOG_NAME_RE = re.compile(r"^governance-(\d{4})-(\d{2})-(\d{2})(?:\.(\d+))?\.jsonl(?:\.gz)?$")


@dataclass(frozen=True)
class GovernanceEntry:
    """Single entry in the governance audit log.

    Wraps any governance tuple with metadata for audit trail.

    Cross-link fields (contract_id, capability_token_id, verification_id)
    are top-level to enable direct traversal without inspecting tuple_data.
    The amendment_of field enables structural amendment tracking.
    seq, previous_hash, and signature are assigned by the writer (F1/F3);
    callers never supply them.
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
    seq: int | None = None

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
        if self.seq is not None:
            data["seq"] = self.seq
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def _tag_payload(self) -> bytes:
        """Canonical bytes the writer MACs: the full entry sans signature."""
        data: dict[str, Any] = {
            "timestamp": self.timestamp,
            "entry_id": self.entry_id,
            "intent_id": self.intent_id,
            "task_id": self.task_id,
            "tuple_type": self.tuple_type,
            "tuple_data": self.tuple_data,
            "state": self.state,
            "drift": self.drift,
        }
        for f in ("contract_id", "capability_token_id", "verification_id",
                  "amendment_of", "previous_hash", "seq"):
            v = getattr(self, f)
            if v is not None:
                data[f] = v
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

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
            seq=data.get("seq"),
        )


class GovernanceBus:
    """Append-only governance audit log for governance tuples.

    Implements audit completeness with:
    - Atomic append-only writes under a single writer lock (F3)
    - One global hash chain with explicit seq, across days and rotations (F1)
    - Writer-computed HMAC tags; caller-supplied signatures rejected (F3)
    - Write-once monotonic archives; retention covers live and compressed
      segments and appends a tombstone recording the pruned prefix (F9)
    - External-anchor checkpoint export and anchor-checked verification (F2)
    - Governance-disable bypass recorded as a tagged SYSTEM entry (F11)
    - Optional async buffering (chain finalized at flush under the lock)

    Thread-safe for concurrent writes.
    """

    def __init__(
        self,
        base_dir: Path | str | None = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        enable_async: bool = False,
        writer_key: bytes | None = None,
    ):
        """Initialize governance bus.

        Args:
            base_dir: Directory for audit logs (default: governance_logs)
            retention_days: Days to retain logs (default: 180)
            enable_async: Enable async write buffering (default: False)
            writer_key: Symmetric key for entry tags (F3). If None, loaded
                from GT_BUS_WRITER_KEY or generated and persisted to
                `<base_dir>/.writer_key`.
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
        self._buffer_lock = threading.RLock()
        self._buffer: list[GovernanceEntry] = []
        self._current_file: Path | None = None
        self._file_handle: Any = None

        self._writer_key = self._load_writer_key(writer_key)

        # F1: persisted head state + poisoned-on-mismatch startup reconcile.
        self._head_seq = 0
        self._head_hash: str | None = None
        self._rotation_counters: dict[str, int] = {}
        self._poisoned = False
        self._bypass_recorded = False
        self._reconcile_head()

    # ------------------------------------------------------------------
    # Writer key (F3) and head state (F1)
    # ------------------------------------------------------------------

    def _load_writer_key(self, key: bytes | None) -> bytes:
        if key is not None:
            return key
        env = os.environ.get(WRITER_KEY_ENV)
        if env:
            return bytes.fromhex(env)
        key_path = self._base_dir / WRITER_KEY_FILENAME
        if key_path.exists():
            return bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
        generated = os.urandom(32)
        key_path.write_text(generated.hex(), encoding="utf-8")
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        return generated

    @property
    def _head_path(self) -> Path:
        return self._base_dir / HEAD_STATE_FILENAME

    def _persist_head(self) -> None:
        """Atomically persist (seq, head_hash). Caller holds self._lock."""
        tmp = self._head_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({
            "seq": self._head_seq,
            "head_hash": self._head_hash,
            "rotation_counters": self._rotation_counters,
            "updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }), encoding="utf-8")
        os.replace(tmp, self._head_path)

    def _iter_segments(self) -> list[Path]:
        """All log segments, active and archived, sorted by (date, rot idx)."""
        segs = []
        for p in self._base_dir.glob("governance-*.jsonl*"):
            m = _LOG_NAME_RE.match(p.name)
            if m:
                segs.append((p, m.group(1, 2, 3), int(m.group(4) or 0)))
        segs.sort(key=lambda t: (t[1], t[2], 0 if t[0].suffix != ".gz" else 1))
        return [p for p, _, _ in segs]

    def _read_segment(self, path: Path) -> list[tuple[str, dict | None]]:
        """Read one segment; returns [(raw_line, parsed_or_None)]."""
        out: list[tuple[str, dict | None]] = []
        opener = (partial(gzip.open, path, "rt", encoding="utf-8")
                  if path.suffix == ".gz"
                  else partial(open, path, "r", encoding="utf-8"))
        try:
            with opener() as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        out.append((line, json.loads(line)))
                    except json.JSONDecodeError:
                        out.append((line, None))
        except (IOError, OSError) as e:
            logger.warning("Unreadable governance log %s: %s", path, e)
        return out

    def _tail_entry(self) -> dict | None:
        """Last log entry across all segments (None if log empty)."""
        tail: dict | None = None
        for seg in self._iter_segments():
            for _raw, data in self._read_segment(seg):
                if data is not None:
                    tail = data
        return tail

    def _reconcile_head(self) -> None:
        """Load persisted head; reconcile against the log tail.

        If persisted head disagrees with the log tail, the log was altered
        or truncated while the writer was stopped: poison the bus so append
        refuses rather than extending a forked chain (F1).
        """
        persisted: dict | None = None
        if self._head_path.exists():
            try:
                persisted = json.loads(self._head_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Unreadable head state %s: %s", self._head_path, e)
                self._poisoned = True
                return

        tail = self._tail_entry()

        if persisted is None:
            if tail is None:
                return  # genesis state; nothing logged yet
            # Bootstrap: pre-F1 or externally-restored log with no head file.
            tail_line = self._tail_line_raw()
            self._head_seq = int(tail.get("seq") or 0) if tail else 0
            if self._head_seq == 0 and tail is not None:
                # Legacy log without seq: derive seq as entry count.
                self._head_seq = sum(
                    1 for seg in self._iter_segments()
                    for _raw, d in self._read_segment(seg) if d is not None
                )
            self._head_hash = (
                self.compute_entry_hash(tail_line) if tail_line else None
            )
            try:
                self._persist_head()
            except OSError as e:
                logger.error("Cannot persist head state: %s", e)
                self._poisoned = True
            return

        self._head_seq = int(persisted["seq"])
        self._head_hash = persisted["head_hash"]
        rc = persisted.get("rotation_counters")
        if isinstance(rc, dict):
            self._rotation_counters = {str(k): int(v) for k, v in rc.items()}

        tail_line = self._tail_line_raw()
        if tail is None:
            if self._head_seq != 0:
                logger.error(
                    "Head state records seq=%d but log is empty -- tail "
                    "truncated while writer stopped; refusing to append.",
                    self._head_seq,
                )
                self._poisoned = True
            return
        actual_hash = self.compute_entry_hash(tail_line) if tail_line else None
        actual_seq = int(tail.get("seq") or 0)
        if actual_seq != self._head_seq or actual_hash != self._head_hash:
            logger.error(
                "Head mismatch: persisted (seq=%d, hash=%s) vs log tail "
                "(seq=%d, hash=%s) -- log altered while writer stopped; "
                "refusing to append.",
                self._head_seq, self._head_hash, actual_seq, actual_hash,
            )
            self._poisoned = True

    def _tail_line_raw(self) -> str | None:
        """Raw JSONL line of the last entry across all segments."""
        last: str | None = None
        for seg in self._iter_segments():
            for raw, data in self._read_segment(seg):
                if data is not None:
                    last = raw
        return last

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------

    def _get_current_file(self) -> Path:
        """Get current log file path (daily rotation)."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._base_dir / f"governance-{today}.jsonl"

    def _archive_path(self, date_str: str) -> Path:
        """Next write-once archive name for a date (F9).

        The per-date counter is durable (persisted in head.json) so archive
        indices are never reused, even after retention deletes archives --
        reusing .N would forge an archive identity (T6).
        """
        n = self._rotation_counters.get(date_str, 0) + 1
        self._rotation_counters[date_str] = n
        return self._base_dir / f"governance-{date_str}.{n}.jsonl.gz"

    def _archive_file(self, path: Path) -> None:
        """Compress a live segment into a uniquely-named archive (F9)."""
        m = _LOG_NAME_RE.match(path.name)
        date_str = (
            f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
            if m else datetime.now(timezone.utc).strftime("%Y-%m-%d")
        )
        compressed = self._archive_path(date_str)
        with open(path, "rb") as f_in, gzip.open(compressed, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        path.unlink()
        try:
            self._persist_head()  # durable rotation counter (F9)
        except OSError as e:
            logger.warning("Could not persist rotation counter: %s", e)

    def _rotate_if_needed(self) -> None:
        """Rotate on size; archive the prior day's file on day change."""
        current = self._get_current_file()

        if self._current_file != current:
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            # Day rollover: archive the previous active file (F9).
            if self._current_file is not None and self._current_file.exists():
                self._archive_file(self._current_file)
            self._current_file = current

        if current.exists() and current.stat().st_size > ROTATION_SIZE_BYTES:
            if self._file_handle:
                self._file_handle.close()
                self._file_handle = None
            self._archive_file(current)

    def _open_file(self) -> Any:
        """Open current log file for appending."""
        if self._file_handle is None or self._file_handle.closed:
            self._current_file = self._get_current_file()
            self._file_handle = open(self._current_file, "a", encoding="utf-8")
        return self._file_handle

    # ------------------------------------------------------------------
    # Append path
    # ------------------------------------------------------------------

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

        Entries are finalized by the writer: seq, timestamp, previous_hash
        and the HMAC tag are all computed under the writer lock. Callers
        cannot supply signatures (F3); the `signature` parameter is kept
        for API compatibility and any non-None value is rejected.

        Args:
            intent_id: Root intent identifier
            task_id: Task identifier
            tuple_type: Type of governance tuple
            tuple_data: The tuple data
            signature: REJECTED if supplied (F3) -- the writer computes tags
            require_signature: Entries always carry the writer tag; this
                knob is retained for API compatibility.
            state: Outcome state ("ok", "blocked", "error")
            drift: Drift score (0.0 to 1.0)
            contract_id: Cross-link to governing CONTRACT entry
            capability_token_id: Cross-link to authorizing DCT entry
            verification_id: Cross-link from ATTEST to EVIDENCE entry
            amendment_of: entry_id of the entry being amended
            authority_class: If True, requires capability_token_id
                referencing a valid DCT (lateral authority enforcement)

        Returns:
            Tuple of (success, error_code).
        """
        if not _is_idp_enabled():
            self._record_bypass()
            return False, IDP_E_GOVERNANCE_DISABLED

        if self._poisoned:
            return False, IDP_E_HEAD_MISMATCH

        # F3: caller-supplied signatures are rejected; W computes the tag.
        if signature is not None:
            logger.error(
                "Governance entry rejected: caller-supplied signature. "
                "The writer computes entry tags (F3)."
            )
            return False, IDP_E_CALLER_SIGNATURE

        # SYSTEM entries are writer-internal (governance-disable bypass
        # markers, retention tombstones). A caller-authored tombstone would
        # let an agent excuse a deleted prefix -- non-author review R1/G7.
        # Internal paths write through _write_entries directly.
        if tuple_type == "SYSTEM":
            logger.error(
                "Governance entry rejected: SYSTEM entries are "
                "writer-internal (tombstones, bypass markers)."
            )
            return False, IDP_E_SYSTEM_FORGED

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

        # PII detection (F8): the bus never rewrites tuple_data. Payloads
        # containing likely PII are refused -- callers redact at the source
        # before signing/hashing, or keep a separate redacted view.
        pii_hits = _detect_pii(tuple_data)
        if pii_hits:
            logger.error(
                "Governance entry rejected: likely PII in tuple_data %s. "
                "Redact at the source before signing (F8); the bus does not "
                "rewrite authenticated payloads.",
                pii_hits,
            )
            return False, IDP_E_PII_DETECTED

        entry = GovernanceEntry(
            timestamp="",  # writer assigns at finalize (F3)
            entry_id=self._generate_entry_id(),
            intent_id=intent_id,
            task_id=task_id,
            tuple_type=tuple_type,
            tuple_data=tuple_data,
            state=state,
            drift=drift,
            contract_id=contract_id,
            capability_token_id=capability_token_id,
            verification_id=verification_id,
            amendment_of=amendment_of,
        )

        if self._enable_async:
            return self._append_async(entry)
        # Single critical section: head read -> finalize -> write -> fsync
        # -> persist head. Releasing the lock between head read and write
        # is the v2.1 T4 fork (F3).
        with self._lock:
            return self._write_entries([entry])

    def _finalize_entry(self, entry: GovernanceEntry) -> GovernanceEntry:
        """Assign seq/timestamp/chain link/tag. Caller holds self._lock."""
        next_seq = self._head_seq + 1
        stamped = GovernanceEntry(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            entry_id=entry.entry_id,
            intent_id=entry.intent_id,
            task_id=entry.task_id,
            tuple_type=entry.tuple_type,
            tuple_data=entry.tuple_data,
            state=entry.state,
            drift=entry.drift,
            contract_id=entry.contract_id,
            capability_token_id=entry.capability_token_id,
            verification_id=entry.verification_id,
            amendment_of=entry.amendment_of,
            previous_hash=self._head_hash,
            seq=next_seq,
        )
        tag = hmac.new(self._writer_key, stamped._tag_payload(),
                       hashlib.sha256).hexdigest()
        return GovernanceEntry(
            timestamp=stamped.timestamp,
            entry_id=stamped.entry_id,
            intent_id=stamped.intent_id,
            task_id=stamped.task_id,
            tuple_type=stamped.tuple_type,
            tuple_data=stamped.tuple_data,
            signature=tag,
            state=stamped.state,
            drift=stamped.drift,
            contract_id=stamped.contract_id,
            capability_token_id=stamped.capability_token_id,
            verification_id=stamped.verification_id,
            amendment_of=stamped.amendment_of,
            previous_hash=stamped.previous_hash,
            seq=stamped.seq,
        )

    def _write_entries(self, entries: list[GovernanceEntry]) -> tuple[bool, str | None]:
        """Finalize and write entries atomically. Caller holds self._lock."""
        try:
            self._rotate_if_needed()
            f = self._open_file()
            written: list[GovernanceEntry] = []
            for pending in entries:
                entry = self._finalize_entry(pending)
                f.write(entry.to_jsonl() + "\n")
                self._head_seq = entry.seq or 0
                self._head_hash = self.compute_entry_hash(entry.to_jsonl())
                written.append(entry)
            f.flush()
            os.fsync(f.fileno())
            self._persist_head()

            if self._current_file:
                try:
                    self._current_file.chmod(0o600)
                except OSError as e:
                    logger.warning("Failed to harden governance log permissions: %s", e)

            return True, None
        except (IOError, OSError):
            return False, IDP_E_AUDIT_INCOMPLETE

    def _append_async(self, entry: GovernanceEntry) -> tuple[bool, str | None]:
        """Async append to buffer; chain finalized at flush (F3)."""
        with self._buffer_lock:
            self._buffer.append(entry)
            if len(self._buffer) >= 100:
                return self._flush_buffer()
            return True, None

    def _flush_buffer(self) -> tuple[bool, str | None]:
        """Flush async buffer: finalize chain under one lock (F3/T5)."""
        with self._lock, self._buffer_lock:
            if not self._buffer:
                return True, None
            if self._poisoned:
                return False, IDP_E_HEAD_MISMATCH
            ok, err = self._write_entries(list(self._buffer))
            if ok:
                self._buffer.clear()
            return ok, err

    def _record_bypass(self) -> None:
        """F11: record a governance-disable bypass as a tagged SYSTEM entry.

        Written once per writer lifetime; the requested record is still
        refused -- append never reports success for unwritten data.
        """
        if self._bypass_recorded:
            return
        marker = GovernanceEntry(
            timestamp="",
            entry_id=self._generate_entry_id(),
            intent_id="system",
            task_id="system",
            tuple_type="SYSTEM",
            tuple_data={
                "action": "governance_disabled",
                "reason": "ENABLE_IDP=false",
                "detail": "Governance bypass recorded before honoring disable",
            },
        )
        with self._lock:
            ok, _ = self._write_entries([marker])
        if ok:
            self._bypass_recorded = True
            logger.warning(
                "ENABLE_IDP=false: bypass SYSTEM entry appended; "
                "requested record NOT written."
            )
        else:
            logger.error("Could not record governance-disable bypass entry.")

    def _generate_entry_id(self) -> str:
        """Generate unique entry ID."""
        return str(uuid.uuid4())

    @staticmethod
    def compute_entry_hash(jsonl_line: str) -> str:
        """SHA-256 of a serialized JSONL entry line (chain link hash)."""
        return hashlib.sha256(jsonl_line.encode("utf-8")).hexdigest()

    def compute_tag(self, entry: GovernanceEntry) -> str:
        """Writer MAC over the canonical entry payload (F3)."""
        return hmac.new(self._writer_key, entry._tag_payload(),
                        hashlib.sha256).hexdigest()

    def verify_tag(self, entry: GovernanceEntry) -> bool:
        """Verify a deserialized entry's writer tag."""
        if entry.signature is None:
            return False
        return hmac.compare_digest(
            entry.signature,
            hmac.new(self._writer_key, entry._tag_payload(),
                     hashlib.sha256).hexdigest(),
        )

    # ------------------------------------------------------------------
    # Checkpoints (F2)
    # ------------------------------------------------------------------

    def compute_checkpoint(self) -> dict[str, Any]:
        """Checkpoint (k, H(e_k), t) for external anchoring (F2).

        Publish to a medium the operator cannot rewrite (Zenodo version,
        Software Heritage). The verifier must fetch checkpoints from the
        medium directly, never through the writer/operator.
        """
        return {
            "seq": self._head_seq,
            "hash": self._head_hash,
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def _verify_entry_sequence(
        self,
        entries: list[tuple[str, dict | None, str, int]],
        anchors: Iterable[dict[str, Any]] | None = None,
    ) -> tuple[bool, list[dict]]:
        """Verify a globally seq-ordered entry list.

        entries: [(raw_line, parsed, segment_name, line_no)] sorted by seq.
        Checks: seq continuity, back-links, writer tags, anchor agreement.
        """
        breaks: list[dict] = []
        prev_raw: str | None = None
        prev_seq: int | None = None
        anchor_map = {int(a["seq"]): a["hash"] for a in (anchors or [])}
        pos = 0

        for raw, data, seg_name, line_no in entries:
            pos += 1
            if data is None or not isinstance(data, dict):
                breaks.append({
                    "line": line_no,
                    "entry_id": "PARSE_ERROR",
                    "segment": seg_name,
                    "expected": "valid JSON object",
                    "actual": "malformed",
                })
                continue

            entry_seq = data.get("seq")
            entry_prev = data.get("previous_hash")
            eid = data.get("entry_id", "UNKNOWN")

            # seq continuity (F1)
            if isinstance(entry_seq, int):
                if prev_seq is None:
                    if entry_seq != 1:
                        breaks.append({
                            "line": line_no, "entry_id": eid,
                            "segment": seg_name,
                            "expected": "seq=1 (genesis) or pruned-prefix tombstone",
                            "actual": f"seq={entry_seq}",
                        })
                elif entry_seq != prev_seq + 1:
                    breaks.append({
                        "line": line_no, "entry_id": eid,
                        "segment": seg_name,
                        "expected": f"seq={prev_seq + 1}",
                        "actual": f"seq={entry_seq}",
                    })

            # back-link (F1)
            expected_prev = self.compute_entry_hash(prev_raw) if prev_raw else None
            if prev_raw is None:
                if entry_prev is not None:
                    breaks.append({
                        "line": line_no, "entry_id": eid,
                        "segment": seg_name,
                        "expected": "null (genesis)",
                        "actual": entry_prev,
                    })
            elif entry_prev != expected_prev:
                breaks.append({
                    "line": line_no, "entry_id": eid,
                    "segment": seg_name,
                    "expected": expected_prev,
                    "actual": entry_prev or "null",
                })

            # writer tag (F3) -- verified only for seq-carrying entries;
            # legacy pre-F1 entries lack seq and were unsigned.
            if isinstance(entry_seq, int):
                try:
                    ent = GovernanceEntry.from_dict(data)
                    if not self.verify_tag(ent):
                        breaks.append({
                            "line": line_no, "entry_id": eid,
                            "segment": seg_name,
                            "expected": "valid writer tag",
                            "actual": data.get("signature"),
                        })
                except (KeyError, TypeError) as e:
                    breaks.append({
                        "line": line_no, "entry_id": eid,
                        "segment": seg_name,
                        "expected": "well-formed entry",
                        "actual": str(e),
                    })

            # anchor agreement (F2)
            if isinstance(entry_seq, int) and entry_seq in anchor_map:
                if self.compute_entry_hash(raw) != anchor_map[entry_seq]:
                    breaks.append({
                        "line": line_no, "entry_id": eid,
                        "segment": seg_name,
                        "expected": f"anchor hash {anchor_map[entry_seq]}",
                        "actual": self.compute_entry_hash(raw),
                    })

            prev_raw = raw
            prev_seq = entry_seq if isinstance(entry_seq, int) else prev_seq

        return len(breaks) == 0, breaks

    def verify_log(
        self,
        anchors: Iterable[dict[str, Any]] | None = None,
    ) -> tuple[bool, list[dict]]:
        """Verify the whole log across all segments in seq order (F1/F2/F3).

        Walks every live and archived segment, orders entries by seq,
        checks continuity + back-links + writer tags, and verifies any
        supplied anchor checkpoints (fetched by the caller from the
        external medium, never through the writer).

        Entries below the lowest present seq that were retention-pruned
        are excused only if covered by a tombstone SYSTEM entry or an
        anchor beyond the gap (cor:gt-retention).
        """
        flat: list[tuple[str, dict | None, str, int]] = []
        for seg in self._iter_segments():
            for i, (raw, data) in enumerate(self._read_segment(seg), start=1):
                flat.append((raw, data, seg.name, i))

        def sort_key(item: tuple[str, dict | None, str, int]) -> tuple[int, str, int]:
            _raw, data, name, ln = item
            if data is None:
                return (10**18, name, ln)
            s = data.get("seq")
            return (s if isinstance(s, int) else 10**18, name, ln)

        flat.sort(key=sort_key)

        ok, breaks = self._verify_entry_sequence(flat, anchors)

        # If the log starts above seq=1, require evidence the prefix was
        # pruned. The excuse is *bound*, not merely present (non-author
        # review 2026-09-25, findings R1-R3 / proposed G7-G9):
        #   - the covering tombstone's pruned_head_hash must equal the
        #     first retained entry's previous_hash (R2/G8);
        #   - a tombstone claiming pruned_through_seq beyond the gap
        #     contradicts the retained log -> fail;
        #   - an anchor at the gap boundary must commit to the pruned
        #     head hash, not merely carry a seq (R3/G9);
        #   - when a boundary anchor exists it is authoritative: a
        #     tombstone contradicting it fails (G7).
        if flat and flat[0][1] is not None:
            first_seq = flat[0][1].get("seq")
            if isinstance(first_seq, int) and first_seq > 1:
                gap_end = first_seq - 1
                first_prev = flat[0][1].get("previous_hash")
                first_loc = (flat[0][3], flat[0][1].get("entry_id"))

                tombstones = [
                    d["tuple_data"] for _r, d, _n, _l in flat
                    if d is not None and d.get("tuple_type") == "SYSTEM"
                    and isinstance(d.get("tuple_data"), dict)
                    and d["tuple_data"].get("action") == "retention_prune"
                ]
                boundary_tombstone = next(
                    (t for t in tombstones
                     if int(t.get("pruned_through_seq") or 0) == gap_end),
                    None,
                )
                overclaim = any(
                    int(t.get("pruned_through_seq") or 0) > gap_end
                    for t in tombstones
                )
                boundary_anchor = next(
                    (a for a in (anchors or [])
                     if int(a.get("seq", -1)) == gap_end),
                    None,
                )

                excused = False
                if overclaim:
                    breaks.insert(0, {
                        "line": flat[0][3],
                        "entry_id": flat[0][1].get("entry_id", "UNKNOWN"),
                        "segment": flat[0][2],
                        "expected": f"tombstone pruned_through_seq <= {gap_end}",
                        "actual": "tombstone claims to have pruned retained entries",
                    })
                elif boundary_anchor is not None:
                    # The external anchor binds the boundary. Its hash must
                    # equal the last pruned entry's hash (= first retained
                    # previous_hash); a disagreeing tombstone also fails.
                    tomb_ok = (
                        boundary_tombstone is None
                        or boundary_tombstone.get("pruned_head_hash") == first_prev
                    )
                    excused = (
                        first_prev is not None
                        and boundary_anchor.get("hash") == first_prev
                        and tomb_ok
                    )
                    if not excused:
                        breaks.insert(0, {
                            "line": flat[0][3],
                            "entry_id": flat[0][1].get("entry_id", "UNKNOWN"),
                            "segment": flat[0][2],
                            "expected": (
                                f"anchor hash/tombstone hash == {first_prev}"
                            ),
                            "actual": (
                                f"anchor hash "
                                f"{boundary_anchor.get('hash')!r}, tombstone "
                                f"{boundary_tombstone.get('pruned_head_hash') if boundary_tombstone else None!r}"
                            ),
                        })
                elif boundary_tombstone is not None:
                    # Agent-adversary scope only (R1 owner decision): with no
                    # boundary anchor, the tombstone still must bind its
                    # recorded head hash to the first retained previous_hash.
                    excused = (
                        first_prev is not None
                        and boundary_tombstone.get("pruned_head_hash")
                        == first_prev
                    )
                    if not excused:
                        breaks.insert(0, {
                            "line": flat[0][3],
                            "entry_id": flat[0][1].get("entry_id", "UNKNOWN"),
                            "segment": flat[0][2],
                            "expected": f"pruned_head_hash == {first_prev}",
                            "actual": (
                                f"tombstone pruned_head_hash "
                                f"{boundary_tombstone.get('pruned_head_hash')!r}"
                            ),
                        })
                else:
                    breaks.insert(0, {
                        "line": flat[0][3],
                        "entry_id": flat[0][1].get("entry_id", "UNKNOWN"),
                        "segment": flat[0][2],
                        "expected": "tombstone or anchor covering pruned prefix",
                        "actual": f"log starts at seq={first_seq} with neither",
                    })

                if excused:
                    breaks = [
                        b for b in breaks
                        if not (
                            b["expected"].startswith("seq=1")
                            or (b["expected"] == "null (genesis)"
                                and (b["line"], b["entry_id"]) == first_loc)
                        )
                    ]

        # Anchors beyond the log tail: a checkpointed entry that is missing
        # means tail truncation since the anchor was published (T2).
        last_seq = 0
        for _r, d, _n, _l in flat:
            if d is not None and isinstance(d.get("seq"), int):
                last_seq = max(last_seq, d["seq"])
        for a in anchors or []:
            if int(a["seq"]) > last_seq:
                breaks.append({
                    "line": 0,
                    "entry_id": "ANCHOR_MISSING",
                    "segment": "",
                    "expected": f"entry seq={a['seq']} anchored at hash {a['hash']}",
                    "actual": f"log tail seq={last_seq}",
                })

        return len(breaks) == 0, breaks

    def verify_chain(self, filepath: Path | None = None) -> tuple[bool, list[dict]]:
        """Verify hash-chain integrity of a single log segment.

        Per-segment view retained for callers that verify one file.
        Under F1 the chain is global: a segment's first entry legitimately
        links back into the previous segment, so line-1 links are only
        checked when the entry is the genesis entry (seq=1 or legacy).

        For the full cross-segment check use verify_log().
        """
        if filepath is None:
            filepath = self._get_current_file()

        if not filepath.exists():
            return True, []

        lines = self._read_segment(filepath)
        entries = [(raw, data, filepath.name, i)
                   for i, (raw, data) in enumerate(lines, start=1)]
        ok, breaks = self._verify_entry_sequence(entries)
        # Per-segment: first entry linking out of the segment is fine
        # unless it is the genesis entry.
        if entries and entries[0][1] is not None:
            first = entries[0][1]
            first_seq = first.get("seq")
            if not (first_seq == 1 or first_seq is None):
                breaks = [b for b in breaks
                          if not (b["line"] == entries[0][3]
                                  and b["expected"] in (
                                      "null (genesis)",
                                      "seq=1 (genesis) or pruned-prefix tombstone",
                                  ))]
        return ok, breaks

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def query_by_intent(
        self,
        intent_id: str,
        tuple_type: (
            Literal["DCTX", "CONTRACT", "EVIDENCE", "ATTEST", "DCT", "SYSTEM"] | None
        ) = None,
        since: str | None = None,
    ) -> Iterator[GovernanceEntry]:
        """Query entries by intent_id."""
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
        """Query entries by task_id."""
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
        files = sorted(self._iter_segments(), reverse=True)

        # One global verification per query instead of per-segment checks:
        # under F1 the chain crosses segment boundaries (T7).
        chain_valid, breaks = self.verify_log()
        if not chain_valid:
            logger.error(
                "%d chain break(s) detected during read -- "
                "governance log may have been tampered with. "
                "error_code=%s breaks=%s",
                len(breaks),
                IDP_E_CHAIN_BROKEN,
                breaks[:3],
            )

        for filepath in files:
            opener = (partial(gzip.open, filepath, "rt", encoding="utf-8")
                      if filepath.suffix == ".gz"
                      else partial(open, filepath, "r", encoding="utf-8"))
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

    # ------------------------------------------------------------------
    # Retention (F9)
    # ------------------------------------------------------------------

    def enforce_retention(self) -> int:
        """Enforce retention: delete expired segments, append a tombstone.

        Covers both live .jsonl segments (never the active file) and
        .jsonl.gz archives (T8 fix: dates parse from the canonical name,
        not the stem). Records the pruned prefix (max removed seq and its
        entry hash) as a writer-tagged SYSTEM tombstone so the gap is
        retention-evident rather than indistinguishable from tampering
        (F9 / cor:gt-retention).

        Returns:
            Number of segments deleted
        """
        if not _is_idp_enabled():
            return 0

        with self._lock:
            return self._enforce_retention_locked()

    def _enforce_retention_locked(self) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        deleted = 0
        last_removed_seq = 0
        last_removed_hash: str | None = None
        active = self._get_current_file()

        # Close the write handle before unlinking: Windows refuses to delete
        # an open file. The next append re-opens via _open_file.
        if self._file_handle is not None and not self._file_handle.closed:
            self._file_handle.close()
            self._file_handle = None

        for filepath in self._iter_segments():
            if filepath == active:
                continue  # never delete the segment being written
            m = _LOG_NAME_RE.match(filepath.name)
            if not m:
                continue
            file_date = datetime(
                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                tzinfo=timezone.utc,
            )
            if file_date >= cutoff:
                continue

            # find the highest-seq entry in the segment for the tombstone
            seg_entries = self._read_segment(filepath)
            for raw, data in seg_entries:
                if data is None:
                    continue
                s = data.get("seq")
                if isinstance(s, int) and s >= last_removed_seq:
                    last_removed_seq = s
                    last_removed_hash = self.compute_entry_hash(raw)
            try:
                filepath.unlink()
                deleted += 1
            except OSError as e:
                logger.warning("Retention delete failed for %s: %s", filepath, e)

        if deleted and not self._poisoned:
            tombstone = GovernanceEntry(
                timestamp="",
                entry_id=self._generate_entry_id(),
                intent_id="system",
                task_id="system",
                tuple_type="SYSTEM",
                tuple_data={
                    "action": "retention_prune",
                    "pruned_segments": deleted,
                    "pruned_through_seq": last_removed_seq,
                    "pruned_head_hash": last_removed_hash,
                },
            )
            with self._lock:
                self._write_entries([tombstone])

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
