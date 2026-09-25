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

"""Observer O -- F7 (observer evidence).

F7: EVIDENCE entries and artifact witnesses w(a) = (id_a, H(a), ref_R)
are emitted by observer O and tagged under a symmetric HMAC key K_O.
K_O is not a private key -- thm:gt-phantom assumes an HMAC. No agent
holds K_O: the observer and the verifier share it; agents submit claims
and evidence through the writer API unkeyed.

Shapes:
  witness  = {artifact_id, artifact_hash, ref, observer_id, ts,
              observer_tag}  -- tag over canon(all fields sans tag)
  evidence = {actor, task_id, ops_executed, resources_accessed,
              t_start, t_end, ..., observer_tag}
  claim    = {artifact_id, artifact_digest, claimed_at, agent}
              (agent-posted; writer-tagged on the bus)

Phantom detection (thm:gt-phantom): a claim is flagged unless a witness
exists with a valid K_O tag, matching artifact_id and artifact digest,
and |w.ts - claim.claimed_at| <= tau.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from reference_impl.delegation_token import _canonical_json

IDP_E_OBSERVER_TAG = "IDP_E_OBSERVER_TAG"

OBSERVER_KEY_ENV = "GT_OBSERVER_KEY"
OBSERVER_KEY_FILENAME = ".observer_key"

_TAG_KEYS = ("observer_tag", "signature")


def _parse_iso(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _tagged_fields(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k not in _TAG_KEYS}


def observer_tag_for(key: bytes, record: dict[str, Any]) -> str:
    """HMAC_{K_O}(canon(record sans tag fields))."""
    return hmac.new(key, _canonical_json(_tagged_fields(record)),
                    hashlib.sha256).hexdigest()


class Observer:
    """The O principal. Holds K_O; agents never see it.

    Key resolution order: explicit ``key`` > ``GT_OBSERVER_KEY`` (hex) >
    persisted ``<base_dir>/.observer_key`` (0600) > generated ephemeral.
    """

    def __init__(
        self,
        observer_id: str = "observer",
        key: bytes | None = None,
        base_dir: Path | str | None = None,
    ):
        self.observer_id = observer_id
        self.key = self._resolve_key(key, base_dir)

    @staticmethod
    def _resolve_key(key: bytes | None, base_dir) -> bytes:
        if key is not None:
            return key
        env = os.environ.get(OBSERVER_KEY_ENV)
        if env:
            return bytes.fromhex(env)
        if base_dir is not None:
            path = Path(base_dir) / OBSERVER_KEY_FILENAME
            if path.exists():
                return bytes.fromhex(path.read_text(encoding="utf-8").strip())
            path.parent.mkdir(parents=True, exist_ok=True)
            generated = os.urandom(32)
            path.write_text(generated.hex(), encoding="utf-8")
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return generated
        return os.urandom(32)

    # ---- tagging ----------------------------------------------------

    def tag(self, record: dict[str, Any]) -> str:
        return observer_tag_for(self.key, record)

    def verify(self, record: dict[str, Any]) -> bool:
        tag = record.get("observer_tag")
        if not tag:
            return False
        return hmac.compare_digest(str(tag), self.tag(record))

    # ---- emission ---------------------------------------------------

    def emit_witness(
        self,
        artifact_id: str,
        artifact_hash: str,
        ref: str,
        ts: str | None = None,
    ) -> dict[str, Any]:
        """w(a) = (id_a, H(a), ref_R), O-tagged."""
        w = {
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "ref": ref,
            "observer_id": self.observer_id,
            "ts": ts or _utcnow(),
        }
        w["observer_tag"] = self.tag(w)
        return w

    def emit_evidence(
        self,
        actor: str,
        task_id: str,
        ops_executed: list[str],
        resources_accessed: list[dict[str, Any]] | None = None,
        t_start: str | None = None,
        t_end: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """An EVIDENCE tuple_data dict tagged under K_O (condition-8 O path)."""
        e = {
            "actor": actor,
            "task_id": task_id,
            "ops_executed": list(ops_executed),
            "resources_accessed": list(resources_accessed or []),
            "t_start": t_start or _utcnow(),
            "t_end": t_end or _utcnow(),
            "observer_id": self.observer_id,
            **extra,
        }
        e["observer_tag"] = self.tag(e)
        return e


# ----------------------------------------------------------------------
# Phantom-delivery detection (thm:gt-phantom)
# ----------------------------------------------------------------------

def flag_phantoms(
    claims: Iterable[dict[str, Any]],
    witnesses: Iterable[dict[str, Any]],
    observer_key: bytes,
    tau_seconds: float,
) -> list[tuple[dict[str, Any], str]]:
    """Flag claims without a covering O-tagged witness.

    A claim {artifact_id, artifact_digest, claimed_at} is covered iff some
    witness has: matching artifact_id, artifact_hash == artifact_digest,
    a valid K_O tag, and |w.ts - claim.claimed_at| <= tau_seconds.

    Sound: an agent cannot satisfy coverage without O having emitted the
    witness (EUF-CMA HMAC). Complete: a truthful claim observed within
    tau is covered.

    Returns [(claim, reason)] for each flagged claim; reasons:
      no_witness, hash_mismatch, tag_invalid, outside_tau.
    """
    tagged_witnesses = [w for w in witnesses
                        if isinstance(w, dict)]
    flagged: list[tuple[dict[str, Any], str]] = []
    for claim in claims:
        cid = claim.get("artifact_id")
        cdigest = claim.get("artifact_digest")
        cts = _parse_iso(claim.get("claimed_at"))

        candidates = [w for w in tagged_witnesses
                      if w.get("artifact_id") == cid]
        if not candidates:
            flagged.append((claim, "no_witness"))
            continue
        digest_ok = [w for w in candidates
                     if w.get("artifact_hash") == cdigest]
        if not digest_ok:
            flagged.append((claim, "hash_mismatch"))
            continue
        tag_ok = [
            w for w in digest_ok
            if hmac.compare_digest(
                str(w.get("observer_tag") or ""),
                observer_tag_for(observer_key, w),
            )
        ]
        if not tag_ok:
            flagged.append((claim, "tag_invalid"))
            continue
        covered = False
        if cts is not None:
            for w in tag_ok:
                wts = _parse_iso(w.get("ts"))
                if wts is not None and abs(
                        (wts - cts).total_seconds()) <= tau_seconds:
                    covered = True
                    break
        if not covered:
            flagged.append((claim, "outside_tau"))
    return flagged
