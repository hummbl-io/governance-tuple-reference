#!/usr/bin/env python3
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

"""Standalone hash-chain verification for governance logs.

Usage:
    python verify_chain.py <logfile.jsonl>
    python verify_chain.py <log-dir>            # verifies the whole log
    python verify_chain.py <log-dir> --anchors checkpoints.jsonl

Under the F1 global chain the log is one sequence across daily segments
and write-once archives. Directory mode orders every entry by seq and
verifies continuity and back-links end to end; a directory containing a
retention-pruned prefix verifies only if a tombstone SYSTEM entry covers
the gap. Optional --anchors is a JSONL file of {seq, hash, ts} records
fetched from the external checkpoint medium; anchor disagreement or a
missing anchored entry fails verification (T2 tail-truncation).

Writer tags are verified only when GT_BUS_WRITER_KEY is set; tag checking
requires the writer's symmetric key and is otherwise skipped (off-line
verifiers still get structural seq/link verification).

Exit codes:
    0 -- chain is valid (or target is empty)
    1 -- chain has breaks (tamper detected)
    2 -- path error (missing, unreadable)
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

GENESIS_SEQ = 1


def compute_entry_hash(jsonl_line: str) -> str:
    """Compute SHA-256 hash of a JSONL entry line."""
    return hashlib.sha256(jsonl_line.encode("utf-8")).hexdigest()


def _tag_payload(data: dict) -> bytes:
    """Reconstruct the canonical MAC payload (entry sans signature)."""
    out = {
        "timestamp": data.get("timestamp"),
        "entry_id": data.get("entry_id"),
        "intent_id": data.get("intent_id"),
        "task_id": data.get("task_id"),
        "tuple_type": data.get("tuple_type"),
        "tuple_data": data.get("tuple_data"),
        "state": data.get("state", "ok"),
        "drift": data.get("drift", 0.0),
    }
    for f in ("contract_id", "capability_token_id", "verification_id",
              "amendment_of", "previous_hash", "seq"):
        if data.get(f) is not None:
            out[f] = data[f]
    return json.dumps(out, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_segments(target: Path) -> tuple[list[Path], int]:
    """Resolve target to log segments. Returns (paths, exit_status)."""
    if target.is_dir():
        segs = sorted(
            p for p in target.glob("governance-*.jsonl*")
        )
        return segs, 0
    if target.exists():
        return [target], 0
    print(f"Error: path not found: {target}", file=sys.stderr)
    return [], 2


def verify_entries(
    rows: list[tuple[str, dict | None, str, int]],
    anchors: list[dict] | None = None,
    writer_key: bytes | None = None,
) -> tuple[bool, list[dict]]:
    """Verify an ordered entry list: seq continuity, back-links, tags, anchors."""
    breaks: list[dict] = []
    prev_raw: str | None = None
    prev_seq: int | None = None
    anchor_map = {int(a["seq"]): a["hash"] for a in (anchors or [])}

    for raw, data, seg_name, line_no in rows:
        if data is None or not isinstance(data, dict):
            breaks.append({
                "line": line_no, "entry_id": "PARSE_ERROR", "segment": seg_name,
                "expected": "valid JSON object", "actual": "malformed",
            })
            continue

        entry_seq = data.get("seq")
        entry_prev = data.get("previous_hash")
        eid = data.get("entry_id", "UNKNOWN")

        if isinstance(entry_seq, int):
            if prev_seq is None:
                if entry_seq != GENESIS_SEQ:
                    breaks.append({
                        "line": line_no, "entry_id": eid, "segment": seg_name,
                        "expected": "seq=1 (genesis) or pruned-prefix tombstone",
                        "actual": f"seq={entry_seq}",
                    })
            elif entry_seq != prev_seq + 1:
                breaks.append({
                    "line": line_no, "entry_id": eid, "segment": seg_name,
                    "expected": f"seq={prev_seq + 1}", "actual": f"seq={entry_seq}",
                })

        expected_prev = compute_entry_hash(prev_raw) if prev_raw else None
        if prev_raw is None:
            if entry_prev is not None:
                breaks.append({
                    "line": line_no, "entry_id": eid, "segment": seg_name,
                    "expected": "null (genesis)", "actual": entry_prev,
                })
        elif entry_prev != expected_prev:
            breaks.append({
                "line": line_no, "entry_id": eid, "segment": seg_name,
                "expected": expected_prev, "actual": entry_prev or "null",
            })

        if writer_key is not None and isinstance(entry_seq, int):
            tag = data.get("signature")
            good = tag is not None and hmac.compare_digest(
                tag, hmac.new(writer_key, _tag_payload(data), hashlib.sha256).hexdigest()
            )
            if not good:
                breaks.append({
                    "line": line_no, "entry_id": eid, "segment": seg_name,
                    "expected": "valid writer tag", "actual": tag,
                })

        if isinstance(entry_seq, int) and entry_seq in anchor_map:
            actual_hash = compute_entry_hash(raw)
            if actual_hash != anchor_map[entry_seq]:
                breaks.append({
                    "line": line_no, "entry_id": eid, "segment": seg_name,
                    "expected": f"anchor hash {anchor_map[entry_seq]}",
                    "actual": actual_hash,
                })

        prev_raw = raw
        if isinstance(entry_seq, int):
            prev_seq = entry_seq

    return len(breaks) == 0, breaks


def verify_path(
    target: Path,
    anchors: list[dict] | None = None,
    writer_key: bytes | None = None,
) -> tuple[bool, list[dict], int]:
    """Verify a log file or directory. Returns (valid, breaks, n_entries)."""
    segments, status = _load_segments(target)
    if status != 0:
        return False, [{"line": 0, "entry_id": "FILE_ERROR",
                        "expected": "existing path", "actual": str(target)}], 0
    if not segments:
        return True, [], 0

    rows: list[tuple[str, dict | None, str, int]] = []
    for seg in segments:
        opener = gzip.open if seg.suffix == ".gz" else open
        try:
            with opener(seg, "rt", encoding="utf-8") as f:  # noqa: SIM115
                for i, raw in enumerate(f, start=1):
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        rows.append((line, json.loads(line), seg.name, i))
                    except json.JSONDecodeError:
                        rows.append((line, None, seg.name, i))
        except (IOError, OSError) as e:
            return False, [{"line": 0, "entry_id": "FILE_ERROR",
                            "expected": "readable file",
                            "actual": f"{seg.name}: {e}"}], 0

    def _key(item: tuple[str, dict | None, str, int]) -> tuple[int, str, int]:
        _r, d, name, ln = item
        s = d.get("seq") if isinstance(d, dict) else None
        return (s if isinstance(s, int) else 10**18, name, ln)

    rows.sort(key=_key)
    ok, breaks = verify_entries(rows, anchors=anchors, writer_key=writer_key)

    if rows and rows[0][1] is not None:
        first_seq = rows[0][1].get("seq")
        if isinstance(first_seq, int) and first_seq > GENESIS_SEQ:
            tombstone_ok = any(
                d is not None and d.get("tuple_type") == "SYSTEM"
                and isinstance(d.get("tuple_data"), dict)
                and d["tuple_data"].get("action") == "retention_prune"
                and int(d["tuple_data"].get("pruned_through_seq") or 0) >= first_seq - 1
                for _r, d, _n, _l in rows
            )
            anchor_ok = any(
                int(a["seq"]) >= first_seq - 1 for a in (anchors or [])
            )
            if tombstone_ok or anchor_ok:
                first_loc = (rows[0][3], rows[0][1].get("entry_id"))
                breaks = [
                    b for b in breaks
                    if not (
                        str(b["expected"]).startswith("seq=1")
                        or (b["expected"] == "null (genesis)"
                            and (b["line"], b["entry_id"]) == first_loc)
                    )
                ]
            else:
                breaks.insert(0, {
                    "line": rows[0][3],
                    "entry_id": rows[0][1].get("entry_id", "UNKNOWN"),
                    "segment": rows[0][2],
                    "expected": "tombstone or anchor covering pruned prefix",
                    "actual": f"log starts at seq={first_seq} with neither",
                })

    last_seq = max(
        (d["seq"] for _r, d, _n, _l in rows
         if isinstance(d, dict) and isinstance(d.get("seq"), int)),
        default=0,
    )
    for a in anchors or []:
        if int(a["seq"]) > last_seq:
            breaks.append({
                "line": 0, "entry_id": "ANCHOR_MISSING", "segment": "",
                "expected": f"entry seq={a['seq']} anchored at hash {a['hash']}",
                "actual": f"log tail seq={last_seq}",
            })

    return len(breaks) == 0, breaks, sum(1 for _r, d, _n, _l in rows if d is not None)


def main() -> int:
    argv = sys.argv[1:]
    anchors: list[dict] = []
    if "--anchors" in argv:
        idx = argv.index("--anchors")
        try:
            anchors_path = Path(argv[idx + 1])
        except IndexError:
            print("Error: --anchors requires a JSONL path", file=sys.stderr)
            return 2
        del argv[idx:idx + 2]
        try:
            with open(anchors_path, "r", encoding="utf-8") as f:
                anchors = [json.loads(l) for l in f if l.strip()]
        except (OSError, json.JSONDecodeError) as e:
            print(f"Error: cannot load anchors: {e}", file=sys.stderr)
            return 2
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1:
        print("Usage: python verify_chain.py <logfile-or-dir> [--anchors checkpoints.jsonl]",
              file=sys.stderr)
        return 2

    writer_key: bytes | None = None
    env_key = os.environ.get("GT_BUS_WRITER_KEY")
    if env_key:
        writer_key = bytes.fromhex(env_key)
    elif args and Path(args[0]).is_dir():
        key_file = Path(args[0]) / ".writer_key"
        if key_file.exists():
            writer_key = bytes.fromhex(key_file.read_text(encoding="utf-8").strip())

    valid, breaks, n = verify_path(Path(args[0]), anchors=anchors, writer_key=writer_key)

    if valid:
        print(f"OK: hash chain valid ({n} entries verified across "
              f"{len(_load_segments(Path(args[0]))[0])} segment(s))")
        return 0
    print(f"FAIL: hash chain broken ({len(breaks)} break(s))")
    for b in breaks:
        seg = f"{b.get('segment')}:" if b.get("segment") else ""
        print(f"  {seg}line {b['line']}: entry_id={b['entry_id']} "
              f"expected={b['expected']} actual={b['actual']}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
