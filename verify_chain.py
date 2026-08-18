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

"""Standalone hash-chain verification script for governance log files.

Usage:
    python verify_chain.py <logfile.jsonl>

Walks every JSONL entry in order and confirms each entry's previous_hash
matches the SHA-256 of the prior entry's canonical JSONL line. Reports
all chain breaks found.

Exit codes:
    0 -- chain is valid (or file is empty)
    1 -- chain has breaks (tamper detected)
    2 -- file error (missing, unreadable)
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def compute_entry_hash(jsonl_line: str) -> str:
    """Compute SHA-256 hash of a JSONL entry line."""
    return hashlib.sha256(jsonl_line.encode("utf-8")).hexdigest()


def verify_chain(filepath: Path) -> tuple[bool, list[dict]]:
    """Verify hash-chain integrity of a governance log file.

    Walks every entry in order and confirms each entry's previous_hash
    matches the SHA-256 of the prior entry's canonical JSONL. Reports
    all breaks found.

    Args:
        filepath: Log file to verify.

    Returns:
        Tuple of (chain_valid, breaks) where breaks is a list of dicts:
        [{"line": int, "entry_id": str, "expected": str, "actual": str}]
    """
    if not filepath.exists():
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        return False, [{"line": 0, "entry_id": "FILE_ERROR", "expected": "existing file", "actual": str(filepath)}]

    breaks: list[dict] = []
    prev_line: str | None = None
    line_num = 0
    total_entries = 0

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for raw_line in f:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                line_num += 1
                total_entries += 1

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
                    # Genesis entry: previous_hash should be None
                    if entry_prev_hash is not None:
                        breaks.append({
                            "line": 1,
                            "entry_id": data.get("entry_id", "UNKNOWN"),
                            "expected": "null (genesis)",
                            "actual": entry_prev_hash,
                        })
                else:
                    # Non-genesis: previous_hash must match hash of prior line
                    expected_hash = compute_entry_hash(prev_line) if prev_line else None
                    if entry_prev_hash != expected_hash:
                        breaks.append({
                            "line": line_num,
                            "entry_id": data.get("entry_id", "UNKNOWN"),
                            "expected": expected_hash or "null",
                            "actual": entry_prev_hash or "null",
                        })

                prev_line = stripped

    except (IOError, OSError) as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return False, [{"line": 0, "entry_id": "FILE_ERROR", "expected": "readable file", "actual": str(e)}]

    return len(breaks) == 0, breaks


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python verify_chain.py <logfile.jsonl>", file=sys.stderr)
        return 2

    filepath = Path(sys.argv[1])

    if not filepath.exists():
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        return 2

    chain_valid, breaks = verify_chain(filepath)

    if chain_valid:
        print(f"OK: hash chain valid ({len(breaks)} breaks in {filepath.name})")
        # Count entries
        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        print(f"    {count} entries verified")
        return 0
    else:
        print(f"FAIL: hash chain broken ({len(breaks)} break(s) in {filepath.name})")
        for b in breaks:
            print(f"  line {b['line']}: entry_id={b['entry_id']} "
                  f"expected={b['expected']} actual={b['actual']}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
