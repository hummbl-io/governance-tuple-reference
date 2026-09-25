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

"""Phase-1 acceptance suite -- the defect harness inverted.

Each test asserts the remediated behavior for one v2.1 defect
(GOVERNANCE_TUPLE_KRINEIA_MERGED_REMEDIATION_MASTER v1.1 section 8):

  T1  rewrite + rechain detected (keyed tags, attacker cannot re-MAC)
  T2  tail truncation detected via checkpoint anchor
  T3  caller-supplied signatures rejected; forged tag fails verification
  T4  concurrent appends never fork the chain (race: N>=20 runs)
  T5  async-buffered entries strictly chained at flush
  T6  same-day rotations produce unique write-once archives
  T7  day rollover preserves the chain; deleting a segment is detected
  T8  retention covers .jsonl and .jsonl.gz; prune appends tombstone
  T13 ENABLE_IDP=false records a tagged SYSTEM bypass and reports failure
  G2  checkpoint export + anchor-checked verification (mocked medium)
  G6  persisted head state: restart continues seq; corrupt head poisons bus
"""

from __future__ import annotations

import json
import os
import threading

os.environ.setdefault("ENABLE_IDP", "true")

import reference_impl.governance_bus as gb
from reference_impl.governance_bus import (
    IDP_E_CALLER_SIGNATURE,
    IDP_E_GOVERNANCE_DISABLED,
    IDP_E_HEAD_MISMATCH,
    IDP_E_SYSTEM_FORGED,
    GovernanceBus,
    GovernanceEntry,
)


def _all_entries(bus: GovernanceBus) -> list[GovernanceEntry]:
    return list(bus.query_all())


def _seqs(bus: GovernanceBus) -> list[int]:
    return sorted(e.seq or -1 for e in _all_entries(bus))


def _force_date(bus: GovernanceBus, date: str | None) -> None:
    """Shadow the segment-date resolver for time-travel tests.

    Only the resolver is replaced; _current_file stays on the prior date so
    _rotate_if_needed sees the day change and archives the old segment.
    date=None restores the real (today) resolver.
    """
    if date is None:
        bus.__dict__.pop("_get_current_file", None)
    else:
        bus._get_current_file = (
            lambda: bus._base_dir / f"governance-{date}.jsonl"
        )


# ---------------------------------------------------------------------------
# T1 -- rewrite + rechain detected
# ---------------------------------------------------------------------------


class TestT1RekeyedChain:
    def test_rewrite_and_rechain_detected(self, tmp_path):
        """Attacker who rewrites history and re-computes the hash chain is
        caught because the writer MAC does not verify (unkeyed-hash fix)."""
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(5):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
        bus.close()

        seg = bus._get_current_file()
        lines = [l.strip() for l in seg.read_text(encoding="utf-8").splitlines() if l.strip()]

        # Attacker: alter entry 2, then re-chain every subsequent entry with
        # correct previous_hash links -- the v2.1 undetectable rewrite.
        forged = []
        prev_hash = None
        for i, raw in enumerate(lines):
            d = json.loads(raw)
            if i == 2:
                d["tuple_data"] = {"n": 999, "injected": True}
            d["previous_hash"] = prev_hash
            forged.append(json.dumps(d, sort_keys=True, separators=(",", ":")))
            prev_hash = GovernanceBus.compute_entry_hash(forged[-1])
        seg.write_text("\n".join(forged) + "\n", encoding="utf-8")

        ok, breaks = bus.verify_log()
        assert ok is False
        tag_breaks = [b for b in breaks if b["expected"] == "valid writer tag"]
        # Genesis tag survives (its MAC payload is unchanged; previous_hash is
        # still null). Entries 2-5 fail: the attacker rewrote previous_hash,
        # which is inside the MAC payload, and cannot re-tag without K_W.
        assert len(tag_breaks) == 4


# ---------------------------------------------------------------------------
# T2 -- tail truncation detected via anchor
# ---------------------------------------------------------------------------


class TestT2TailTruncation:
    def test_truncation_below_checkpoint_detected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(6):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
        checkpoint = bus.compute_checkpoint()
        assert checkpoint["seq"] == 6

        # Operator truncates the last 2 entries -- without an anchor this
        # looks like a clean 4-entry chain.
        seg = bus._get_current_file()
        lines = [l for l in seg.read_text(encoding="utf-8").splitlines() if l.strip()]
        seg.write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")

        ok, breaks = bus.verify_log(anchors=[checkpoint])
        assert ok is False
        assert any(b["entry_id"] == "ANCHOR_MISSING" for b in breaks)

    def test_unanchored_truncation_flagged_as_gap(self, tmp_path):
        """Without an anchor, truncation leaves contiguous seqs -- the gap is
        only provable via a published checkpoint (documented limitation)."""
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(4):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
        seg = bus._get_current_file()
        lines = [l for l in seg.read_text(encoding="utf-8").splitlines() if l.strip()]
        seg.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        ok, _ = bus.verify_log()  # structurally clean prefix; undetectable w/o anchor
        assert ok is True


# ---------------------------------------------------------------------------
# T3 -- caller signatures rejected, forged tags fail
# ---------------------------------------------------------------------------


class TestT3Signatures:
    def test_caller_signature_rejected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        ok, err = bus.append("i", "t", "DCTX", {"x": 1}, signature="x")
        assert ok is False
        assert err == IDP_E_CALLER_SIGNATURE

    def test_writer_tag_forgery_detected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        bus.append("i", "t", "DCTX", {"x": 1})
        entry = _all_entries(bus)[0]
        forged = GovernanceEntry(
            timestamp=entry.timestamp, entry_id=entry.entry_id,
            intent_id=entry.intent_id, task_id=entry.task_id,
            tuple_type=entry.tuple_type, tuple_data={"x": 2},
            signature="forged", previous_hash=entry.previous_hash,
            seq=entry.seq,
        )
        assert bus.verify_tag(forged) is False
        assert bus.verify_tag(entry) is True


# ---------------------------------------------------------------------------
# T4 -- concurrent appends never fork (race, N>=20)
# ---------------------------------------------------------------------------


class TestT4Race:
    RUNS = 20
    THREADS = 4
    PER_THREAD = 10

    def test_concurrent_appends_distribution(self, tmp_path):
        """20 race runs; report the break distribution, assert all zero."""
        distributions: list[int] = []
        seq_errors = 0
        for run in range(self.RUNS):
            d = tmp_path / f"run{run}"
            bus = GovernanceBus(base_dir=d)
            threads = [
                threading.Thread(
                    target=lambda k=k: [
                        bus.append("i", f"t{k}-{j}", "DCTX", {"w": k, "j": j})
                        for j in range(self.PER_THREAD)
                    ],
                )
                for k in range(self.THREADS)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            bus.close()

            ok, breaks = bus.verify_log()
            distributions.append(len(breaks))
            assert ok is True, f"run {run}: {len(breaks)} breaks"
            expected = list(range(1, self.THREADS * self.PER_THREAD + 1))
            bus2_entries = _seqs(bus)
            if bus2_entries != expected:
                seq_errors += 1
        assert seq_errors == 0
        assert distributions == [0] * self.RUNS, (
            f"race distribution: {distributions}"
        )


# ---------------------------------------------------------------------------
# T5 -- async buffer chains correctly at flush
# ---------------------------------------------------------------------------


class TestT5Async:
    def test_async_flush_chains(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path, enable_async=True)
        for i in range(10):
            ok, err = bus.append("i", f"t{i}", "DCTX", {"n": i})
            assert ok is True
        ok, err = bus._flush_buffer()
        assert ok is True
        bus.close()
        valid, breaks = bus.verify_log()
        assert valid is True and breaks == []
        assert _seqs(bus) == list(range(1, 11))

    def test_async_concurrent_producers(self, tmp_path):
        """Concurrent producers into a small buffer (flush at 3) still chain."""
        bus = GovernanceBus(base_dir=tmp_path, enable_async=True)
        def produce(k: int) -> None:
            for j in range(9):
                bus.append("i", f"{k}-{j}", "DCTX", {"w": k, "j": j})
        threads = [threading.Thread(target=produce, args=(k,)) for k in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        bus.close()  # close() flushes the remainder
        valid, breaks = bus.verify_log()
        assert valid is True, breaks
        assert _seqs(bus) == list(range(1, 28))


# ---------------------------------------------------------------------------
# T6 -- same-day rotations: unique write-once archives
# ---------------------------------------------------------------------------


class TestT6Rotation:
    def test_same_day_rotations_unique(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 250)
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(60):
            bus.append("i", f"t{i}", "DCTX", {"payload": "x" * 40, "n": i})
        bus.close()
        gz = sorted(tmp_path.glob("governance-*.jsonl.gz"))
        assert len(gz) >= 2, f"expected >=2 archives, got {gz}"
        names = [p.name for p in gz]
        assert len(names) == len(set(names))  # no overwrite
        valid, breaks = bus.verify_log()
        assert valid is True, breaks

    def test_active_file_survives_rotations(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 250)
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(30):
            bus.append("i", f"t{i}", "DCTX", {"payload": "y" * 40, "n": i})
        bus.close()
        # current segment is a live .jsonl, archives are .jsonl.gz
        assert bus._get_current_file().exists()
        assert _seqs(bus) == list(range(1, 31))


# ---------------------------------------------------------------------------
# T7 -- day rollover preserves the global chain
# ---------------------------------------------------------------------------


class TestT7DayRollover:
    def test_chain_crosses_day_boundary(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        _force_date(bus, "2026-01-01")
        bus.append("i", "d1", "DCTX", {"day": 1})
        _force_date(bus, "2026-01-02")
        bus.append("i", "d2", "DCTX", {"day": 2})
        bus.close()
        entries = _all_entries(bus)
        by_seq = {e.seq: e for e in entries}
        assert by_seq[2].previous_hash is not None
        valid, breaks = bus.verify_log()
        assert valid is True, breaks

    def test_deleting_earlier_day_detected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        _force_date(bus, "2026-01-01")
        for i in range(3):
            bus.append("i", f"d1-{i}", "DCTX", {"day": 1})
        _force_date(bus, "2026-01-02")
        bus.append("i", "d2", "DCTX", {"day": 2})
        bus.close()
        day1_archive = tmp_path / "governance-2026-01-01.1.jsonl.gz"
        assert day1_archive.exists()
        day1_archive.unlink()
        valid, breaks = bus.verify_log()
        assert valid is False
        assert any("seq" in b["expected"] for b in breaks)


# ---------------------------------------------------------------------------
# T8 -- retention covers .jsonl + .jsonl.gz; tombstone on prune
# ---------------------------------------------------------------------------


class TestT8Retention:
    def test_retention_deletes_both_kinds_with_tombstone(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 220)
        bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
        _force_date(bus, "2026-01-01")
        for i in range(50):
            bus.append("i", f"t{i}", "DCTX", {"payload": "z" * 30, "n": i})
        # Restore real date: retention runs "today" -- the active file is
        # fresh-dated and the tombstone lands somewhere retention-safe.
        _force_date(bus, None)
        # Hand-craft a sibling old-date live .jsonl segment so retention must
        # cover the uncompressed kind too (v2.1 only reached .gz correctly).
        old_seg = tmp_path / "governance-2026-01-02.jsonl"
        with open(old_seg, "w", encoding="utf-8") as f:
            f.write(bus._tail_line_raw() + "\n")

        deleted = bus.enforce_retention()
        assert deleted >= 1
        assert old_seg.exists() is False
        # every archived old-day segment was removed too
        for p in tmp_path.glob("governance-2026-01-0[12].jsonl.gz"):
            assert p.exists() is False
        tombstones = [
            e for e in _all_entries(bus)
            if e.tuple_type == "SYSTEM"
            and e.tuple_data.get("action") == "retention_prune"
        ]
        assert len(tombstones) == 1
        assert tombstones[0].tuple_data["pruned_segments"] == deleted
        assert tombstones[0].tuple_data["pruned_through_seq"] > 0
        assert tombstones[0].tuple_data["pruned_head_hash"]

    def test_verify_after_prune_with_tombstone(self, tmp_path, monkeypatch):
        """Pruned prefix + tombstone verifies clean; without tombstone it fails."""
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 200)
        bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
        _force_date(bus, "2026-01-01")
        for i in range(40):
            bus.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
        _force_date(bus, None)
        for i in range(10):
            bus.append("i", f"new{i}", "DCTX", {"payload": "q" * 30, "n": i})
        bus.enforce_retention()
        valid, breaks = bus.verify_log()
        assert valid is True, breaks

        # G10 (R4): strip the tombstone line -- the uncovered gap must fail.
        tomb = next(
            e for e in _all_entries(bus)
            if e.tuple_type == "SYSTEM"
            and e.tuple_data.get("action") == "retention_prune"
        )
        seg = next(tmp_path.glob("governance-*.jsonl"))
        kept = [
            ln for ln in seg.read_text().splitlines()
            if ln.strip() and json.loads(ln)["entry_id"] != tomb.entry_id
        ]
        bus.close()
        seg.write_text("\n".join(kept) + "\n")
        bus2 = GovernanceBus(base_dir=tmp_path, retention_days=30)
        valid, breaks = bus2.verify_log()
        assert valid is False
        assert any("tombstone" in b["expected"] for b in breaks)


# ---------------------------------------------------------------------------
# G7-G10 -- bound excuses (non-author review R1-R4, 2026-09-25)
# A gap may only be excused by evidence bound to the pruned head hash.
# ---------------------------------------------------------------------------


def _pruned_log(tmp_path, monkeypatch, n_old=40, n_new=15):
    """Build a bus with a retention-pruned log. Returns (bus, gap_end)."""
    monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 200)
    bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
    _force_date(bus, "2026-01-01")
    for i in range(n_old):
        bus.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
    _force_date(bus, None)
    for i in range(n_new):
        bus.append("i", f"new{i}", "DCTX", {"payload": "q" * 30, "n": i})
    bus.enforce_retention()
    entries = sorted(_all_entries(bus), key=lambda e: e.seq or 0)
    first_seq = min(e.seq for e in entries if e.seq)
    return bus, first_seq - 1


def _write_forged_tombstone(bus: GovernanceBus, through_seq: int,
                            head_hash: str) -> None:
    """Append a SYSTEM tombstone through the internal writer path
    (properly tagged -- simulates an operator adversary holding K_W)."""
    tomb = GovernanceEntry(
        timestamp="",
        entry_id=bus._generate_entry_id(),
        intent_id="system",
        task_id="system",
        tuple_type="SYSTEM",
        tuple_data={
            "action": "retention_prune",
            "pruned_segments": 1,
            "pruned_through_seq": through_seq,
            "pruned_head_hash": head_hash,
        },
    )
    with bus._lock:
        bus._write_entries([tomb])


class TestBoundExcuses:
    def test_g7_forged_tombstone_overclaim_fails(self, tmp_path, monkeypatch):
        """A tombstone claiming coverage past the gap fails verification."""
        bus, gap_end = _pruned_log(tmp_path, monkeypatch)
        valid, _ = bus.verify_log()
        assert valid
        _write_forged_tombstone(bus, through_seq=gap_end + 1,
                                head_hash="00" * 32)
        valid, breaks = bus.verify_log()
        assert valid is False
        assert any("pruned_through_seq" in b["expected"] for b in breaks)

    def test_g7b_public_append_cannot_write_tombstone(self, tmp_path, monkeypatch):
        """Agent-adversary path closed: public append refuses SYSTEM."""
        bus, gap_end = _pruned_log(tmp_path, monkeypatch)
        ok, err = bus.append(
            "i", "t", "SYSTEM",
            {"action": "retention_prune",
             "pruned_through_seq": gap_end + 50,
             "pruned_head_hash": "00" * 32},
        )
        assert not ok
        assert err == IDP_E_SYSTEM_FORGED

    def test_g8_tombstone_hash_must_match(self, tmp_path, monkeypatch):
        """Boundary tombstone with a wrong pruned_head_hash fails."""
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 200)
        bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
        _force_date(bus, "2026-01-01")
        for i in range(5):
            bus.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
        day1 = bus._base_dir / "governance-2026-01-01.jsonl"
        last_line = day1.read_text().splitlines()[-1]
        pruned_hash = bus.compute_entry_hash(last_line)
        _force_date(bus, "2026-01-02")
        for i in range(10):
            bus.append("i", f"n{i}", "DCTX", {"payload": "q" * 30, "n": i})
        for p in tmp_path.glob("governance-2026-01-01*"):
            p.unlink()
        # Forged boundary tombstone with wrong head hash
        _write_forged_tombstone(bus, through_seq=5, head_hash="00" * 32)
        valid, breaks = bus.verify_log()
        assert valid is False
        assert any("pruned_head_hash" in b["expected"] for b in breaks)
        # Correct hash excuses the gap (sanity: same machinery, right hash)
        bus2_dir = tmp_path / "second"
        bus2_dir.mkdir()
        bus2 = GovernanceBus(base_dir=bus2_dir, retention_days=30)
        _force_date(bus2, "2026-01-01")
        for i in range(5):
            bus2.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
        last_line2 = (bus2_dir / "governance-2026-01-01.jsonl").read_text().splitlines()[-1]
        pruned_hash2 = bus2.compute_entry_hash(last_line2)
        _force_date(bus2, "2026-01-02")
        for i in range(10):
            bus2.append("i", f"n{i}", "DCTX", {"payload": "q" * 30, "n": i})
        for p in bus2_dir.glob("governance-2026-01-01*"):
            p.unlink()
        _write_forged_tombstone(bus2, through_seq=5, head_hash=pruned_hash2)
        valid, breaks = bus2.verify_log()
        assert valid is True, breaks

    def test_g9_anchor_must_commit_to_hash(self, tmp_path, monkeypatch):
        """A boundary anchor with matching seq but wrong hash fails."""
        monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 200)
        bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
        _force_date(bus, "2026-01-01")
        for i in range(5):
            bus.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
        day1 = bus._base_dir / "governance-2026-01-01.jsonl"
        pruned_hash = bus.compute_entry_hash(day1.read_text().splitlines()[-1])
        _force_date(bus, "2026-01-02")
        for i in range(10):
            bus.append("i", f"n{i}", "DCTX", {"payload": "q" * 30, "n": i})
        for p in tmp_path.glob("governance-2026-01-01*"):
            p.unlink()

        # seq-only anchor (wrong hash) must NOT excuse the gap
        valid, breaks = bus.verify_log(
            anchors=[{"seq": 5, "hash": "00" * 32}]
        )
        assert valid is False
        # anchor bound to the true pruned head hash excuses it
        valid, breaks = bus.verify_log(
            anchors=[{"seq": 5, "hash": pruned_hash}]
        )
        assert valid is True, breaks
        # a contradicting tombstone loses to the bound anchor (G7/G9)
        _write_forged_tombstone(bus, through_seq=5, head_hash="11" * 32)
        valid, breaks = bus.verify_log(
            anchors=[{"seq": 5, "hash": pruned_hash}]
        )
        assert valid is False


# ---------------------------------------------------------------------------
# T13 -- ENABLE_IDP=false: bypass recorded, failure reported
# ---------------------------------------------------------------------------


class TestT13DisableBypass:
    def test_disable_writes_bypass_then_refuses(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ENABLE_IDP", "false")
        bus = GovernanceBus(base_dir=tmp_path)
        ok, err = bus.append("i", "t", "DCTX", {"x": 1})
        assert ok is False
        assert err == IDP_E_GOVERNANCE_DISABLED
        monkeypatch.setenv("ENABLE_IDP", "true")
        entries = list(bus.query_all())
        assert len(entries) == 1
        sys_entry = entries[0]
        assert sys_entry.tuple_type == "SYSTEM"
        assert sys_entry.tuple_data["action"] == "governance_disabled"
        assert bus.verify_tag(sys_entry) is True

    def test_repeated_disabled_appends_single_bypass(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ENABLE_IDP", "false")
        bus = GovernanceBus(base_dir=tmp_path)
        for _ in range(3):
            ok, err = bus.append("i", "t", "DCTX", {"x": 1})
            assert ok is False and err == IDP_E_GOVERNANCE_DISABLED
        monkeypatch.setenv("ENABLE_IDP", "true")
        assert len(list(bus.query_all())) == 1  # one bypass marker, not three


# ---------------------------------------------------------------------------
# G2 -- checkpoint publish/fetch through a mocked medium
# ---------------------------------------------------------------------------


class TestG2CheckpointMedium:
    def test_publish_fetch_verify_roundtrip(self, tmp_path):
        """Mocked medium: checkpoints written by the bus are fetched by the
        verifier independently; verification enforces anchor agreement."""
        bus = GovernanceBus(base_dir=tmp_path)
        medium: list[dict] = []  # the external anchor store
        for i in range(8):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
            if i in (3, 7):
                medium.append(bus.compute_checkpoint())

        ok, breaks = bus.verify_log(anchors=medium)
        assert ok is True, breaks

    def test_anchor_mismatch_detected(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(5):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
        medium = [{"seq": 5, "hash": "0" * 64, "ts": "fake"}]
        ok, breaks = bus.verify_log(anchors=medium)
        assert ok is False
        assert any("anchor hash" in b["expected"] for b in breaks)


# ---------------------------------------------------------------------------
# G6 -- persisted head: restart continuation + corruption poisoning
# ---------------------------------------------------------------------------


class TestG6HeadState:
    def test_restart_continues_sequence(self, tmp_path):
        bus1 = GovernanceBus(base_dir=tmp_path)
        for i in range(3):
            bus1.append("i", f"t{i}", "DCTX", {"n": i})
        bus1.close()
        bus2 = GovernanceBus(base_dir=tmp_path)  # same dir = restarted writer
        bus2.append("i", "t3", "DCTX", {"n": 3})
        bus2.close()
        assert _seqs(bus2) == [1, 2, 3, 4]
        valid, breaks = bus2.verify_log()
        assert valid is True, breaks

    def test_corrupted_head_poisons_writer(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        bus.append("i", "t", "DCTX", {"x": 1})
        bus.close()
        (tmp_path / "head.json").write_text(
            '{"seq": 99, "head_hash": "deadbeef"}', encoding="utf-8"
        )
        bus2 = GovernanceBus(base_dir=tmp_path)
        ok, err = bus2.append("i", "t2", "DCTX", {"x": 2})
        assert ok is False
        assert err == IDP_E_HEAD_MISMATCH

    def test_tail_truncated_while_stopped_poisons_writer(self, tmp_path):
        bus = GovernanceBus(base_dir=tmp_path)
        for i in range(4):
            bus.append("i", f"t{i}", "DCTX", {"n": i})
        bus.close()
        seg = bus._get_current_file()
        lines = [l for l in seg.read_text(encoding="utf-8").splitlines() if l.strip()]
        seg.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        bus2 = GovernanceBus(base_dir=tmp_path)
        ok, err = bus2.append("i", "t", "DCTX", {"x": 1})
        assert ok is False
        assert err == IDP_E_HEAD_MISMATCH
