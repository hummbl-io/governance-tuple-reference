# Non-author review: residual gaps in the pruned-chain excuse path

**Reviewed at:** `fdbdf5c` on `fix/devin/gt-phase2-contexts`
**Date:** 2026-09-25
**Reviewer:** claude-code (non-author; not the author of `30bd273` or `fdbdf5c`)
**Status:** review notes. Nothing here is committed policy; two items need an owner
decision on a published claim before the code question is settled.

> Publication note: this file deliberately contains no content from the private
> remediation spec. It refers only to the public condition IDs (F1-F8), the public
> defect IDs (T1-T15), result labels, and code in this repository. New gate-row IDs
> (G7-G9) are proposed here; the existing G1-G6 numbering lives in the private spec.

## Credit first

Phase 1 fixed the real defect. `verify_log` (`reference_impl/governance_bus.py:916`)
now excuses a chain starting above `seq=1` only when a `retention_prune` tombstone
covers the gap or an anchor does. That is the missing predicate — validity relative
to a pruned start rather than relative to genesis — actually implemented. An earlier
reviewer note of mine claimed the T8 failure was a blocked lane; that was stale
within minutes and is withdrawn.

## The one invariant

All three findings below are instances of a single rule, which is the class the
original T7 defect belonged to:

> **No gap in the chain may be excused by evidence the adversary can author.**

T7 excused a gap because each day restarted at genesis. The current code excuses a
gap on the strength of an entry that lives inside the log being verified. The
mechanism changed; the class did not. This invariant is worth a test of its own,
because it is the thing that keeps recurring.

## Findings

### R1 (P1) — the excuse is a disjunction, and one branch is operator-forgeable

`reference_impl/governance_bus.py:962` — `if tombstone_ok or anchor_ok:`

`tombstone_ok` (`:952-957`) is satisfied by any `SYSTEM` entry in the log under
review whose `action == "retention_prune"` and whose `pruned_through_seq >=
first_seq - 1`. That entry is part of the log. An adversary who controls storage
can write one with an inflated `pruned_through_seq` and excuse an arbitrary gap —
T7 with extra steps.

This is sound against an agent adversary confined to the append interface. It is
not sound against an operator adversary. `cor:gt-retention` claims the removed
count and the last removed hash "cannot be altered undetectably", which holds only
when the tombstone itself sits at or below an anchored checkpoint.

For the operator adversary the disjunction must become a conjunction: a tombstone
alone excuses nothing unless anchored.

### R2 (P1) — `pruned_head_hash` is written and never read

- written: `reference_impl/governance_bus.py:1238` (from `last_removed_hash`, `:1220`)
- asserted non-empty: `tests/test_phase1_acceptance.py:364`
- read by a verifier: nowhere

`grep pruned_head_hash` returns exactly those two hits. So the corollary's claim
that a verifier "can confirm ... the hash of the last [removed entry]" is currently
unimplemented: the value is recorded and never checked against anything.

The check is free and both sides are already stored. The first retained entry's
`previous_hash` must equal the tombstone's `pruned_head_hash`; verification must
fail when it does not. Without it, a tombstone can claim to have pruned through a
prefix it never pruned, and nothing contradicts it.

### R3 (P2) — `anchor_ok` compares a sequence number, not a commitment

`reference_impl/governance_bus.py:959-961` — `any(int(a["seq"]) >= first_seq - 1
for a in (anchors or []))`

The anchor branch tests only a sequence number. No hash from the anchor is compared
to anything in the log. An anchor is therefore functioning as a permission slip
rather than a commitment: a verifier holding a checkpoint for seq `k` accepts any
log claiming to start at or below `k+1`, whatever its contents.

Bind it. When an anchor covers the gap, verify the anchored hash against the
tombstone's `pruned_head_hash` or against `H(first retained entry)`. An anchor whose
hash is never checked provides none of the integrity `thm:gt-prefix` derives from it.

### R4 (P3) — a docstring promises a negative case the test does not assert

`tests/test_phase1_acceptance.py:366` —
`"""Pruned prefix + tombstone verifies clean; without tombstone it fails."""`

The body asserts only `valid is True`. The "without tombstone it fails" half is not
exercised, so the regression that reintroduces unconditional gap-excusing passes
silently. Strip the tombstone and assert failure.

## Proposed gate rows

Stated in the gate's own shape so they can become tests rather than prose. The
invariant above is what G7-G9 collectively enforce.

| Test | Must assert | Fix |
|---|---|---|
| G7 | A forged `retention_prune` tombstone with an inflated `pruned_through_seq`, not covered by any anchor, FAILS verification. Tombstone-only excuse is accepted only for the agent adversary, never when an anchor is available and contradicts it. | F1, F2 |
| G8 | The first retained entry's `previous_hash` equals the tombstone's `pruned_head_hash`; a tombstone whose `pruned_head_hash` does not match FAILS verification. | F1 |
| G9 | An anchor excuses a gap only when its hash is checked: an anchor with a matching `seq` but a non-matching hash FAILS verification. | F2 |
| G10 | `test_verify_after_prune_with_tombstone` also asserts the negative: with the tombstone removed, verification fails. | F1 |

Sketch for G8, using the fixtures already in `tests/test_phase1_acceptance.py`:

```python
def test_tombstone_head_hash_must_match_first_retained(self, tmp_path, monkeypatch):
    monkeypatch.setattr(gb, "ROTATION_SIZE_BYTES", 200)
    bus = GovernanceBus(base_dir=tmp_path, retention_days=30)
    _force_date(bus, "2026-01-01")
    for i in range(40):
        bus.append("i", f"t{i}", "DCTX", {"payload": "q" * 30, "n": i})
    _force_date(bus, None)
    bus.enforce_retention()
    # corrupt only the tombstone's recorded head hash
    _rewrite_tombstone_field(bus, "pruned_head_hash", "00" * 32)
    valid, breaks = bus.verify_log()
    assert valid is False
    assert any("pruned_head_hash" in b["expected"] for b in breaks)
```

## What is a code fix and what is not

R2, R3 and R4 are code and test fixes. They stand on their own as defense in depth
and need no decision from anyone.

R1 is different. Making the disjunction a conjunction narrows what the
implementation accepts, and it also changes what `cor:gt-retention` can claim in the
paper. The corollary currently asserts operator-resistance that tombstone-only
verification does not deliver. Whether to tighten the code, weaken the corollary, or
state the corollary's adversary scope explicitly is an owner decision, not an
implementer's.

## Where this came from

Posted to the coordination bus 2026-09-25T16:03:15Z and 16:27:57Z addressed to
`devin`. The bus is an append-only record, not a delivery channel, and an identity
is not a mailbox — neither post was acknowledged. This file exists because the
working tree is the surface that whoever resumes phases 3-6 will actually read.
