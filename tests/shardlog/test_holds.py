"""Forensic holds: compact barrier, release, and the append-only hold log."""

from __future__ import annotations

import os

from bagsort.store.journal import JournalEntry
from bagsort.store.shardlog import ShardLog, TriggerPolicy
from bagsort.store.shardlog.holds import HoldError
from bagsort.store.shardlog.log import CompactionBlocked

try:
    import pytest
except ImportError:  # pragma: no cover
    from ._pytest_compat import pytest


def _counter(seq):
    return JournalEntry(sequence=seq, kind="counter.add", payload={"name": "k", "delta": 1})


def _open(tmp_path):
    policy = TriggerPolicy(
        shard_max_bytes=230, shard_max_entries=3, compact_bytes=150, compact_entries=0
    )
    return ShardLog.open(str(tmp_path), policy=policy, sync=False)


def test_held_prefix_shard_blocks_all_compaction(tmp_path):
    log = _open(tmp_path)
    for seq in range(1, 10):
        log.append(_counter(seq), hold_case_id=("CASE-1" if seq == 2 else ""))
    assert log.compactable_shards()[0] == []
    with pytest.raises(CompactionBlocked):
        log.compact(force=True)
    assert not any(name.startswith("snap-") for name in os.listdir(str(tmp_path)))
    # every raw shard is retained while the hold is live
    assert len([f for f in os.listdir(str(tmp_path)) if f.endswith(".shard")]) >= 3


def test_replay_equivalence_preserved_while_hold_is_live(tmp_path):
    log = _open(tmp_path)
    for seq in range(1, 10):
        log.append(_counter(seq), hold_case_id=("CASE-1" if seq == 2 else ""))
    reopened = ShardLog.open(str(tmp_path), policy=log.policy, sync=False)
    assert reopened.state.counters == {"k": 9}
    assert reopened.holds.is_held(2)
    reopened.verify()


def test_release_allows_prefix_compaction_and_keeps_audit_trail(tmp_path):
    log = _open(tmp_path)
    for seq in range(1, 10):
        log.append(_counter(seq), hold_case_id=("CASE-1" if seq == 2 else ""))
    log.release_hold(2, "CASE-1", note="case closed")
    assert log.manifest.envelope is not None
    reopened = ShardLog.open(str(tmp_path), policy=log.policy, sync=False)
    assert reopened.state.counters == {"k": 9}
    actions = [(r.seq, r.action, r.case_id) for r in reopened.holds.records()]
    assert (2, "hold", "CASE-1") in actions
    assert (2, "release", "CASE-1") in actions
    assert reopened.holds.held_sequences() == set()


def test_double_hold_and_wrong_case_release_are_rejected(tmp_path):
    log = _open(tmp_path)
    log.append(_counter(1), hold_case_id="CASE-1")
    with pytest.raises(HoldError):
        log.holds.hold(1, "CASE-2")
    with pytest.raises(HoldError):
        log.release_hold(1, "OTHER")
    log.release_hold(1, "CASE-1")


def test_tampered_hold_log_breaks_its_hash_chain(tmp_path):
    log = _open(tmp_path)
    log.append(_counter(1), hold_case_id="CASE-1")
    hold_path = os.path.join(str(tmp_path), "holds.log")
    raw = bytearray(open(hold_path, "rb").read())
    # flip a byte inside the JSON body (after the 5-byte magic + 4-byte length)
    raw[12] ^= 0x01
    open(hold_path, "wb").write(bytes(raw))
    with pytest.raises(HoldError):
        ShardLog.open(str(tmp_path), policy=log.policy, sync=False)
