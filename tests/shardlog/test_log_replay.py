"""Append, rollover, replay equivalence and snapshot-assisted restart."""

from __future__ import annotations

from bagsort.store.journal import JournalEntry
from bagsort.store.shardlog import ShardLog, TriggerPolicy, state_digest
from bagsort.store.shardlog.log import CompactionBlocked

try:
    import pytest
except ImportError:  # pragma: no cover
    from ._pytest_compat import pytest


def _counter(seq, name="k", delta=1):
    return JournalEntry(
        sequence=seq, kind="counter.add", payload={"name": name, "delta": delta}
    )


def _open(tmp_path, **overrides):
    # Roll shards over by entry count (large byte ceiling) so shard boundaries
    # are deterministic regardless of payload encoding size; compact by bytes.
    policy = TriggerPolicy(
        shard_max_bytes=overrides.pop("shard_max_bytes", 10 ** 9),
        shard_max_entries=overrides.pop("shard_max_entries", 4),
        compact_bytes=overrides.pop("compact_bytes", 500),
        compact_entries=overrides.pop("compact_entries", 0),
    )
    return ShardLog.open(str(tmp_path), policy=policy, sync=False)


def test_appended_entries_replay_to_identical_state(tmp_path):
    log = _open(tmp_path)
    expected = {}
    for seq in range(1, 25):
        name = f"k{seq % 3}"
        log.append(_counter(seq, name))
        expected[name] = expected.get(name, 0) + 1
    assert log.state.counters == expected
    report = log.verify()
    assert state_digest(report.state) == state_digest(log.state)


def test_restart_after_many_rollovers_and_compactions(tmp_path):
    log = _open(tmp_path)
    expected = {}
    n = 40
    for seq in range(1, n + 1):
        name = f"k{seq % 4}"
        log.append(_counter(seq, name))
        expected[name] = expected.get(name, 0) + 1

    reopened = ShardLog.open(str(tmp_path), policy=log.policy, sync=False)
    assert reopened.state.counters == expected
    assert reopened.next_seq == n + 1
    # the fast path must have loaded an envelope and folded few shards
    report = reopened.verify()
    assert report.loaded_envelope
    assert len(report.compacted_shards) >= 1


def test_compacted_shard_bytes_are_removed_but_summaries_remain(tmp_path):
    import os

    log = _open(tmp_path)
    for seq in range(1, 20):
        log.append(_counter(seq))
    assert log.manifest.envelope is not None
    envelope = log.manifest.envelope
    # shards compacted *in this run* are gone from disk ...
    for index in envelope.shard_indices:
        assert not os.path.exists(
            os.path.join(str(tmp_path), f"log-{index:010d}.shard")
        )
    # ... while the envelope carries the cumulative summary chain covering 1..seq_end
    snap = __import__(
        "bagsort.store.shardlog.envelope", fromlist=["read_envelope"]
    ).read_envelope(os.path.join(str(tmp_path), envelope.file_name))
    assert snap.shards[0].seq_start == 1
    assert snap.shards[-1].seq_end == envelope.seq_end
    assert snap.shards[-1].index >= envelope.shard_indices[-1]


def test_envelope_state_equals_state_folded_up_to_seq_end(tmp_path):
    import os

    from bagsort.store.shardlog.envelope import read_envelope

    log = _open(tmp_path)
    for seq in range(1, 12):
        log.append(_counter(seq))
    ref = log.manifest.envelope
    assert ref is not None
    envelope = read_envelope(os.path.join(str(tmp_path), ref.file_name))
    assert envelope.verify()
    # the envelope must equal replay of exactly its covered prefix, not the
    # live state (which also includes post-envelope entries still in shards)
    from bagsort.model.state import State, apply_entry

    expected = State()
    for seq in range(1, envelope.seq_end + 1):
        apply_entry(expected, "counter.add", {"name": "k", "delta": 1})
    assert envelope.state_digest == state_digest(expected)
    # ... and envelope + surviving shards together equal the live state
    assert state_digest(log.state) == state_digest(log.verify().state)


def test_force_compaction_below_threshold_is_blocked(tmp_path):
    policy = TriggerPolicy(
        shard_max_bytes=10 ** 9, shard_max_entries=4, compact_bytes=10 ** 9, compact_entries=0
    )
    log = ShardLog.open(str(tmp_path), policy=policy, sync=False)
    for seq in range(1, 6):
        log.append(_counter(seq))
    with pytest.raises(CompactionBlocked):
        log.compact()
    result = log.compact(force=True)
    # first sealed shard covers seq 1..4; seq 5 is in the active shard
    assert result.seq_end == 4
    assert 5 not in result.shard_indices
