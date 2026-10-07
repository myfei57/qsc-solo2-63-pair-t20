"""Crash safety: every durable step is recoverable with no half shard."""

from __future__ import annotations

from bagsort.store.journal import JournalEntry
from bagsort.store.shardlog import ShardLog, TriggerPolicy

try:
    import pytest
except ImportError:  # pragma: no cover
    from ._pytest_compat import pytest


class _Crash(Exception):
    pass


def _counter(seq):
    return JournalEntry(sequence=seq, kind="counter.add", payload={"name": "k", "delta": 1})


def _policy():
    return TriggerPolicy(
        shard_max_bytes=240, shard_max_entries=3, compact_bytes=160, compact_entries=0
    )


def _write_until_crash(tmp_path, point, n, sync=True):
    def hook(where):
        if where == point:
            raise _Crash(where)

    log = ShardLog.open(str(tmp_path), policy=_policy(), sync=sync, crash_hook=hook)
    try:
        for seq in range(1, n + 1):
            log.append(_counter(seq))
    except _Crash:
        return


CRASH_POINTS = [
    "before_active_create",
    "before_frame_write",
    "before_seal",
    "before_rollover_publish",
    "before_intent",
    "before_envelope_write",
    "before_compact_publish",
    "after_commit",
]


def _check_point(tmp_path, point):
    n = 14
    _write_until_crash(tmp_path, point, n)
    recovered = ShardLog.open(str(tmp_path), policy=_policy(), sync=True)
    prefix = recovered.watermark
    assert 0 <= prefix <= n
    assert recovered.state.counters.get("k", 0) == prefix
    # recovery must not raise and every surviving object verifies
    recovered.verify()
    # finish the history and prove the final state is exactly the intended one
    for seq in range(prefix + 1, n + 1):
        recovered.append(_counter(seq))
    final = ShardLog.open(str(tmp_path), policy=_policy(), sync=True)
    assert final.state.counters == {"k": n}
    assert final.next_seq == n + 1


def test_all_crash_points_recover_to_an_equivalent_prefix(tmp_path):
    for point in CRASH_POINTS:
        import shutil

        target = tmp_path / point
        target.mkdir()
        try:
            _check_point(target, point)
        finally:
            shutil.rmtree(target, ignore_errors=True)


def test_no_compaction_intent_survives_as_a_half_shard(tmp_path):
    import os

    _write_until_crash(tmp_path, "before_compact_publish", 12)
    # envelope may be present, but no shard is marked compacted pre-commit and
    # the intent journal must be reconciled away on open
    ShardLog.open(str(tmp_path), policy=_policy(), sync=True)
    journal_dir = os.path.join(str(tmp_path), "compaction")
    if os.path.isdir(journal_dir):
        leftovers = [f for f in os.listdir(journal_dir) if f.endswith(".json")]
        assert leftovers == []
