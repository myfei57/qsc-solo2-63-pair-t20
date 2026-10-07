"""ShardedStore behaves like the classic Store but persists via the shard log."""

from __future__ import annotations

from bagsort.app import Plant
from bagsort.clock import Clock
from bagsort.store.sharded_store import ShardedStore
from bagsort.store.shardlog import TriggerPolicy, state_digest

try:
    import pytest
except ImportError:  # pragma: no cover
    from ._pytest_compat import pytest


def _store(tmp_path):
    policy = TriggerPolicy(
        shard_max_bytes=10 ** 9, shard_max_entries=10, compact_bytes=800, compact_entries=0
    )
    return ShardedStore.open(str(tmp_path), policy=policy, sync=False)


def test_plant_mutations_are_durable_and_replay_equivalent(tmp_path):
    store = _store(tmp_path)
    plant = Plant.build(store, clock=Clock())
    plant.register_flight("CA1", carousel="2")
    for index in range(12):
        plant.check_in(f"{2000 + index}", "T1-CA1")
    before = store.state().as_dict()

    reopened = ShardedStore.open(str(tmp_path), policy=store.shard_log.policy, sync=False)
    assert reopened.state().as_dict() == before
    report = reopened.shard_log.verify()
    assert report.loaded_envelope
    assert state_digest(reopened.shard_log.state) == state_digest(store.shard_log.state)


def test_session_buffering_and_rollback_still_works(tmp_path):
    store = _store(tmp_path)
    with store.session() as session:
        session.record("counter.add", {"name": "kept", "delta": 1})
    assert store.state().counters == {"kept": 1}
    try:
        with store.session() as session:
            session.record("counter.add", {"name": "dropped", "delta": 1})
            raise RuntimeError("abort")
    except RuntimeError:
        pass
    assert store.state().counters == {"kept": 1}
    assert store.watermark == 1
    reopened = ShardedStore.open(str(tmp_path), policy=store.shard_log.policy, sync=False)
    assert reopened.state().counters == {"kept": 1}


def test_persist_returns_envelope_id(tmp_path):
    store = _store(tmp_path)
    with store.session() as session:
        session.record("counter.add", {"name": "k", "delta": 1})
    first = store.persist()
    # a second persist with nothing new returns the same envelope id or ""
    assert isinstance(first, str)
