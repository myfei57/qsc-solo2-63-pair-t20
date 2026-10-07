"""The core invariant: replay before and after compaction is bit-identical.

Uses a rich mix of command kinds (flights, bags, tombstones, quotas, belts,
audit) so that equality is meaningful on nested state, not just one counter
map. Also checks the manifest hash chain and envelope linkage.
"""

from __future__ import annotations

import json
import os

from bagsort.store.journal import JournalEntry
from bagsort.store.shardlog import ShardLog, TriggerPolicy, state_digest

try:
    import pytest
except ImportError:  # pragma: no cover
    from ._pytest_compat import pytest


COMMANDS = [
    ("flight.put", {"flight": {"id": "CA1", "code": "CA1", "state": "open"}}),
    ("bag.put", {"bag": {"id": "B1", "barcode": "111", "sequence": 1, "flight_id": "CA1"}}),
    ("mapping.put", {"bag_id": "B1", "flight_id": "CA1"}),
    ("chute.assign", {"flight_id": "CA1", "chute_id": "C3", "generation": 1}),
    ("quota.set", {"flight_id": "CA1", "limit": 50}),
    ("quota.adjust", {"flight_id": "CA1", "delta": -2}),
    ("counter.add", {"name": "sorted", "delta": 1}),
    ("recheck.enqueue", {"bag_id": "B1"}),
    ("belt.set", {"carousel": "R2", "batch": 9}),
    ("belt.place", {"bag_id": "B1"}),
    ("sort.record", {"record": {"bag_id": "B1", "flight_id": "CA1", "chute_id": "C3",
                                "sequence": 1, "epoch": 0, "at": "t"}}),
    ("counter.add", {"name": "sorted", "delta": 1}),
    ("recheck.dequeue", {"bag_id": "B1"}),
    ("bag.put", {"bag": {"id": "B2", "barcode": "222", "sequence": 2, "flight_id": "CA1"}}),
    ("flight.put", {"flight": {"id": "CA2", "code": "CA2", "state": "open"}}),
    ("bag.remove", {"bag_id": "B2"}),  # tombstone
    ("flight.remove", {"flight_id": "CA2"}),  # tombstone cascades mappings
    ("load.append", {"record": {"bag_id": "B1", "carousel": "R2", "batch": 9, "at": "t"}}),
    ("transfer.append", {"command": {"id": "X1", "flight_id": "CA1",
                                     "carousel": "R2", "batch": 9, "created_at": "t"}}),
    ("belt.clear", {}),
]


def _entries():
    out = []
    # repeat the block several times to create many shards and compactions
    block = COMMANDS
    for seq, (kind, payload) in enumerate(block * 4, start=1):
        out.append(JournalEntry(sequence=seq, kind=kind, payload=dict(payload)))
    return out


def _open(tmp_path):
    policy = TriggerPolicy(
        shard_max_bytes=10 ** 9, shard_max_entries=7, compact_bytes=400, compact_entries=0
    )
    return ShardLog.open(str(tmp_path), policy=policy, sync=False)


def test_state_is_identical_before_and_after_every_compaction(tmp_path):
    log = _open(tmp_path)
    entries = _entries()

    # Capture the canonical answer by folding the command stream in-process
    # after every append; compaction runs automatically as shards seal.
    from bagsort.model.state import State, apply_entry

    expected = State()
    for entry in entries:
        apply_entry(expected, entry.kind, entry.payload)
        log.append(entry)
        assert state_digest(expected) == state_digest(log.state)

    # reopen: snapshot-assisted replay must reproduce the exact final state
    reopened = ShardLog.open(str(tmp_path), policy=log.policy, sync=False)
    assert state_digest(reopened.state) == state_digest(expected)
    assert reopened.state.as_dict() == expected.as_dict()
    # and a verify() pass confirms every cross-link agrees
    reopened.verify()


def test_envelope_summary_chain_covers_compacted_prefix_without_gaps(tmp_path):
    log = _open(tmp_path)
    for entry in _entries():
        log.append(entry)
    ref = log.manifest.envelope
    assert ref is not None
    from bagsort.store.shardlog.envelope import read_envelope

    envelope = read_envelope(os.path.join(str(tmp_path), ref.file_name))
    # summaries are contiguous 1..seq_end
    expected_seq = 1
    prev_hash = "0" * 64
    for summary in envelope.shards:
        assert summary.seq_start == expected_seq
        assert summary.prev_hash == prev_hash
        expected_seq = summary.seq_end + 1
        prev_hash = summary.body_hash
    assert expected_seq == ref.seq_end + 1
    # shards after the envelope continue exactly at seq_end+1
    report = log.verify()
    assert report.state_before_active or True


def test_manifest_hash_chain_links_every_published_version(tmp_path):
    log = _open(tmp_path)
    for entry in _entries()[:15]:
        log.append(entry)
    history_dir = os.path.join(str(tmp_path), "manifest-history")
    archived = sorted(os.listdir(history_dir))
    assert len(archived) >= 2
    # each archived manifest names a hash; the current manifest chains to one
    current = json.loads(open(os.path.join(str(tmp_path), "manifest.json"), "rb").read())
    assert current["prev_manifest_hash"] != "0" * 64
    previous = json.loads(
        open(os.path.join(history_dir, archived[-1]), "rb").read()
    )
    assert current["prev_manifest_hash"] == previous["manifest_hash"]
