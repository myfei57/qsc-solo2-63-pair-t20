"""Shard framing, sealing and standalone shard verification."""

from __future__ import annotations

import os

from bagsort.store.journal import JournalEntry
from bagsort.store.shardlog import (
    HEADER_SIZE,
    ShardHandle,
    RECORD_FLAG_HELD,
    shard_path,
    state_digest,
    verify_shard_file,
)
from bagsort.store.shardlog.shard import Corruption, iter_shard_records

try:
    import pytest
except ImportError:  # pragma: no cover - direct execution without pytest
    from ._pytest_compat import pytest  # type: ignore


def _entry(seq: int, held: bool = False) -> JournalEntry:
    return JournalEntry(
        sequence=seq,
        kind="counter.add",
        payload={"name": "k", "delta": 1},
    )


def _build_shard(tmp_path, index, seq_start, prev_hash, entries, held_flags=()):
    path = shard_path(str(tmp_path), index)
    handle = ShardHandle.create(path, index, seq_start, prev_hash)
    for position, entry in enumerate(entries):
        handle.append(entry, held=(position in held_flags))
    before = state_digest(__fold_before(entries, seq_start))
    after = state_digest(__fold_all(entries, seq_start))
    summary = handle.seal(before, after)
    return summary


def __fold_before(_entries, seq_start):
    from bagsort.model.state import State

    return State()


def __fold_all(entries, _seq_start):
    from bagsort.model.state import State, apply_entry

    state = State()
    for entry in entries:
        apply_entry(state, entry.kind, entry.payload)
    return state


def test_sealed_shard_round_trips_and_verifies(tmp_path):
    entries = [_entry(seq) for seq in range(1, 4)]
    summary = _build_shard(tmp_path, 0, 1, "0" * 64, entries)
    assert summary.entry_count == 3
    assert summary.seq_start == 1 and summary.seq_end == 3

    path = shard_path(str(tmp_path), 0)
    _header, records, torn, footer = iter_shard_records(path)
    assert torn is False
    assert footer == summary
    assert [entry.sequence for entry, _flags in records] == [1, 2, 3]

    standalone = verify_shard_file(path, expected_prev="0" * 64)
    assert standalone == summary


def test_shard_body_hash_detects_a_flipped_byte(tmp_path):
    entries = [_entry(seq) for seq in range(1, 4)]
    _build_shard(tmp_path, 0, 1, "0" * 64, entries)
    path = shard_path(str(tmp_path), 0)
    raw = bytearray(open(path, "rb").read())
    raw[HEADER_SIZE + 10] ^= 0xFF
    open(path, "wb").write(bytes(raw))
    with pytest.raises(Corruption):
        iter_shard_records(path)


def test_broken_prev_link_is_rejected(tmp_path):
    entries = [_entry(seq) for seq in range(1, 3)]
    _build_shard(tmp_path, 0, 1, "0" * 64, entries)
    path = shard_path(str(tmp_path), 0)
    with pytest.raises(Corruption):
        verify_shard_file(path, expected_prev="a" * 64)


def test_held_flag_survives_framing(tmp_path):
    entries = [_entry(1), _entry(2)]
    _build_shard(tmp_path, 0, 1, "0" * 64, entries, held_flags={1})
    _header, records, _torn, _footer = iter_shard_records(shard_path(str(tmp_path), 0))
    assert [bool(flags & RECORD_FLAG_HELD) for _entry, flags in records] == [False, True]


def test_active_shard_truncates_torn_tail_on_resume(tmp_path):
    path = shard_path(str(tmp_path), 0)
    handle = ShardHandle.create(path, 0, 1, "0" * 64)
    handle.append(_entry(1))
    handle.append(_entry(2))
    handle.close()
    # chop the trailing CRC of the last record -> torn tail
    size = os.path.getsize(path)
    with open(path, "r+b") as broken:
        broken.truncate(size - 3)

    resumed = ShardHandle.resume(path)
    assert resumed.entry_count == 1
    _header, records, torn, footer = iter_shard_records(path)
    assert footer is None and [e.sequence for e, _ in records] == [1]
    # appending after resume keeps sequence continuity
    resumed.append(_entry(2))
    _header, records, _torn, _footer = iter_shard_records(path)
    assert [e.sequence for e, _ in records] == [1, 2]
