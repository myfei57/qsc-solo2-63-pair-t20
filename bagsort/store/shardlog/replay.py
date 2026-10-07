"""Replayer: rebuild state from the shard/snapshot layout and cross-check it.

Two replay paths exist and must produce the *same* state:

* **snapshot replay** (the fast restart path): load the current envelope's
  materialised state, verify its digest, then fold only the surviving shards
  after the envelope's ``seq_end``;
* **raw replay** (the audit path before any compaction): fold every shard
  record from sequence 1. Once shards are compacted their bytes are gone by
  design; the envelope summaries plus its state digest then anchor history.

Every link the manifest names is checked: envelope body hash, per-shard
summaries, the shard body-hash chain, sequence contiguity and per-shard
state-before/after digests. A mismatch raises :class:`Corruption` rather than
silently diverging.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

from ...model.state import State, apply_entry
from ..journal import JournalEntry
from .coding import (
    ZERO_HASH,
    canonical_entry,
    sha256_hex,
    state_digest,
)
from .envelope import read_envelope
from .manifest import EnvelopeRef, Manifest
from .shard import (
    HEADER_SIZE,
    Corruption,
    RECORD_FLAG_HELD,
    ShardSummary,
    iter_shard_records,
    shard_path,
)

RECORD_FRAME_OVERHEAD = 4 + 4 + 1 + 4
ENVELOPE_MARKER = b"\nBAGSNAP1 "


@dataclass
class ReplayReport:
    state: State
    next_seq: int
    state_before_active: str
    loaded_envelope: str
    folded_shards: list[int] = field(default_factory=list)
    compacted_shards: list[int] = field(default_factory=list)
    held_sequences: list[int] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)


def _frame_len(entry: JournalEntry) -> int:
    return RECORD_FRAME_OVERHEAD + len(canonical_entry(entry))


def _chain_step(previous: str, payload: bytes) -> str:
    return sha256_hex(bytes.fromhex(previous) + hashlib.sha256(payload).digest())


def _read_shard(
    directory: str, index: int, expected_prev: str | None
) -> tuple[list[tuple[JournalEntry, int]], ShardSummary | None, dict[str, object]]:
    path = shard_path(directory, index)
    header, records, _torn, footer = iter_shard_records(path)
    if expected_prev is not None and header["prev_hash"] != expected_prev:
        raise Corruption(f"shard {index}: body-hash chain link broken")
    return records, footer, header


def _check_summary_against_records(
    summary: ShardSummary, records: list[tuple[JournalEntry, int]], body_file_bytes: int | None = None
) -> None:
    if summary.entry_count != len(records):
        raise Corruption(f"shard {summary.index}: entry count mismatch")
    if not records:
        raise Corruption(f"shard {summary.index}: sealed empty shard")
    if records[0][0].sequence != summary.seq_start:
        raise Corruption(f"shard {summary.index}: seq_start mismatch")
    if records[-1][0].sequence != summary.seq_end:
        raise Corruption(f"shard {summary.index}: seq_end mismatch")
    body_bytes = HEADER_SIZE + sum(_frame_len(entry) for entry, _flags in records)
    if body_bytes != summary.body_bytes:
        raise Corruption(f"shard {summary.index}: body length mismatch")
    first = last = ZERO_HASH
    for position, (entry, _flags) in enumerate(records):
        step = _chain_step(summary.prev_hash if position == 0 else last, canonical_entry(entry))
        if position == 0:
            first = step
        last = step
    if first != summary.first_hash or last != summary.last_hash:
        raise Corruption(f"shard {summary.index}: record chain mismatch")


def _fold_records(state: State, records: list[tuple[JournalEntry, int]]) -> list[int]:
    held: list[int] = []
    for entry, flags in records:
        if entry.sequence < 1:
            raise Corruption("record sequence must be >= 1")
        apply_entry(state, entry.kind, entry.payload)
        if flags & RECORD_FLAG_HELD:
            held.append(entry.sequence)
    return held


def _verify_envelope_ref(directory: str, ref: EnvelopeRef):
    path = os.path.join(directory, ref.file_name)
    with open(path, "rb") as handle:
        raw = handle.read()
    split_at = raw.rfind(ENVELOPE_MARKER)
    if split_at < 0:
        raise Corruption(f"envelope {ref.envelope_id}: missing checksum marker")
    body = raw[:split_at]
    if sha256_hex(body) != ref.body_hash:
        raise Corruption(f"envelope {ref.envelope_id}: body hash mismatch")
    envelope = read_envelope(path)
    if not envelope.verify():
        raise Corruption(f"envelope {ref.envelope_id}: self-check failed")
    if envelope.envelope_id != ref.envelope_id:
        raise Corruption("envelope id disagrees with manifest")
    if envelope.seq_end != ref.seq_end:
        raise Corruption("envelope seq_end disagrees with manifest")
    if envelope.state_digest != ref.state_digest:
        raise Corruption("envelope state digest disagrees with manifest")
    return envelope


def replay_log(log: "ShardLogLike", verify: bool = True) -> ReplayReport:  # noqa: F821
    """Replay the log referenced by ``log.manifest`` from ``log.directory``."""

    manifest: Manifest = log.manifest
    directory = log.directory
    state = State()
    folded: list[int] = []
    compacted: list[int] = []
    held: list[int] = []
    checks: list[str] = []

    envelope_ref = manifest.envelope
    envelope_seq_end = 0
    if envelope_ref is not None:
        envelope = _verify_envelope_ref(directory, envelope_ref)
        state = envelope.state
        envelope_seq_end = envelope.seq_end
        checks.append(f"envelope:{envelope.envelope_id}")
        expected_start = 1
        for summary in envelope.shards:
            ref = manifest.shards.get(summary.index)
            if ref is None or not ref.compacted:
                raise Corruption(
                    f"envelope claims shard {summary.index} but manifest does not compact it"
                )
            if summary.body_hash != ref.summary.body_hash:
                raise Corruption(f"shard {summary.index}: envelope/manifest summary differs")
            if summary.seq_start != expected_start:
                raise Corruption(f"envelope shard {summary.index}: non-contiguous coverage")
            expected_start = summary.seq_end + 1
            compacted.append(summary.index)
        if expected_start != envelope_seq_end + 1:
            raise Corruption("envelope shard summaries do not cover seq_end")
        checks.extend(f"summary:{index}" for index in compacted)

    expected_prev = ZERO_HASH
    state_before_active = state_digest(state)
    expected_seq = envelope_seq_end + 1
    surviving_last_seq = envelope_seq_end

    # The active shard is unsealed on purpose and therefore is not an entry in
    # manifest.shards; build the ordered index list including it.
    ordered_indices = sorted(set(manifest.shards) | ({manifest.active_index} if manifest.active_index >= 0 else set()))
    for index in ordered_indices:
        ref = manifest.shards.get(index)
        is_active = index == manifest.active_index
        if ref is None:
            if not is_active:
                raise Corruption(f"shard {index}: missing manifest reference")
            # provisional summary populated from the file below
            summary = None
        else:
            summary = ref.summary
            if ref.compacted:
                if summary.prev_hash != expected_prev and expected_prev != ZERO_HASH:
                    raise Corruption(f"shard {index}: compacted chain link broken")
                expected_prev = summary.body_hash
                continue
        if is_active:
            state_before_active = state_digest(state)
        records, footer, header = _read_shard(directory, index, expected_prev)
        if footer is None:
            if not is_active:
                raise Corruption(f"shard {index}: unsealed shard is not the active one")
        else:
            if is_active:
                raise Corruption("manifest active shard is already sealed")
            assert summary is not None
            _check_summary_against_records(summary, records)
            if verify and state_digest(state) != summary.state_before:
                raise Corruption(f"shard {index}: state-before digest mismatch")
        for entry, _flags in records:
            if entry.sequence != expected_seq:
                raise Corruption(
                    f"shard {index}: expected seq {expected_seq}, found {entry.sequence}"
                )
            expected_seq += 1
        shard_held = _fold_records(state, records)
        if footer is not None and verify and summary is not None and state_digest(state) != summary.state_after:
            raise Corruption(f"shard {index}: state-after digest mismatch")
        held.extend(shard_held)
        folded.append(index)
        if records:
            surviving_last_seq = records[-1][0].sequence
        if footer is not None and summary is not None:
            expected_prev = summary.body_hash
        # For the unsealed active shard there is no body hash yet; its prev link
        # was already checked in _read_shard, so expected_prev simply stands.

    next_seq = surviving_last_seq + 1

    return ReplayReport(
        state=state,
        next_seq=next_seq,
        state_before_active=state_before_active,
        loaded_envelope=envelope_ref.envelope_id if envelope_ref else "",
        folded_shards=folded,
        compacted_shards=compacted,
        held_sequences=held,
        checks=checks,
    )


def _fold_shard_indices(directory, manifest, indices, prev_envelope):
    """Fold an envelope base state plus the given shard indices for compaction.

    Returns ``(state, total_entries, summaries_by_index, base_state_digest)``
    and performs every integrity check, so the resulting envelope can only be
    written when it is provably equivalent to raw replay.
    """

    state = State()
    summaries: dict[int, ShardSummary] = {}
    total = 0
    if prev_envelope is not None:
        envelope = _verify_envelope_ref(directory, prev_envelope)
        state = envelope.state
        summaries = {summary.index: summary for summary in envelope.shards}
        total += sum(summary.entry_count for summary in summaries.values())

    previous_index = max(summaries) if summaries else None
    prev_hash = (
        manifest.shards[indices[0]].summary.prev_hash
        if indices
        else ZERO_HASH
    )
    for index in indices:
        if previous_index is not None and index <= previous_index:
            raise Corruption("compaction indices must extend the envelope prefix")
        ref = manifest.shards[index]
        records, footer, _header = _read_shard(directory, index, prev_hash)
        if footer is None:
            raise Corruption(f"cannot compact unsealed shard {index}")
        _check_summary_against_records(footer, records)
        if state_digest(state) != footer.state_before:
            raise Corruption(f"shard {index}: state-before digest mismatch at compaction")
        _fold_records(state, records)
        if state_digest(state) != footer.state_after:
            raise Corruption(f"shard {index}: state-after digest mismatch at compaction")
        summaries[index] = footer
        total += footer.entry_count
        prev_hash = footer.body_hash
        previous_index = index
    return state, total, summaries, state_digest(State())


def verify_log(log: "ShardLogLike") -> ReplayReport:  # noqa: F821
    return replay_log(log, verify=True)
