"""Which journal commands a compaction summary must keep verbatim.

Most of the journal folds into a state delta. Some commands are evidence rather
than a disposable intermediate value: append-only records (sorting, transfers,
loads, audit) and tombstones that explain why something disappeared. Those are
copied into the compacted shard as *traced* entries. The state delta still
contains their materialised effect, so the replayer skips them; inspection,
CSV export, tombstone queries and assignment histories keep working.

Forensic retention is stronger than tracing. A hold references specific entry
sequences; a shard containing *any* held sequence is never compacted, so the
held record stays exactly where it was committed, in its original raw shard.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .journal import JournalEntry

# Commands whose occurrences are historical records, not overwriteable state.
TRACE_KINDS: frozenset[str] = frozenset(
    {
        "sort.record",
        "transfer.append",
        "load.append",
        "audit.append",
    }
)


def is_traced(entry: JournalEntry) -> bool:
    return entry.kind in TRACE_KINDS or entry.tombstone


def traced_entries(entries: Iterable[JournalEntry]) -> list[JournalEntry]:
    selected = [entry for entry in entries if is_traced(entry)]
    return [
        JournalEntry(
            sequence=entry.sequence,
            kind=entry.kind,
            payload=entry.payload,
            at=entry.at,
            traced=True,
        )
        for entry in selected
    ]


def foldable_entries(entries: Iterable[JournalEntry]) -> list[JournalEntry]:
    return [entry for entry in entries if not is_traced(entry)]


@dataclass(frozen=True)
class CompactionPolicy:
    """Rules for sealing raw shards and choosing what may be compacted.

    Triggering by entry count gives deterministic shard boundaries but spends
    a fixed rewrite budget even when entries are tiny. Triggering by bytes
    bounds disk use and rewrite volume for fat payloads, but seals at uneven
    command counts. The default is count-driven sealing (predictable recovery
    work) with a byte ceiling as a safety valve; either threshold seals a shard.
    """

    target_entries: int = 100
    max_bytes: int = 256 * 1024
    trigger: str = "count"  # "count" or "bytes"; selects which bound is primary

    def __post_init__(self) -> None:
        if self.trigger not in {"count", "bytes"}:
            raise ValueError("trigger must be 'count' or 'bytes'")
        if self.target_entries <= 0:
            raise ValueError("target_entries must be positive")
        if self.max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

    def should_seal(self, entry_count: int, byte_size: int) -> bool:
        """Whether the active raw shard is full enough to roll over."""

        if entry_count >= self.target_entries:
            return True
        if byte_size >= self.max_bytes:
            return True
        return False

    def primary_exceeded(self, entry_count: int, byte_size: int) -> str | None:
        if self.trigger == "count" and entry_count >= self.target_entries:
            return "count"
        if self.trigger == "bytes" and byte_size >= self.max_bytes:
            return "bytes"
        return None
