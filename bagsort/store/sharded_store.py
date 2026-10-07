"""A :class:`Store`-compatible durable backend backed by the sharded log.

The classic :class:`~bagsort.store.store.Store` keeps the committed journal in
memory and persists a single whole-history JSON envelope. :class:`ShardedStore`
keeps the same in-memory model (so every subsystem and the buffered
``Session`` transaction keep working) but mirrors each committed command into
the sharded, compactable log, and on open rebuilds the journal from the
snapshot envelope plus surviving shards.

The result is drop-in persistence with bounded restart replay: old history is
summarised into snapshot envelopes, new commands keep appending to the active
shard, and forensic holds flow straight through.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

from ..errors import ConflictError
from ..model.state import State
from .journal import Journal, JournalEntry
from .store import Session
from .shardlog import ShardLog, TriggerPolicy
from .shardlog.log import CompactionBlocked


class ShardedStore:
    """Drop-in durable alternative to :class:`Store` using the shard log."""

    def __init__(
        self,
        path: str,
        policy: TriggerPolicy | None = None,
        sync: bool = True,
    ) -> None:
        self._path = os.path.abspath(path)
        self._log = ShardLog.open(self._path, policy=policy, sync=sync)
        self._journal = self._load_journal()
        self._cache: State | None = None

    def _load_journal(self) -> Journal:
        # Recover committed entries only where raw shard bytes survive. The
        # envelope contributes the folded state directly (its bytes are gone).
        journal = Journal()
        for entry in self._committed_entries_from_shards():
            journal.append(entry.kind, entry.payload, entry.at)
        journal.commit()
        return journal

    def _committed_entries_from_shards(self) -> list[JournalEntry]:
        """Reconstruct surviving (non-compacted) committed entries in order."""

        from .shardlog.shard import iter_shard_records, shard_path

        entries: list[JournalEntry] = []
        for index in sorted(self._log.manifest.shards):
            ref = self._log.manifest.shards[index]
            if ref.compacted:
                continue
            _header, records, _torn, _footer = iter_shard_records(
                shard_path(self._path, index)
            )
            entries.extend(entry for entry, _flags in records)
        return entries

    # -- Store-compatible surface -----------------------------------------

    @property
    def path(self) -> str:
        return self._path

    @property
    def shard_log(self) -> ShardLog:
        return self._log

    @property
    def watermark(self) -> int:
        return self._log.watermark

    def state(self) -> State:
        # The shard log already holds the fully folded state (envelope + shards).
        return self._log.state

    def entries(self) -> list[JournalEntry]:
        """Entries whose raw bytes still exist (post-envelope entries)."""

        return self._journal.committed()

    def entries_since(self, watermark: int) -> list[JournalEntry]:
        return self._journal.since(watermark)

    def pending(self):
        return self._journal.pending()

    def has_pending(self) -> bool:
        return self._journal.has_pending()

    def tombstones(self):
        return [entry for entry in self._journal.committed() if entry.tombstone]

    def kinds(self):
        return self._journal.kinds()

    def dirty(self) -> bool:
        # Every commit is durably appended; there is no unpersisted window.
        return False

    def stats(self) -> dict[str, int]:
        state = self.state()
        return {
            "watermark": self.watermark,
            "entries": self.watermark,
            "flights": len(state.flights),
            "bags": len(state.bags),
            "assignments": len(state.assignments),
            "sort_records": len(state.sort_records),
            "transfer_commands": len(state.transfer_commands),
            "load_records": len(state.load_records),
            "audit": len(state.audit),
        }

    @property
    def journal(self) -> Journal:
        return self._journal

    @contextmanager
    def session(self) -> Iterator[Session]:
        try:
            yield Session(self)
        except BaseException:
            self._journal.rollback()
            raise
        else:
            if self._journal.has_pending():
                self.commit()

    def commit(self) -> int:
        if not self._journal.has_pending():
            raise ConflictError("nothing to commit")
        start = self._journal.watermark
        # Promote into the in-memory journal first so the sequence numbers and
        # the shard log's append order agree, then mirror each new committed
        # command durably into a shard.
        new_watermark = self._journal.commit()
        committed = self._journal.committed()
        for sequence in range(start + 1, new_watermark + 1):
            self._log.append(committed[sequence - 1])
        return new_watermark

    def rollback(self) -> int:
        return self._journal.rollback()

    def reset(self) -> None:
        raise NotImplementedError(
            "ShardedStore reset is intentionally unsupported: history is "
            "append-only; compact instead"
        )

    def envelope(self):  # pragma: no cover - compatibility shim
        raise NotImplementedError("use shard_log snapshots instead")

    def persist(self) -> str:
        """Force a compaction pass; returns the current envelope id.

        Returns the id of the envelope now covering the compactable prefix. If
        there is nothing new to compact but an envelope already exists, that
        envelope id is returned; an empty string means no envelope exists yet.
        """

        try:
            return self._log.compact(force=True).envelope_id
        except CompactionBlocked:
            ref = self._log.manifest.envelope
            return ref.envelope_id if ref is not None else ""

    @classmethod
    def open(
        cls,
        path: str,
        policy: TriggerPolicy | None = None,
        sync: bool = True,
    ) -> "ShardedStore":
        return cls(path, policy=policy, sync=sync)
