"""Append-only command journal with an explicit commit watermark.

Every mutation the plant performs is expressed as a command. Commands are first
buffered as *pending*; readers never see them. A commit moves the whole buffer
into the committed log and advances the watermark, a rollback drops it. This is
what gives the service "uncommitted records are invisible" and "restart replays
from the watermark" as real properties instead of conventions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from bagsort.model.state import State



@dataclass(frozen=True)
class JournalEntry:
    """One committed command.

    ``traced`` marks an entry a compaction summary kept verbatim instead of
    folding it into the state checkpoint. Traced entries are historical
    evidence (append-only records, tombstones, forensic holds); the replayer
    skips them because their effect is already inside the checkpoint.
    """

    sequence: int
    kind: str
    payload: dict[str, Any]
    at: str = ""
    traced: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "payload": self.payload,
            "at": self.at,
            "traced": self.traced,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "JournalEntry":
        payload = raw.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("journal payload must be an object")
        return cls(
            sequence=int(raw.get("sequence", 0)),
            kind=str(raw.get("kind", "")),
            payload=dict(payload),
            at=str(raw.get("at", "")),
            traced=bool(raw.get("traced", False)),
        )

    @property
    def tombstone(self) -> bool:
        """A tombstone retires an entity instead of updating it."""

        return self.kind.endswith(".remove")


class Journal:
    """Committed entries plus the buffer of commands not yet committed.

    Commands older than a compaction boundary live in a folded *checkpoint*
    instead of in the entry list. A compacted shard keeps some commands as
    evidence (append-only records and tombstones); those are stored as
    ``traced`` entries at the checkpoint. They remain inspectable but are not
    replayed. ``kinds`` still accounts for them because the checkpoint carries
    the folded command tallies.
    """

    def __init__(
        self,
        checkpoint: "State | None" = None,
        traced: list[JournalEntry] | None = None,
        checkpoint_kinds: dict[str, int] | None = None,
    ) -> None:
        self._checkpoint = checkpoint
        self._checkpoint_watermark = 0
        self._traced: list[JournalEntry] = list(traced or [])
        self._checkpoint_kinds: dict[str, int] = dict(checkpoint_kinds or {})
        self._committed: list[JournalEntry] = []
        self._pending: list[tuple[str, dict[str, Any], str]] = []

    @property
    def watermark(self) -> int:
        if self._committed:
            return self._committed[-1].sequence
        if self._checkpoint is not None:
            return self._checkpoint_watermark
        return 0

    def has_checkpoint(self) -> bool:
        return self._checkpoint is not None

    def checkpoint(self) -> "State | None":
        return self._checkpoint

    def traced(self) -> list[JournalEntry]:
        """Verbatim evidence carried at the checkpoint; never re-applied."""

        return list(self._traced)

    def load_checkpoint(
        self,
        checkpoint: "State",
        watermark: int,
        traced: list[JournalEntry] | None = None,
        kinds: dict[str, int] | None = None,
    ) -> None:
        """Install a folded checkpoint produced by a compacted shard chain."""

        self._checkpoint = checkpoint
        self._checkpoint_watermark = watermark
        self._traced = list(traced or [])
        self._checkpoint_kinds = dict(kinds or {})
        self._committed = []

    def committed(self) -> list[JournalEntry]:
        return self._traced + list(self._committed)

    def since(self, watermark: int) -> list[JournalEntry]:
        """Entries with ``sequence`` strictly greater than ``watermark``."""

        return [
            entry
            for entry in self.committed()
            if entry.sequence > watermark
        ]

    def pending(self) -> list[tuple[str, dict[str, Any], str]]:
        return list(self._pending)

    def has_pending(self) -> bool:
        return bool(self._pending)

    def append(self, kind: str, payload: dict[str, Any], at: str = "") -> None:
        self._pending.append((kind, payload, at))

    def commit(self) -> int:
        """Promote every buffered command; returns the new watermark."""

        sequence = self.watermark
        for kind, payload, at in self._pending:
            sequence += 1
            self._committed.append(
                JournalEntry(sequence=sequence, kind=kind, payload=payload, at=at)
            )
        self._pending = []
        return sequence

    def rollback(self) -> int:
        """Discard the buffer; returns how many commands were dropped."""

        dropped = len(self._pending)
        self._pending = []
        return dropped

    def tombstones(self) -> list[JournalEntry]:
        return [entry for entry in self._committed if entry.tombstone]

    def kinds(self) -> dict[str, int]:
        counts: dict[str, int] = dict(self._checkpoint_kinds)
        for entry in self._committed:
            counts[entry.kind] = counts.get(entry.kind, 0) + 1
        return dict(sorted(counts.items()))
