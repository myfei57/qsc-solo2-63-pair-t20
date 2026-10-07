"""Forensic holds: an append-only register of records exempt from compaction.

A *hold* marks one committed command sequence (or a closed range) as preserved
for forensics. The register is an append-only, hash-chained log: entries may be
released later, but the release is itself another record — history is never
rewritten. ``hold_digest`` folds every register record, so a snapshot envelope
proves exactly which holds were in force when compaction ran.

The shard log refuses to compact any shard that intersects a live hold ("被取证保留的记录不能进压实"). Because compaction consumes a *prefix* of shards, it
stops at the first protected shard even if later shards are clean.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from .coding import ZERO_HASH, canonical_json, sha256_hex

HOLD_FILE = "holds.log"
HOLD_VERSION = 1
HOLD_RECORD_MAGIC = b"HOLD1"
HOLD_RECORD_HEADER = HOLD_RECORD_MAGIC  # followed by 4-byte LE length


class HoldError(RuntimeError):
    """The hold register is unreadable or the request is invalid."""


@dataclass(frozen=True)
class HoldRecord:
    seq: int
    action: str  # "hold" or "release"
    case_id: str
    note: str = ""
    at: str = ""
    prev_digest: str = ZERO_HASH
    digest: str = ZERO_HASH

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "action": self.action,
            "case_id": self.case_id,
            "note": self.note,
            "at": self.at,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }


def _content(record: HoldRecord) -> dict[str, Any]:
    raw = record.as_dict()
    raw.pop("digest")
    return raw


def _digest(prev_digest: str, seq: int, action: str, case_id: str, note: str, at: str) -> str:
    body = canonical_json(
        {"prev_digest": prev_digest, "seq": seq, "action": action,
         "case_id": case_id, "note": note, "at": at}
    )
    return sha256_hex(body)


class HoldRegister:
    def __init__(self, directory: str) -> None:
        self._path = os.path.join(directory, HOLD_FILE)
        self._records: list[HoldRecord] = []
        self._active: dict[int, list[HoldRecord]] = {}

    @property
    def path(self) -> str:
        return self._path

    @property
    def digest(self) -> str:
        """Running digest over the whole register (0 hash when empty)."""

        return self._records[-1].digest if self._records else ZERO_HASH

    def load(self) -> "HoldRegister":
        self._records = []
        if not os.path.exists(self._path):
            self._rebuild_active()
            return self
        with open(self._path, "rb") as handle:
            raw = handle.read()
        offset = 0
        while offset < len(raw):
            if raw[offset:offset + 5] != HOLD_RECORD_HEADER:
                raise HoldError("hold log: bad record magic")
            length = int.from_bytes(raw[offset + 5:offset + 9], "little")
            frame_end = offset + 9 + length
            if frame_end > len(raw):
                raise HoldError("hold log: truncated tail")
            try:
                data = json.loads(raw[offset + 9:frame_end])
                record = HoldRecord(
                    seq=int(data["seq"]),
                    action=str(data["action"]),
                    case_id=str(data["case_id"]),
                    note=str(data.get("note", "")),
                    at=str(data.get("at", "")),
                    prev_digest=str(data.get("prev_digest", ZERO_HASH)),
                    digest=str(data["digest"]),
                )
            except (ValueError, KeyError, TypeError) as exc:
                raise HoldError(f"hold log: malformed record: {exc}") from exc
            expected = _digest(
                record.prev_digest, record.seq, record.action,
                record.case_id, record.note, record.at,
            )
            expected_prev = self._records[-1].digest if self._records else ZERO_HASH
            if record.prev_digest != expected_prev or record.digest != expected:
                raise HoldError("hold log: hash chain broken")
            self._records.append(record)
            offset = frame_end
        self._rebuild_active()
        return self

    def _rebuild_active(self) -> None:
        self._active = {}
        for record in self._records:
            if record.action == "hold":
                self._active.setdefault(record.seq, []).append(record)
            elif record.action == "release":
                self._active.pop(record.seq, None)
            else:  # pragma: no cover - guarded by the append API
                raise HoldError(f"unknown hold action {record.action!r}")

    def records(self) -> list[HoldRecord]:
        return list(self._records)

    def held_sequences(self) -> set[int]:
        return set(self._active)

    def is_held(self, seq: int) -> bool:
        return seq in self._active

    def holds_for(self, seq: int) -> list[HoldRecord]:
        return list(self._active.get(seq, ()))

    def range_touches_hold(self, seq_start: int, seq_end: int) -> int | None:
        """Return the first held sequence within ``[seq_start, seq_end]``."""

        for seq in range(seq_start, seq_end + 1):
            if seq in self._active:
                return seq
        return None

    def _append_record(
        self, seq: int, action: str, case_id: str, note: str, at: str, sync: bool
    ) -> HoldRecord:
        if action not in ("hold", "release"):
            raise HoldError(f"unknown hold action {action!r}")
        prev_digest = self.digest
        digest = _digest(prev_digest, seq, action, case_id, note, at)
        record = HoldRecord(
            seq=seq, action=action, case_id=case_id, note=note, at=at,
            prev_digest=prev_digest, digest=digest,
        )
        body = canonical_json(record.as_dict())
        frame = HOLD_RECORD_HEADER + len(body).to_bytes(4, "little") + body
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "ab") as handle:
            handle.write(frame)
            handle.flush()
            if sync:
                os.fsync(handle.fileno())
        self._records.append(record)
        if action == "hold":
            self._active.setdefault(seq, []).append(record)
        else:
            self._active.pop(seq, None)
        return record

    def hold(self, seq: int, case_id: str, note: str = "", at: str = "", sync: bool = True) -> HoldRecord:
        if seq < 1:
            raise HoldError("held sequence must be >= 1")
        if not case_id:
            raise HoldError("a hold requires a case id")
        if seq in self._active:
            cases = ", ".join(record.case_id for record in self._active[seq])
            raise HoldError(f"seq {seq} is already held ({cases})")
        return self._append_record(seq, "hold", case_id, note, at, sync)

    def release(self, seq: int, case_id: str, note: str = "", at: str = "", sync: bool = True) -> HoldRecord:
        if seq not in self._active:
            raise HoldError(f"seq {seq} is not held")
        active_cases = {record.case_id for record in self._active[seq]}
        if case_id not in active_cases:
            raise HoldError(f"case {case_id!r} does not hold seq {seq}")
        return self._append_record(seq, "release", case_id, note, at, sync)
