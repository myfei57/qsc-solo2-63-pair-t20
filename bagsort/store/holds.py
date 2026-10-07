"""Append-only forensic hold ledger.

A hold says "entry sequence N is under forensic retention: never compact it".
Holds are themselves evidence, so the ledger is append-only and checksummed as
a hash chain: every hold references the previous ledger digest. The on-disk
file is replaced atomically (temp file + ``os.replace``), which keeps the
ledger one valid document instead of a half-written one after a crash.

Holds are permanent by design; there is no release API. If a sequence has
already been folded into a compacted shard it is too late, so placing a hold on
it is rejected loudly rather than silently downgraded to a trace.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from bagsort.errors import ConflictError, ValidationError

GENESIS = "0" * 64
HOLD_ENVELOPE_VERSION = 1


@dataclass(frozen=True)
class Hold:
    sequence: int
    reason: str
    at: str
    prev_digest: str
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "reason": self.reason,
            "at": self.at,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Hold":
        return cls(
            sequence=int(raw.get("sequence", 0)),
            reason=str(raw.get("reason", "")),
            at=str(raw.get("at", "")),
            prev_digest=str(raw.get("prev_digest", GENESIS)),
            digest=str(raw.get("digest", "")),
        )


def hold_digest(hold: Hold) -> str:
    material = json.dumps(
        [hold.sequence, hold.reason, hold.at, hold.prev_digest],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class HoldLedger:
    def __init__(self, path: str, holds: list[Hold] | None = None) -> None:
        self._path = os.path.abspath(path)
        self._holds: list[Hold] = list(holds or [])

    @property
    def path(self) -> str:
        return self._path

    def holds(self) -> list[Hold]:
        return list(self._holds)

    def sequences(self) -> frozenset[int]:
        return frozenset(hold.sequence for hold in self._holds)

    def last_digest(self) -> str:
        return self._holds[-1].digest if self._holds else GENESIS

    def add(self, sequence: int, reason: str, at: str = "") -> Hold:
        if sequence < 1:
            raise ConflictError("forensic hold requires a positive entry sequence")
        if sequence in self.sequences():
            raise ConflictError(f"entry {sequence} is already under forensic hold")
        hold = Hold(
            sequence=sequence,
            reason=reason,
            at=at,
            prev_digest=self.last_digest(),
            digest="",
        )
        hold = Hold(
            sequence=hold.sequence,
            reason=hold.reason,
            at=hold.at,
            prev_digest=hold.prev_digest,
            digest=hold_digest(hold),
        )
        self._holds.append(hold)
        return hold

    def intersects(self, start: int, end: int) -> bool:
        return any(start <= sequence <= end for sequence in self.sequences())

    def verify(self) -> bool:
        previous = GENESIS
        for hold in self._holds:
            if hold.prev_digest != previous or hold_digest(hold) != hold.digest:
                return False
            previous = hold.digest
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": HOLD_ENVELOPE_VERSION,
            "count": len(self._holds),
            "digest": self.last_digest(),
            "holds": [hold.as_dict() for hold in self._holds],
        }

    @classmethod
    def from_dict(cls, path: str, raw: dict[str, Any]) -> "HoldLedger":
        holds = [Hold.from_dict(item) for item in raw.get("holds", [])]
        ledger = cls(path, holds)
        if not ledger.verify():
            raise ValidationError("forensic hold ledger failed its chain check")
        digest = str(raw.get("digest", ""))
        if digest and digest != ledger.last_digest():
            raise ValidationError("forensic hold ledger digest does not match")
        return ledger

    def persist(self) -> str:
        if not self.verify():
            raise ValidationError("refusing to persist a broken forensic hold ledger")
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        temporary = f"{self._path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(self.as_dict(), handle, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(temporary, self._path)
        return self.last_digest()

    @classmethod
    def open(cls, path: str) -> "HoldLedger":
        try:
            with open(path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            return cls(path)
        if not raw.strip():
            return cls(path)
        try:
            return cls.from_dict(path, json.loads(raw))
        except (ValueError, TypeError) as exc:
            raise ValidationError(f"hold ledger is not valid: {exc}") from exc
