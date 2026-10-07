"""Snapshot envelopes: the compacted form of a prefix of command history.

An envelope is the only *new* data a compaction writes. It contains:

* ``state`` — the materialised state folded from every entry up to ``seq_end``,
  serialised canonically, with ``state_digest`` independently recomputable;
* ``shards`` — one :class:`ShardSummary` per compacted shard (nothing else of
  those shards is kept on disk afterwards);
* linkage fields chaining this envelope onto its predecessor and binding the
  forensic-hold register at compaction time.

The file is canonical JSON plus a trailing ASCII footer line carrying the hash
of the body, so the file is verifiable on its own (``verify_file``) without the
manifest.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from ...model.state import State
from .coding import ZERO_HASH, canonical_json, sha256_hex, state_digest
from .shard import ShardSummary

ENVELOPE_VERSION = 1
ENVELOPE_PREFIX = "snap-"
ENVELOPE_SUFFIX = ".env"
ENVELOPE_FOOTER_MARKER = b"BAGSNAP1 "


class EnvelopeError(RuntimeError):
    """An envelope is unreadable or fails verification."""


def envelope_file_name(envelope_id: str) -> str:
    return f"{ENVELOPE_PREFIX}{envelope_id}{ENVELOPE_SUFFIX}"


def envelope_path(directory: str, envelope_id: str) -> str:
    return os.path.join(directory, envelope_file_name(envelope_id))


@dataclass
class SnapshotEnvelope:
    envelope_id: str
    seq_end: int
    state_digest: str
    state: State
    shards: list[ShardSummary] = field(default_factory=list)
    prev_envelope_id: str = ""
    hold_digest: str = ZERO_HASH
    entry_count: int = 0
    version: int = ENVELOPE_VERSION

    def body_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "envelope_id": self.envelope_id,
            "prev_envelope_id": self.prev_envelope_id,
            "seq_end": self.seq_end,
            "entry_count": self.entry_count,
            "state_digest": self.state_digest,
            "hold_digest": self.hold_digest,
            "shards": [summary.as_dict() for summary in self.shards],
            "state": self.state.as_dict(),
        }

    def encode(self) -> bytes:
        body = canonical_json(self.body_dict())
        return body + b"\n" + ENVELOPE_FOOTER_MARKER + sha256_hex(body).encode("ascii") + b"\n"

    @classmethod
    def decode(cls, raw: bytes) -> "SnapshotEnvelope":
        marker = b"\n" + ENVELOPE_FOOTER_MARKER
        split_at = raw.rfind(marker)
        if split_at < 0:
            raise EnvelopeError("envelope missing checksum footer")
        body = raw[:split_at]
        stored_hash = raw[split_at + len(marker):].strip()
        if sha256_hex(body) != stored_hash.decode("ascii"):
            raise EnvelopeError("envelope body hash mismatch")
        try:
            data = json.loads(body)
            state = State.from_dict(data.get("state", {}))
            return cls(
                envelope_id=str(data["envelope_id"]),
                seq_end=int(data["seq_end"]),
                state_digest=str(data["state_digest"]),
                state=state,
                shards=[ShardSummary.from_dict(item) for item in data.get("shards", [])],
                prev_envelope_id=str(data.get("prev_envelope_id", "")),
                hold_digest=str(data.get("hold_digest", ZERO_HASH)),
                entry_count=int(data.get("entry_count", 0)),
                version=int(data.get("version", ENVELOPE_VERSION)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EnvelopeError(f"envelope fields are invalid: {exc}") from exc

    def verify(self, state: State | None = None) -> bool:
        """Recompute the state digest and every shard-link invariant.

        With no argument the state loaded with the envelope is checked; a
        freshly replayed state can be passed in to prove replay equivalence.
        """

        candidate = self.state if state is None else state
        if state_digest(candidate) != self.state_digest:
            return False
        total = sum(summary.entry_count for summary in self.shards)
        if total != self.entry_count:
            return False
        if self.shards:
            if self.shards[0].seq_start != 1 and not self.prev_envelope_id:
                return False
            if self.shards[-1].seq_end != self.seq_end:
                return False
            for previous, current in zip(self.shards, self.shards[1:]):
                if current.seq_start != previous.seq_end + 1:
                    return False
        return True


def read_envelope(path: str) -> SnapshotEnvelope:
    """Read an envelope from disk, verifying its outer checksum."""

    with open(path, "rb") as handle:
        return SnapshotEnvelope.decode(handle.read())


def write_envelope_atomic(directory: str, envelope: SnapshotEnvelope, sync: bool = True) -> str:
    """Write the envelope via a temp file + atomic rename; returns its path."""

    path = envelope_path(directory, envelope.envelope_id)
    temporary = f"{path}.tmp"
    with open(temporary, "wb") as handle:
        handle.write(envelope.encode())
        handle.flush()
        if sync:
            os.fsync(handle.fileno())
    os.replace(temporary, path)
    return path
