"""The manifest: authoritative catalogue of shards and snapshot envelopes.

The manifest is the one file a reader must trust. It is itself a hash chain
(each published version names the hash of the previous one), and every shard
or envelope reference carries the full structural digests needed to verify
that object without trusting its presence or size. Publication is
write-temp + fsync + atomic ``os.replace`` + directory fsync, so a crash
leaves either the old manifest or the new one — never a torn manifest.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .coding import ZERO_HASH, canonical_json, sha256_hex
from .shard import ShardSummary

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1


class ManifestError(RuntimeError):
    """The manifest is missing, torn, or fails hash-chain validation."""


@dataclass(frozen=True)
class ShardRef:
    summary: ShardSummary
    compacted: bool = False
    envelope_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        raw: dict[str, Any] = {"summary": self.summary.as_dict(), "compacted": self.compacted}
        if self.envelope_id:
            raw["envelope_id"] = self.envelope_id
        return raw

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ShardRef":
        return cls(
            summary=ShardSummary.from_dict(raw["summary"]),
            compacted=bool(raw.get("compacted", False)),
            envelope_id=str(raw.get("envelope_id", "")),
        )


@dataclass(frozen=True)
class EnvelopeRef:
    envelope_id: str
    file_name: str
    body_hash: str
    state_digest: str
    seq_end: int
    shard_indices: tuple[int, ...]
    prev_envelope_id: str
    hold_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "file_name": self.file_name,
            "body_hash": self.body_hash,
            "state_digest": self.state_digest,
            "seq_end": self.seq_end,
            "shard_indices": list(self.shard_indices),
            "prev_envelope_id": self.prev_envelope_id,
            "hold_digest": self.hold_digest,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EnvelopeRef":
        return cls(
            envelope_id=str(raw["envelope_id"]),
            file_name=str(raw["file_name"]),
            body_hash=str(raw["body_hash"]),
            state_digest=str(raw["state_digest"]),
            seq_end=int(raw["seq_end"]),
            shard_indices=tuple(int(item) for item in raw.get("shard_indices", [])),
            prev_envelope_id=str(raw.get("prev_envelope_id", "")),
            hold_digest=str(raw.get("hold_digest", ZERO_HASH)),
        )


@dataclass
class Manifest:
    epoch: int = 0
    prev_manifest_hash: str = ZERO_HASH
    active_index: int = -1
    active_committed_bytes: int = 0
    active_committed_entries: int = 0
    next_seq: int = 1
    shards: dict[int, ShardRef] = field(default_factory=dict)
    envelope: EnvelopeRef | None = None
    total_appended_bytes: int = 0
    total_compacted_input_bytes: int = 0
    total_envelope_bytes: int = 0

    def content(self) -> dict[str, Any]:
        """The signed content (metadata excluded from its own hash)."""

        return {
            "version": MANIFEST_VERSION,
            "epoch": self.epoch,
            "prev_manifest_hash": self.prev_manifest_hash,
            "active_index": self.active_index,
            "active_committed_bytes": self.active_committed_bytes,
            "active_committed_entries": self.active_committed_entries,
            "next_seq": self.next_seq,
            "shards": [
                self.shards[index].as_dict()
                for index in sorted(self.shards)
            ],
            "envelope": self.envelope.as_dict() if self.envelope else None,
            "total_appended_bytes": self.total_appended_bytes,
            "total_compacted_input_bytes": self.total_compacted_input_bytes,
            "total_envelope_bytes": self.total_envelope_bytes,
        }

    def content_hash(self) -> str:
        return sha256_hex(canonical_json(self.content()))

    def as_dict(self) -> dict[str, Any]:
        raw = self.content()
        raw["manifest_hash"] = self.content_hash()
        return raw

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Manifest":
        manifest = cls(
            epoch=int(raw.get("epoch", 0)),
            prev_manifest_hash=str(raw.get("prev_manifest_hash", ZERO_HASH)),
            active_index=int(raw.get("active_index", -1)),
            active_committed_bytes=int(raw.get("active_committed_bytes", 0)),
            active_committed_entries=int(raw.get("active_committed_entries", 0)),
            next_seq=int(raw.get("next_seq", 1)),
            shards={
                ref.summary.index: ref
                for ref in (ShardRef.from_dict(item) for item in raw.get("shards", []))
            },
            envelope=(
                EnvelopeRef.from_dict(raw["envelope"])
                if raw.get("envelope") is not None
                else None
            ),
            total_appended_bytes=int(raw.get("total_appended_bytes", 0)),
            total_compacted_input_bytes=int(raw.get("total_compacted_input_bytes", 0)),
            total_envelope_bytes=int(raw.get("total_envelope_bytes", 0)),
        )
        stored = str(raw.get("manifest_hash", ""))
        if stored and stored != manifest.content_hash():
            raise ManifestError("manifest hash mismatch")
        manifest._stored_hash = stored
        return manifest

    def ordered_shards(self) -> list[ShardRef]:
        return [self.shards[index] for index in sorted(self.shards)]

    def sealed_prefix_indices(self) -> list[int]:
        """Indices of compacted or sealed shards in replay order."""

        return sorted(self.shards)


def manifest_path(directory: str) -> str:
    return os.path.join(directory, MANIFEST_NAME)


def _fsync_directory(path: str) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_manifest(directory: str, manifest: Manifest, sync: bool = True) -> str:
    """Atomically publish a new manifest, chaining it onto the previous one."""

    previous_hash = ZERO_HASH
    if os.path.exists(manifest_path(directory)):
        with open(manifest_path(directory), "rb") as handle:
            previous_raw = handle.read()
        previous = json.loads(previous_raw.decode("utf-8"))
        previous_hash = str(previous.get("manifest_hash", ""))
        old_epoch = int(previous.get("epoch", manifest.epoch))
        archive_dir = os.path.join(directory, "manifest-history")
        os.makedirs(archive_dir, exist_ok=True)
        archived = os.path.join(archive_dir, f"manifest-{old_epoch:010d}.json")
        if os.path.exists(archived):
            raise ManifestError(f"manifest history collision at epoch {old_epoch}")
        with open(archived, "wb") as handle:
            handle.write(previous_raw)
            handle.flush()
            if sync:
                os.fsync(handle.fileno())

    manifest.prev_manifest_hash = previous_hash
    manifest.epoch += 1
    raw = canonical_json(manifest.as_dict()) + b"\n"

    os.makedirs(directory, exist_ok=True)
    temporary = os.path.join(directory, ".manifest.tmp")
    with open(temporary, "wb") as handle:
        handle.write(raw)
        handle.flush()
        if sync:
            os.fsync(handle.fileno())
    os.replace(temporary, manifest_path(directory))
    if sync:
        _fsync_directory(directory)
    return manifest.content_hash()


def load_manifest(directory: str) -> Manifest | None:
    path = manifest_path(directory)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as handle:
        raw = handle.read()
    if not raw.strip():
        raise ManifestError("manifest is empty")
    try:
        return Manifest.from_dict(json.loads(raw.decode("utf-8")))
    except (ValueError, TypeError, KeyError) as exc:
        raise ManifestError(f"manifest is not readable: {exc}") from exc
