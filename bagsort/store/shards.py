"""Shard envelopes, the manifest, and their on-disk layout.

Three artefacts cross-check each other:

* a **raw shard** is the committed commands in one interval, with a digest over
  their canonical rendering;
* a **compact shard** replaces one sealed raw shard. It carries the state delta
  between the shard boundaries, the digest of the raw stream it summarised, the
  entries kept verbatim as traced evidence, and input/output state digests;
* the **manifest** is the ordered directory of shards. Every descriptor has the
  SHA-256 of that shard file's bytes, interval boundaries, and the output state
  digest. Its own digest is a hash over the descriptor chain, so reordering,
  deleting or substituting a shard breaks verification.

Each file is written to ``<name>.tmp`` and installed with ``os.replace``: a
crash leaves either the previous file or the new one, never a half shard.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from bagsort.errors import ValidationError
from .journal import JournalEntry
from .snapshot import digest_for as entries_digest
from .state_codec import digest as json_digest

RAW = "raw"
COMPACT = "compact"
SHARD_ENVELOPE_VERSION = 1
MANIFEST_VERSION = 1
MANIFEST_NAME = "manifest.json"
HOLDS_NAME = "holds.json"
CHECKPOINT_NAME = "checkpoint.json"
CHECKPOINT_VERSION = 1


def file_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _entries(raw: Any) -> tuple[JournalEntry, ...]:
    if not isinstance(raw, list):
        raise ValidationError("shard entries must be a list")
    return tuple(JournalEntry.from_dict(item) for item in raw)


@dataclass(frozen=True)
class Shard:
    """Either a raw command interval or its compacted summary envelope."""

    shard_id: int
    kind: str
    start_sequence: int
    end_sequence: int
    entries: tuple[JournalEntry, ...]
    digest: str
    input_state_digest: str = ""
    output_state_digest: str = ""
    delta: dict[str, Any] | None = None
    raw_digest: str = ""
    source_file: str = ""
    entry_count: int = 0
    folded_count: int = 0
    traced_count: int = 0
    version: int = SHARD_ENVELOPE_VERSION
    file_name: str = ""

    @property
    def is_compact(self) -> bool:
        return self.kind == COMPACT

    def as_dict(self) -> dict[str, Any]:
        raw: dict[str, Any] = {
            "version": self.version,
            "shard_id": self.shard_id,
            "kind": self.kind,
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "input_state_digest": self.input_state_digest,
            "output_state_digest": self.output_state_digest,
            "digest": self.digest,
        }
        if self.kind == RAW:
            raw["entry_count"] = len(self.entries)
            raw["entries"] = [entry.as_dict() for entry in self.entries]
        else:
            raw.update(
                {
                    "entry_count": self.entry_count,
                    "folded_count": self.folded_count,
                    "traced_count": self.traced_count,
                    "raw_digest": self.raw_digest,
                    "delta": self.delta or {},
                    "traced": [entry.as_dict() for entry in self.entries],
                }
            )
        return raw

    @classmethod
    def from_dict(cls, raw: dict[str, Any], file_name: str = "") -> "Shard":
        kind = str(raw.get("kind", ""))
        if kind not in {RAW, COMPACT}:
            raise ValidationError(f"unknown shard kind {kind!r}")
        entries = _entries(raw.get("entries" if kind == RAW else "traced", []))
        return cls(
            shard_id=int(raw.get("shard_id", 0)),
            kind=kind,
            start_sequence=int(raw.get("start_sequence", 0)),
            end_sequence=int(raw.get("end_sequence", 0)),
            entries=entries,
            digest=str(raw.get("digest", "")),
            input_state_digest=str(raw.get("input_state_digest", "")),
            output_state_digest=str(raw.get("output_state_digest", "")),
            delta=dict(raw.get("delta", {})) if kind == COMPACT else None,
            raw_digest=str(raw.get("raw_digest", "")),
            source_file=str(raw.get("source_file", "")),
            entry_count=int(raw.get("entry_count", len(entries))),
            folded_count=int(raw.get("folded_count", 0)),
            traced_count=int(raw.get("traced_count", 0)),
            version=int(raw.get("version", SHARD_ENVELOPE_VERSION)),
            file_name=file_name,
        )

    def verify_self(self) -> bool:
        """Structural and digest checks that do not need any other shard."""

        if self.kind == RAW:
            if entries_digest(list(self.entries)) != self.digest:
                return False
            if self.entry_count and self.entry_count != len(self.entries):
                return False
        else:
            expected = json_digest(
                {
                    "version": self.version,
                    "shard_id": self.shard_id,
                    "start_sequence": self.start_sequence,
                    "end_sequence": self.end_sequence,
                    "input_state_digest": self.input_state_digest,
                    "output_state_digest": self.output_state_digest,
                    "raw_digest": self.raw_digest,
                    "delta": self.delta or {},
                    "traced_digest": entries_digest(list(self.entries)),
                    "entry_count": self.entry_count,
                    "folded_count": self.folded_count,
                    "traced_count": self.traced_count,
                }
            )
            if expected != self.digest:
                return False
            if len(self.entries) != self.traced_count:
                return False
            if self.entry_count != self.folded_count + self.traced_count:
                return False
            if any(not entry.traced for entry in self.entries):
                return False
        if self.entries:
            if self.entries[0].sequence != self.start_sequence:
                return False
            if self.entries[-1].sequence != self.end_sequence:
                return False
        sequences = [entry.sequence for entry in self.entries]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            return False
        return True


def raw_shard(shard_id: int, entries: list[JournalEntry]) -> Shard:
    start = entries[0].sequence
    end = entries[-1].sequence
    digest_value = entries_digest(entries)
    return Shard(
        shard_id=shard_id,
        kind=RAW,
        start_sequence=start,
        end_sequence=end,
        entries=tuple(entries),
        digest=digest_value,
        entry_count=len(entries),
    )


def compact_shard(
    source: Shard,
    delta: dict[str, Any],
    traced: list[JournalEntry],
    input_state_digest: str,
    output_state_digest: str,
    source_file: str,
) -> Shard:
    if source.kind != RAW:
        raise ValidationError("only a raw shard can be compacted")
    marked = tuple(
        JournalEntry(
            sequence=entry.sequence,
            kind=entry.kind,
            payload=entry.payload,
            at=entry.at,
            traced=True,
        )
        for entry in traced
    )
    folded = source.entry_count - len(marked)
    body = {
        "version": SHARD_ENVELOPE_VERSION,
        "shard_id": source.shard_id,
        "start_sequence": source.start_sequence,
        "end_sequence": source.end_sequence,
        "input_state_digest": input_state_digest,
        "output_state_digest": output_state_digest,
        "raw_digest": source.digest,
        "delta": delta,
        "traced_digest": entries_digest(list(marked)),
        "entry_count": source.entry_count,
        "folded_count": folded,
        "traced_count": len(marked),
    }
    return Shard(
        shard_id=source.shard_id,
        kind=COMPACT,
        start_sequence=source.start_sequence,
        end_sequence=source.end_sequence,
        entries=marked,
        digest=json_digest(body),
        input_state_digest=input_state_digest,
        output_state_digest=output_state_digest,
        delta=delta,
        raw_digest=source.digest,
        source_file=source_file,
        entry_count=source.entry_count,
        folded_count=folded,
        traced_count=len(marked),
    )


@dataclass(frozen=True)
class ShardDescriptor:
    shard_id: int
    kind: str
    file_name: str
    file_digest: str
    start_sequence: int
    end_sequence: int
    output_state_digest: str
    entry_count: int
    generation: int = 1
    source_file: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "shard_id": self.shard_id,
            "kind": self.kind,
            "file": self.file_name,
            "file_digest": self.file_digest,
            "start_sequence": self.start_sequence,
            "end_sequence": self.end_sequence,
            "output_state_digest": self.output_state_digest,
            "entry_count": self.entry_count,
            "generation": self.generation,
            "source_file": self.source_file,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ShardDescriptor":
        return cls(
            shard_id=int(raw["shard_id"]),
            kind=str(raw["kind"]),
            file_name=str(raw["file"]),
            file_digest=str(raw["file_digest"]),
            start_sequence=int(raw["start_sequence"]),
            end_sequence=int(raw["end_sequence"]),
            output_state_digest=str(raw["output_state_digest"]),
            entry_count=int(raw["entry_count"]),
            generation=int(raw.get("generation", 1)),
            source_file=str(raw.get("source_file", "")),
        )


@dataclass(frozen=True)
class Manifest:
    shards: tuple[ShardDescriptor, ...]
    watermark: int
    generation: int
    holds_digest: str
    checkpoint: dict[str, Any] | None = None
    digest: str = ""
    version: int = MANIFEST_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generation": self.generation,
            "watermark": self.watermark,
            "holds_digest": self.holds_digest,
            "checkpoint": self.checkpoint,
            "shards": [shard.as_dict() for shard in self.shards],
            "digest": self.digest,
        }

    def descriptor_for(self, shard_id: int) -> ShardDescriptor | None:
        for descriptor in self.shards:
            if descriptor.shard_id == shard_id:
                return descriptor
        return None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Manifest":
        shards = tuple(
            ShardDescriptor.from_dict(item) for item in raw.get("shards", [])
        )
        manifest = cls(
            shards=shards,
            watermark=int(raw.get("watermark", 0)),
            generation=int(raw.get("generation", 0)),
            holds_digest=str(raw.get("holds_digest", "")),
            checkpoint=raw.get("checkpoint"),
            digest=str(raw.get("digest", "")),
            version=int(raw.get("version", MANIFEST_VERSION)),
        )
        if manifest.digest and manifest.digest != unsigned_digest(manifest):
            raise ValidationError("manifest digest does not match its shard chain")
        return manifest


def unsigned_digest(manifest: Manifest) -> str:
    payload = {
        "version": manifest.version,
        "generation": manifest.generation,
        "watermark": manifest.watermark,
        "holds_digest": manifest.holds_digest,
        "checkpoint": manifest.checkpoint,
        "shards": [shard.as_dict() for shard in manifest.shards],
    }
    return json_digest(payload)


def signed_manifest(
    shards: list[ShardDescriptor],
    watermark: int,
    generation: int,
    holds_digest: str,
    checkpoint: dict[str, Any] | None,
) -> Manifest:
    draft = Manifest(
        shards=tuple(shards),
        watermark=watermark,
        generation=generation,
        holds_digest=holds_digest,
        checkpoint=checkpoint,
    )
    return Manifest(
        shards=draft.shards,
        watermark=draft.watermark,
        generation=draft.generation,
        holds_digest=draft.holds_digest,
        checkpoint=draft.checkpoint,
        digest=unsigned_digest(draft),
    )


def atomic_write_json(path: str, payload: dict[str, Any]) -> str:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    temporary = f"{path}.tmp"
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return file_sha256(path)


def load_json_file(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.loads(handle.read())


def shard_file_name(shard_id: int, kind: str, generation: int = 1) -> str:
    return f"shard-{shard_id:06d}-{kind}-g{generation:02d}.json"


# -- full checkpoint envelope ----------------------------------------------


@dataclass(frozen=True)
class Checkpoint:
    """A full materialised state shortcut for long compacted histories."""

    watermark: int
    state: dict[str, Any]
    state_digest_value: str
    digest: str = ""
    version: int = CHECKPOINT_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "watermark": self.watermark,
            "state": self.state,
            "state_digest": self.state_digest_value,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Checkpoint":
        checkpoint = cls(
            watermark=int(raw.get("watermark", 0)),
            state=dict(raw.get("state", {})),
            state_digest_value=str(raw.get("state_digest", "")),
            digest=str(raw.get("digest", "")),
            version=int(raw.get("version", CHECKPOINT_VERSION)),
        )
        if checkpoint.state_digest_value != json_digest(checkpoint.state):
            raise ValidationError("checkpoint state digest does not match")
        expected = json_digest(
            {
                "version": checkpoint.version,
                "watermark": checkpoint.watermark,
                "state": checkpoint.state,
                "state_digest": checkpoint.state_digest_value,
            }
        )
        if checkpoint.digest != expected:
            raise ValidationError("checkpoint envelope digest does not match")
        return checkpoint


def build_checkpoint(watermark: int, state: dict[str, Any], state_digest_value: str) -> Checkpoint:
    draft = Checkpoint(
        watermark=watermark,
        state=state,
        state_digest_value=state_digest_value,
    )
    digest_value = json_digest(
        {
            "version": draft.version,
            "watermark": draft.watermark,
            "state": draft.state,
            "state_digest": draft.state_digest_value,
        }
    )
    return Checkpoint(
        watermark=watermark,
        state=state,
        state_digest_value=state_digest_value,
        digest=digest_value,
    )
