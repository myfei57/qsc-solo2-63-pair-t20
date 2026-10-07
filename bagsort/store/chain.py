"""Replay a manifest's shard chain and verify that every shard agrees with it.

There are two replay paths:

* :meth:`ShardReplayer.replay_full` starts at sequence zero, validates every
  shard in order, applies raw commands or compacted deltas, and compares every
  advertised output state digest. This is the forensic path used to prove a
  compacted history still replays to the same state.
* :meth:`ShardReplayer.replay_from_checkpoint` starts at the newest full
  checkpoint recorded in the manifest and only touches later shards. This is
  the normal restart path; bounds recovery time as history grows.

Both paths produce the same state digest. A raw shard can always be verified by
itself, while a compacted shard is verified against its boundary digests, its
summary digest, and the manifest hash of its file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from bagsort.errors import ValidationError
from bagsort.model.state import State
from . import shards as envelope
from .policy import traced_entries
from .replay import replay_all
from .state_codec import apply_delta, decode_state, state_digest
from .journal import JournalEntry

EMPTY_STATE_DIGEST = state_digest(State())


@dataclass(frozen=True)
class ReplayResult:
    state: State
    watermark: int
    traced: tuple[JournalEntry, ...]
    kinds: dict[str, int]
    shard_ids: tuple[int, ...]
    started_at: int
    output_digest: str


def _kind_tally(entries: list[JournalEntry], base: dict[str, int] | None = None) -> dict[str, int]:
    counts = dict(base or {})
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return dict(sorted(counts.items()))


class ShardReplayer:
    def __init__(self, directory: str) -> None:
        self._directory = os.path.abspath(directory)

    def _load_shard(self, descriptor: envelope.ShardDescriptor) -> envelope.Shard:
        path = os.path.join(self._directory, descriptor.file_name)
        if not os.path.isfile(path):
            raise ValidationError(f"manifest references missing shard {descriptor.file_name}")
        if envelope.file_sha256(path) != descriptor.file_digest:
            raise ValidationError(f"shard file {descriptor.file_name} failed its hash check")
        shard = envelope.Shard.from_dict(envelope.load_json_file(path), descriptor.file_name)
        if not shard.verify_self():
            raise ValidationError(f"shard {descriptor.shard_id} failed its envelope check")
        if shard.kind != descriptor.kind:
            raise ValidationError(f"shard {descriptor.shard_id} kind disagrees with manifest")
        if shard.start_sequence != descriptor.start_sequence:
            raise ValidationError(f"shard {descriptor.shard_id} start disagrees with manifest")
        if shard.end_sequence != descriptor.end_sequence:
            raise ValidationError(f"shard {descriptor.shard_id} end disagrees with manifest")
        return shard

    def _verify_interval(
        self,
        shard: envelope.Shard,
        expected_start: int,
        expected_input_digest: str,
    ) -> None:
        if shard.start_sequence != expected_start + (1 if expected_start >= 0 else 0):
            # Empty chains use start 0; first shard may start at 1.
            if not (expected_start == 0 and shard.start_sequence == 1):
                raise ValidationError(
                    f"shard {shard.shard_id} has a sequence gap: "
                    f"{expected_start} -> {shard.start_sequence}"
                )
        if shard.input_state_digest != expected_input_digest and shard.is_compact:
            raise ValidationError(
                f"compact shard {shard.shard_id} input digest does not chain"
            )

    def replay_full(self, manifest: envelope.Manifest) -> ReplayResult:
        state = State()
        previous_end = 0
        previous_digest = EMPTY_STATE_DIGEST
        traced: list[JournalEntry] = []
        kinds: dict[str, int] = {}
        ids: list[int] = []
        for descriptor in manifest.shards:
            shard = self._load_shard(descriptor)
            if shard.start_sequence != previous_end + 1:
                raise ValidationError(
                    f"shard {shard.shard_id} does not continue sequence {previous_end}"
                )
            if shard.kind == envelope.RAW:
                state = replay_all(list(shard.entries), state)
                kinds = _kind_tally(list(shard.entries), kinds)
            else:
                if shard.input_state_digest != previous_digest:
                    raise ValidationError(
                        f"compact shard {shard.shard_id} starts from the wrong state"
                    )
                state = apply_delta(state, shard.delta or {})
                kinds = _kind_tally(list(shard.entries), kinds)
                traced.extend(shard.entries)
            output = state_digest(state)
            if shard.output_state_digest != output:
                raise ValidationError(
                    f"shard {shard.shard_id} output state digest does not match replay"
                )
            if descriptor.output_state_digest != output:
                raise ValidationError(
                    f"manifest output digest for shard {shard.shard_id} does not match replay"
                )
            previous_end = shard.end_sequence
            previous_digest = output
            ids.append(shard.shard_id)
        if previous_end != manifest.watermark:
            raise ValidationError("manifest watermark does not end the shard chain")
        return ReplayResult(
            state=state,
            watermark=previous_end,
            traced=tuple(traced),
            kinds=kinds,
            shard_ids=tuple(ids),
            started_at=0,
            output_digest=previous_digest,
        )

    def replay_from_checkpoint(self, manifest: envelope.Manifest) -> ReplayResult:
        if not manifest.checkpoint:
            return self.replay_full(manifest)
        checkpoint_path = os.path.join(self._directory, str(manifest.checkpoint["file"]))
        if envelope.file_sha256(checkpoint_path) != str(manifest.checkpoint["file_digest"]):
            raise ValidationError("checkpoint file failed its hash check")
        checkpoint = envelope.Checkpoint.from_dict(
            envelope.load_json_file(checkpoint_path)
        )
        state = decode_state(checkpoint.state)
        watermark = checkpoint.watermark
        if watermark != int(manifest.checkpoint["watermark"]):
            raise ValidationError("checkpoint watermark disagrees with manifest")
        if state_digest(state) != checkpoint.state_digest_value:
            raise ValidationError("checkpoint state digest does not decode")

        previous_end = watermark
        previous_digest = checkpoint.state_digest_value
        traced: list[JournalEntry] = []
        kinds: dict[str, int] = dict(manifest.checkpoint.get("kinds", {}))
        ids: list[int] = []
        for descriptor in manifest.shards:
            if descriptor.end_sequence <= watermark:
                continue
            shard = self._load_shard(descriptor)
            if shard.start_sequence != previous_end + 1:
                raise ValidationError(
                    f"shard {shard.shard_id} does not continue checkpoint {previous_end}"
                )
            if shard.kind == envelope.COMPACT:
                if shard.input_state_digest != previous_digest:
                    raise ValidationError(
                        f"compact shard {shard.shard_id} starts from the wrong state"
                    )
                state = apply_delta(state, shard.delta or {})
                kinds = _kind_tally(list(shard.entries), kinds)
                traced.extend(shard.entries)
            else:
                state = replay_all(list(shard.entries), state)
                kinds = _kind_tally(list(shard.entries), kinds)
            output = state_digest(state)
            if shard.output_state_digest != output:
                raise ValidationError(
                    f"shard {shard.shard_id} output state digest does not match replay"
                )
            previous_end = shard.end_sequence
            previous_digest = output
            ids.append(shard.shard_id)
        if previous_end != manifest.watermark:
            raise ValidationError("manifest watermark does not end the checkpoint chain")
        return ReplayResult(
            state=state,
            watermark=previous_end,
            traced=tuple(traced),
            kinds=kinds,
            shard_ids=tuple(ids),
            started_at=watermark,
            output_digest=previous_digest,
        )

    def verify_chain(self, manifest: envelope.Manifest) -> bool:
        """Full-chain proof; used by explicit verification and tests."""

        full = self.replay_full(manifest)
        fast = self.replay_from_checkpoint(manifest)
        return full.output_digest == fast.output_digest and full.watermark == fast.watermark
