"""Canonical encodings and digests shared by shards, envelopes and the manifest.

All integrity hashes are SHA-256 over *canonical* bytes, so the same logical
record always hashes to the same value regardless of which process serialised
it. State digests hash the folded materialised state (see ``State.as_dict``),
which is what makes two replays provably equivalent.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..journal import JournalEntry
from ...model.state import State

#: Digests are 32 raw bytes / 64 hex chars.
ZERO_HASH = "0" * 64
#: Digest of the state produced by replaying zero entries.
STATE_DIGEST_EMPTY = hashlib.sha256(
    json.dumps(State().as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
).hexdigest()


def canonical_json(value: Any) -> bytes:
    """Stable, key-sorted JSON bytes for ``value``."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_entry(entry: JournalEntry) -> bytes:
    """Canonical bytes of one committed command, without any record framing."""

    return canonical_json(entry.as_dict())


def entry_digest(entry: JournalEntry) -> str:
    return sha256_hex(canonical_entry(entry))


def canonical_state(state: State) -> bytes:
    """Canonical bytes of a folded materialised state."""

    return canonical_json(state.as_dict())


def state_digest(state: State) -> str:
    """Content digest of a folded state; identical states share one digest."""

    return sha256_hex(canonical_state(state))
