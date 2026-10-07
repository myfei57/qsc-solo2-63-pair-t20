"""Rebuild materialised state from a committed journal.

A journal is a chain of shards. A raw shard contributes its commands one by
one. A compacted shard contributes a state checkpoint (the folded effect of
everything up to its watermark) followed by the entries it kept verbatim as
*traced* evidence; traced entries are skipped on replay because their effect is
already represented in the checkpoint. Either entry point rebuilds the same
:class:`~bagsort.model.state.State`, which is what "replay equivalence after
compaction" means in code.
"""

from __future__ import annotations

import copy
from typing import Any, Iterable

from bagsort.model.state import State, apply_entry
from .journal import JournalEntry


def replay(entries: Iterable[JournalEntry], base: State | None = None) -> State:
    """Fold committed entries into a fresh (or supplied) :class:`State`.

    Entries flagged ``traced`` are historical records preserved by a compaction
    summary. They must not be applied again: a compacted shard's checkpoint
    already contains their effect.
    """

    state = copy.deepcopy(base) if base is not None else State()
    for entry in entries:
        if entry.traced:
            continue
        apply_entry(state, entry.kind, entry.payload)
    return state


def replay_all(entries: Iterable[JournalEntry], base: State | None = None) -> State:
    """Apply every entry, traced ones included.

    Used while *building* a summary, where the entries come straight from a raw
    shard and must all be folded exactly once. It is deliberately a different
    name from :func:`replay` so a reader can tell checkpoint-aware replay from
    raw folding.
    """

    state = copy.deepcopy(base) if base is not None else State()
    for entry in entries:
        apply_entry(state, entry.kind, entry.payload)
    return state


def command_pairs(entries: Iterable[JournalEntry]) -> list[tuple[str, dict[str, Any]]]:
    return [(entry.kind, entry.payload) for entry in entries if not entry.traced]
