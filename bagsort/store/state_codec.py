"""Canonical encoding and digests for materialised state checkpoints.

A compacted shard does not keep every folded command. Instead it keeps the
*effect* of those commands as a state delta: the difference between the state
at the shard's start watermark and the state at its end watermark. Deltas are
small enough for old history while chaining them (or jumping from the latest
full checkpoint) rebuilds exactly the state a raw replay would have produced.

The canonical rendering sorts every key and uses compact separators, so a
digest is stable across processes and rejects any silent edit.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from ..model.entities import (
    AuditEntry,
    Bag,
    ChuteAssignment,
    Flight,
    LoadRecord,
    Sequence,
    SortRecord,
    TransferCommand,
)
from ..model.state import State


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def state_digest(state: State) -> str:
    return digest(state.as_dict())


_ENTITY_CODECS = {
    "flights": (Flight, "id"),
    "bags": (Bag, "id"),
    "assignments": (ChuteAssignment, "flight_id"),
    "sort_records": (SortRecord, None),
    "transfer_commands": (TransferCommand, "id"),
    "load_records": (LoadRecord, None),
    "audit": (AuditEntry, "sequence"),
}


def encode_state(state: State) -> dict[str, Any]:
    return copy.deepcopy(state.as_dict())


def decode_state(raw: dict[str, Any]) -> State:
    raw = raw or {}

    flights = {key: Flight.from_dict(value) for key, value in raw.get("flights", {}).items()}
    bags = {key: Bag.from_dict(value) for key, value in raw.get("bags", {}).items()}
    assignments = {
        key: ChuteAssignment.from_dict(value)
        for key, value in raw.get("assignments", {}).items()
    }
    return State(
        flights=flights,
        bags=bags,
        mappings=dict(raw.get("mappings", {})),
        assignments=assignments,
        sort_records=[SortRecord.from_dict(item) for item in raw.get("sort_records", [])],
        transfer_commands=[
            TransferCommand.from_dict(item) for item in raw.get("transfer_commands", [])
        ],
        load_records=[LoadRecord.from_dict(item) for item in raw.get("load_records", [])],
        audit=[AuditEntry.from_dict(item) for item in raw.get("audit", [])],
        quota_limits={
            str(key): int(value) for key, value in raw.get("quota_limits", {}).items()
        },
        counters={str(key): int(value) for key, value in raw.get("counters", {}).items()},
        sequence=Sequence.from_dict(raw.get("sequence", {})),
        recheck_queue=list(raw.get("recheck_queue", [])),
        belt_carousel=str(raw.get("belt", {}).get("carousel", "")),
        belt_batch=int(raw.get("belt", {}).get("batch", 0)),
        belt_on_carousel=list(raw.get("belt", {}).get("on_carousel", [])),
    )


# -- state delta ------------------------------------------------------------


def state_delta(before: State, after: State) -> dict[str, Any]:
    """The smallest patch describing how ``before`` becomes ``after``.

    Mutable maps use ``put``/``remove``; append-only lists record appended
    identities. The recheck queue and belt surface are order/lifecycle views, so
    they are captured wholesale when they change. The sequence allocator is a
    monotonic counter carried as an explicit value.
    """

    patch: dict[str, Any] = {}

    maps: dict[str, Any] = {
        "flights": (before.flights, after.flights),
        "bags": (before.bags, after.bags),
        "mappings": (before.mappings, after.mappings),
        "assignments": (before.assignments, after.assignments),
        "quota_limits": (before.quota_limits, after.quota_limits),
        "counters": (before.counters, after.counters),
    }
    for field, (old, new) in maps.items():
        puts = {key: new[key].as_dict() if hasattr(new[key], "as_dict") else new[key]
                for key in new if key not in old or old[key] != new[key]}
        removes = sorted(key for key in old if key not in new)
        if puts or removes:
            patch[field] = {"put": puts, "remove": removes}

    for field in ("sort_records", "transfer_commands", "load_records", "audit"):
        old_values = getattr(before, field)
        new_values = getattr(after, field)
        if len(new_values) < len(old_values):
            raise ValueError(f"field {field!r} is append-only but shrank during compaction")
        appended = [value.as_dict() for value in new_values[len(old_values):]]
        if appended:
            patch[field] = {"append": appended}

    if before.recheck_queue != after.recheck_queue:
        patch["recheck_queue"] = {"values": list(after.recheck_queue)}
    if before.belt_on_carousel != after.belt_on_carousel:
        patch["belt_on_carousel"] = {"values": list(after.belt_on_carousel)}
    if (
        before.belt_carousel != after.belt_carousel
        or before.belt_batch != after.belt_batch
    ):
        patch["belt"] = {
            "carousel": after.belt_carousel,
            "batch": after.belt_batch,
        }
    if before.sequence != after.sequence:
        patch["sequence"] = after.sequence.as_dict()
    return patch


def apply_delta(state: State, patch: dict[str, Any]) -> State:
    """Apply a delta produced by :func:`state_delta` in place."""

    map_codecs = {
        "flights": Flight,
        "bags": Bag,
        "assignments": ChuteAssignment,
    }
    for field in ("flights", "bags", "mappings", "assignments", "quota_limits", "counters"):
        change = patch.get(field)
        if not change:
            continue
        target = getattr(state, field)
        model = map_codecs.get(field)
        for key in change.get("remove", []):
            target.pop(str(key), None)
        for key, value in change.get("put", {}).items():
            target[str(key)] = model.from_dict(value) if model is not None else value

    list_models = {
        "sort_records": SortRecord,
        "transfer_commands": TransferCommand,
        "load_records": LoadRecord,
        "audit": AuditEntry,
    }
    for field, model in list_models.items():
        change = patch.get(field)
        if change:
            getattr(state, field).extend(model.from_dict(item) for item in change.get("append", []))

    if "recheck_queue" in patch:
        state.recheck_queue = list(patch["recheck_queue"].get("values", []))
    if "belt_on_carousel" in patch:
        state.belt_on_carousel = list(patch["belt_on_carousel"].get("values", []))
    if "belt" in patch:
        state.belt_carousel = str(patch["belt"].get("carousel", ""))
        state.belt_batch = int(patch["belt"].get("batch", 0))
    if "sequence" in patch:
        state.sequence = Sequence.from_dict(patch["sequence"])
    return state
