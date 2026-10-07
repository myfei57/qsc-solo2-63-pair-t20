"""Sharded, compactable command log with snapshot envelopes.

The shard log turns the single growing command journal into:

* sealed *shards* ("old shards") that only need their summary once compacted,
* one *active* shard that keeps accepting appended commands,
* checksummed *snapshot envelopes* ("snap-XXXX.env") summarising compacted
  prefixes of history,
* a hash-chained :class:`Manifest` that binds shards and envelopes together.

Every on-disk object is self describing and independently verifiable; the
replayer can rebuild the exact same materialised state either from the raw
shards or from a snapshot envelope plus the remaining shards.
"""

from .coding import (
    STATE_DIGEST_EMPTY,
    canonical_entry,
    canonical_state,
    state_digest,
)
from .manifest import EnvelopeRef, Manifest, ShardRef
from .shard import (
    FOOTER_SIZE,
    HEADER_MAGIC,
    HEADER_SIZE,
    RECORD_FLAG_HELD,
    ShardHandle,
    ShardSummary,
    iter_shard_records,
    read_shard_footer,
    record_frame_len,
    shard_path,
    verify_shard_file,
)
from .envelope import SnapshotEnvelope, read_envelope
from .log import CompactionBlocked, CompactionResult, ShardLog, TriggerPolicy
from .replay import ReplayReport, replay_log, verify_log

__all__ = [
    "STATE_DIGEST_EMPTY",
    "canonical_entry",
    "canonical_state",
    "state_digest",
    "EnvelopeRef",
    "Manifest",
    "ShardRef",
    "FOOTER_SIZE",
    "HEADER_MAGIC",
    "HEADER_SIZE",
    "RECORD_FLAG_HELD",
    "ShardHandle",
    "ShardSummary",
    "iter_shard_records",
    "read_shard_footer",
    "shard_path",
    "verify_shard_file",
    "SnapshotEnvelope",
    "read_envelope",
    "CompactionBlocked",
    "CompactionResult",
    "ShardLog",
    "TriggerPolicy",
    "ReplayReport",
    "replay_log",
    "verify_log",
]
