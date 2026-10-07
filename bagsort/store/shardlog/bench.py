"""Trigger-policy micro-benchmark: write amplification vs replay cost.

The two compaction triggers pull in opposite directions. This module measures
both sides on a synthetic append-only workload so the choice can be made with
the write-amplification cost stated explicitly instead of as a rule of thumb.

Costs measured
--------------
* ``write_amplification`` -- cumulative snapshot envelope bytes written divided
  by cumulative compacted shard bytes. Every compaction rewrites the *whole*
  folded state, so compacting more often (or compacting byte-tiny prefixes on a
  count trigger) pushes this number up.
* ``replay_records`` / ``replay_ms`` -- how many surviving records must be
  folded on restart and how long it takes. A count trigger bounds this by
  command count regardless of command size; a bytes trigger bounds it by the
  byte threshold and therefore allows more records to survive when records are
  small.
"""

from __future__ import annotations

import glob
import os
import tempfile
import time

from ..journal import JournalEntry
from .coding import state_digest
from .log import ShardLog, TriggerPolicy
from .shard import iter_shard_records, shard_path


def _entry(seq: int, detail_bytes: int) -> JournalEntry:
    return JournalEntry(
        sequence=seq,
        kind="audit.append",
        payload={
            "entry": {
                "sequence": seq,
                "kind": "ev",
                "subject": f"bag-{seq:08d}",
                "detail": {"blob": "y" * detail_bytes},
            }
        },
    )


def _run_once(
    policy: TriggerPolicy, n: int, detail_bytes: int
) -> tuple[dict[str, float], ShardLog, str]:
    directory = tempfile.mkdtemp(prefix="shardlog-bench-")
    log = ShardLog.open(directory, policy=policy, sync=False)
    compactions = 0
    last_input = 0
    last_envelope = 0
    original = log.compact

    def counting(*args, **kwargs):
        nonlocal compactions, last_input, last_envelope
        result = original(*args, **kwargs)
        compactions += 1
        last_input = result.input_bytes
        last_envelope = result.envelope_bytes
        return result

    log.compact = counting  # type: ignore[assignment]
    started = time.perf_counter()
    for seq in range(1, n + 1):
        log.append(_entry(seq, detail_bytes))
    append_ms = (time.perf_counter() - started) * 1000

    surviving_shard_bytes = sum(
        os.path.getsize(path) for path in glob.glob(os.path.join(directory, "log-*.shard"))
    )
    envelope_bytes_on_disk = sum(
        os.path.getsize(path) for path in glob.glob(os.path.join(directory, "snap-*.env"))
    )

    reopened = ShardLog.open(directory, policy=policy, sync=False)
    started = time.perf_counter()
    report = reopened.verify()
    replay_ms = (time.perf_counter() - started) * 1000
    replay_records = 0
    for index in report.folded_shards:
        _h, records, _torn, _f = iter_shard_records(shard_path(directory, index))
        replay_records += len(records)

    manifest = reopened.manifest
    amplification = (
        manifest.total_envelope_bytes / manifest.total_compacted_input_bytes
        if manifest.total_compacted_input_bytes
        else 0.0
    )
    metrics = {
        "compactions": compactions,
        "write_amplification": round(amplification, 3),
        "snapshot_bytes_written": manifest.total_envelope_bytes,
        "compacted_input_bytes": manifest.total_compacted_input_bytes,
        "last_run_input_bytes": last_input,
        "last_run_envelope_bytes": last_envelope,
        "surviving_shard_bytes": surviving_shard_bytes,
        "envelope_bytes_on_disk": envelope_bytes_on_disk,
        "replay_records": replay_records,
        "replay_ms": round(replay_ms, 3),
        "append_ms": round(append_ms, 2),
        "final_state_digest": state_digest(reopened.state),
    }
    return metrics, reopened, directory


def run_trigger_benchmark(
    n: int = 3000,
    detail_bytes: int = 60,
    compact_bytes: int = 64 * 1024,
    compact_entries: int = 500,
    shard_bytes: int = 16 * 1024,
) -> dict[str, object]:
    """Run the same workload twice, differing only in the compaction trigger."""

    import shutil

    bytes_policy = TriggerPolicy(
        shard_max_bytes=shard_bytes,
        shard_max_entries=10 ** 9,
        compact_bytes=compact_bytes,
        compact_entries=0,
    )
    count_policy = TriggerPolicy(
        shard_max_bytes=shard_bytes,
        shard_max_entries=10 ** 9,
        compact_bytes=10 ** 18,
        compact_entries=compact_entries,
    )

    bytes_metrics, _b, bytes_dir = _run_once(bytes_policy, n, detail_bytes)
    count_metrics, _c, count_dir = _run_once(count_policy, n, detail_bytes)
    shutil.rmtree(bytes_dir, ignore_errors=True)
    shutil.rmtree(count_dir, ignore_errors=True)

    ratio = (
        count_metrics["write_amplification"] / bytes_metrics["write_amplification"]
        if bytes_metrics["write_amplification"]
        else 0.0
    )
    return {
        "workload": {"entries": n, "detail_bytes": detail_bytes, "shard_bytes": shard_bytes},
        "triggers": {"compact_bytes": compact_bytes, "compact_entries": compact_entries},
        "bytes_trigger": bytes_metrics,
        "count_trigger": count_metrics,
        "count_over_bytes_wa_ratio": round(ratio, 3),
        "interpretation": (
            "bytes trigger writes fewer snapshot bytes when records are small "
            "(compaction waits for real disk occupancy); count trigger caps "
            "replay records regardless of size but rewrites the snapshot at a "
            "fixed command cadence, which dominates as entry size shrinks."
        ),
    }
