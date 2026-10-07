"""Command-line interface for the sharded, compactable command log.

Subcommands:

* ``shards``       list shards and the active slot
* ``snapshots``    list snapshot envelopes
* ``verify``       verify manifest, envelope(s) and every shard independently
* ``replay``       rebuild state and print the state digest + summary
* ``compact``      force a compaction pass (thresholds otherwise auto-fire)
* ``hold``         place a forensic hold on a sequence
* ``release``      release a forensic hold
* ``bench``        run the count-vs-bytes trigger micro-benchmark

The log itself is written programmatically (see ``ShardLog.append``); this CLI
is the operational/inspection surface.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time

from .coding import state_digest, ZERO_HASH
from .envelope import read_envelope
from .log import CompactionBlocked, ShardLog, TriggerPolicy
from .manifest import load_manifest
from .shard import verify_shard_file
from .shard import shard_path


def _policy(args: argparse.Namespace) -> TriggerPolicy:
    return TriggerPolicy(
        shard_max_bytes=args.shard_bytes,
        shard_max_entries=args.shard_entries,
        compact_bytes=args.compact_bytes,
        compact_entries=args.compact_entries,
    )


def _open(args: argparse.Namespace) -> ShardLog:
    return ShardLog.open(args.dir, policy=_policy(args), sync=not args.no_sync)


def _cmd_shards(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.dir)
    if manifest is None:
        print("no manifest yet")
        return 0
    rows = []
    for index in sorted(manifest.shards):
        ref = manifest.shards[index]
        rows.append(
            {
                "index": index,
                "seq_start": ref.summary.seq_start,
                "seq_end": ref.summary.seq_end,
                "entries": ref.summary.entry_count,
                "bytes": ref.summary.body_bytes,
                "compacted": ref.compacted,
                "envelope": ref.envelope_id or None,
                "on_disk": os.path.exists(shard_path(args.dir, index)),
            }
        )
    print(json.dumps({"active": manifest.active_index, "next_seq": manifest.next_seq,
                      "shards": rows}, indent=2))
    return 0


def _cmd_snapshots(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.dir)
    if manifest is None or manifest.envelope is None:
        print("no snapshot envelope")
        return 0
    ref = manifest.envelope
    envelope = read_envelope(os.path.join(args.dir, ref.file_name))
    print(json.dumps({
        "envelope_id": ref.envelope_id,
        "file": ref.file_name,
        "seq_end": ref.seq_end,
        "entries": envelope.entry_count,
        "shards": [summary.index for summary in envelope.shards],
        "state_digest": ref.state_digest[:16] + "...",
        "prev_envelope": ref.prev_envelope_id or None,
        "hold_digest": ref.hold_digest[:16] + "...",
        "self_verified": envelope.verify(),
    }, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    log = _open(args)
    report = log.verify()
    # independently verify each surviving shard against its declared predecessor
    prev = ZERO_HASH
    per_shard = []
    for index in sorted(log.manifest.shards):
        ref = log.manifest.shards[index]
        if ref.compacted:
            prev = ref.summary.body_hash
            continue
        summary = verify_shard_file(shard_path(args.dir, index), expected_prev=prev)
        per_shard.append({"index": index, "entries": summary.entry_count, "ok": True})
        prev = summary.body_hash
    print(json.dumps({
        "status": "ok",
        "next_seq": report.next_seq,
        "state_digest": state_digest(report.state),
        "envelope": report.loaded_envelope or None,
        "folded_shards": report.folded_shards,
        "compacted_shards": report.compacted_shards,
        "held_sequences": report.held_sequences,
        "verified_shards": per_shard,
        "checks": report.checks,
    }, indent=2))
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    log = _open(args)
    started = time.perf_counter()
    report = log.verify()
    elapsed_ms = (time.perf_counter() - started) * 1000
    payload = {
        "next_seq": report.next_seq,
        "state_digest": state_digest(report.state),
        "envelope": report.loaded_envelope or None,
        "replayed_shards": len(report.folded_shards),
        "elapsed_ms": round(elapsed_ms, 3),
    }
    if args.show_state:
        payload["state"] = report.state.as_dict()
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


def _cmd_compact(args: argparse.Namespace) -> int:
    log = _open(args)
    try:
        result = log.compact(force=args.force)
    except CompactionBlocked as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}))
        return 1
    print(json.dumps({
        "status": "compacted",
        "envelope_id": result.envelope_id,
        "shards": list(result.shard_indices),
        "entries_now": result.entries_compacted_now,
        "input_bytes": result.input_bytes,
        "envelope_bytes": result.envelope_bytes,
        "write_amplification": round(result.write_amplification, 3),
        "state_digest": result.state_digest[:16] + "...",
    }, indent=2))
    return 0


def _cmd_hold(args: argparse.Namespace) -> int:
    log = _open(args)
    record = log.holds.hold(args.seq, args.case, note=args.note)
    print(json.dumps({"status": "held", "seq": record.seq, "case": record.case_id,
                      "digest": record.digest[:16] + "..."}))
    return 0


def _cmd_release(args: argparse.Namespace) -> int:
    log = _open(args)
    record = log.release_hold(args.seq, args.case, note=args.note)
    print(json.dumps({"status": "released", "seq": record.seq, "case": record.case_id,
                      "envelope_after_release": (
                          log.manifest.envelope.envelope_id if log.manifest.envelope else None
                      )}))
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_trigger_benchmark

    result = run_trigger_benchmark(
        n=args.entries,
        detail_bytes=args.detail_bytes,
        compact_bytes=args.compact_bytes,
        compact_entries=args.compact_entries,
        shard_bytes=args.shard_bytes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shardlog", description="sharded command log")
    parser.add_argument("--dir", required=True, help="log directory")
    parser.add_argument("--shard-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--shard-entries", type=int, default=2_000)
    parser.add_argument("--compact-bytes", type=int, default=1 * 1024 * 1024)
    parser.add_argument("--compact-entries", type=int, default=10_000)
    parser.add_argument("--no-sync", action="store_true", help="skip fsync (tests only)")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("shards")
    commands.add_parser("snapshots")
    commands.add_parser("verify")
    replay = commands.add_parser("replay")
    replay.add_argument("--show-state", action="store_true")
    compact = commands.add_parser("compact")
    compact.add_argument("--force", action="store_true")
    hold = commands.add_parser("hold")
    hold.add_argument("seq", type=int)
    hold.add_argument("--case", required=True)
    hold.add_argument("--note", default="")
    release = commands.add_parser("release")
    release.add_argument("seq", type=int)
    release.add_argument("--case", required=True)
    release.add_argument("--note", default="")
    bench = commands.add_parser("bench")
    bench.add_argument("--entries", type=int, default=3000)
    bench.add_argument("--detail-bytes", type=int, default=60)
    return parser


_HANDLERS = {
    "shards": _cmd_shards,
    "snapshots": _cmd_snapshots,
    "verify": _cmd_verify,
    "replay": _cmd_replay,
    "compact": _cmd_compact,
    "hold": _cmd_hold,
    "release": _cmd_release,
    "bench": _cmd_bench,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return _HANDLERS[args.command](args)
