"""The shard log writer: append, roll over, compact, recover.

Crash-safety model
------------------
Every state transition is a small sequence of *durable* steps with an explicit
recovery rule, so no crash point leaves a half shard or an ambiguous layout:

1. record frames are appended (and fsynced) to the active shard before the
   manifest is touched — a recovered torn tail is truncated on open;
2. rollover seals the old shard (footer + fsync) then publishes a manifest that
   names the sealed shard and clears the active slot. A shard whose footer
   exists but the manifest does not know about is adopted; a footerless shard
   the manifest does not know about is discarded as a pre-commit artifact;
3. compaction writes only temp/auxiliary files first (intent journal plus the
   envelope), then a single atomic manifest publish is the *commit point*. The
   intent journal makes every post-commit step (delete input shards, delete the
   journal itself) idempotent on restart.
"""

from __future__ import annotations

import glob
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from ...model.state import State, apply_entry
from ..journal import JournalEntry
from .coding import ZERO_HASH, sha256_hex, state_digest
from .envelope import (
    SnapshotEnvelope,
    envelope_file_name,
    envelope_path,
    read_envelope,
    write_envelope_atomic,
)
from .holds import HoldRegister
from .manifest import (
    EnvelopeRef,
    Manifest,
    ShardRef,
    load_manifest,
    publish_manifest,
)
from .replay import ReplayReport, _fold_shard_indices, replay_log
from .shard import (
    HEADER_SIZE,
    Corruption,
    ShardHandle,
    iter_shard_records,
    read_shard_footer,
    record_frame_len,
    shard_path,
)

JOURNAL_DIR_NAME = "compaction"


class CompactionBlocked(RuntimeError):
    """Compaction cannot proceed: empty prefix, threshold not met, or a hold."""


@dataclass(frozen=True)
class TriggerPolicy:
    """When shards roll over and when compaction fires.

    Two compaction signals are offered because their costs pull in opposite
    directions (see ``docs/compaction.md``):

    * ``compact_bytes`` fires once compactable sealed shards hold at least this
      many bytes. It bounds work to real disk occupancy — the default, and the
      choice that keeps **write amplification** low;
    * ``compact_entries`` also forces a compaction after this many commands,
      regardless of byte size. Count triggering gives a steady command-budget
      for restart replay, but rewrites the snapshot's fixed state size even
      when entries are tiny: its write amplification is
      ``state_bytes / compacted_bytes`` and is unbounded as entries shrink.
    """

    shard_max_bytes: int = 4 * 1024 * 1024
    shard_max_entries: int = 2_000
    compact_bytes: int = 1 * 1024 * 1024
    compact_entries: int = 10_000

    def shard_rolls_over(self, body_bytes: int, entry_count: int) -> bool:
        return body_bytes >= self.shard_max_bytes or entry_count >= self.shard_max_entries

    def compact_due(self, compactable_bytes: int, compactable_entries: int) -> bool:
        if compactable_entries == 0:
            return False
        if self.compact_bytes > 0 and compactable_bytes >= self.compact_bytes:
            return True
        if self.compact_entries > 0 and compactable_entries >= self.compact_entries:
            return True
        return False


@dataclass(frozen=True)
class CompactionResult:
    envelope_id: str
    shard_indices: tuple[int, ...]
    entries_in_envelope: int
    entries_compacted_now: int
    input_bytes: int
    envelope_bytes: int
    seq_end: int
    state_digest: str

    @property
    def write_amplification(self) -> float:
        """Envelope bytes written over bytes of shards folded *this run*.

        With a bytes trigger this stays close to ``state_size / shard_size``;
        a count trigger can push it arbitrarily high for tiny commands.
        """

        if self.input_bytes == 0:
            return 0.0
        return self.envelope_bytes / self.input_bytes


CrashHook = Callable[[str], None]


class ShardLog:
    def __init__(
        self,
        directory: str,
        policy: TriggerPolicy | None = None,
        sync: bool = True,
        crash_hook: CrashHook | None = None,
    ) -> None:
        self._dir = os.path.abspath(directory)
        self._policy = policy or TriggerPolicy()
        self._sync = sync
        self._crash_hook = crash_hook or (lambda point: None)
        self._manifest = Manifest()
        self._holds = HoldRegister(self._dir)
        self._writer: ShardHandle | None = None
        self._state = State()
        self._state_before_active: str = state_digest(State())

    @property
    def directory(self) -> str:
        return self._dir

    @property
    def manifest(self) -> Manifest:
        return self._manifest

    @property
    def holds(self) -> HoldRegister:
        return self._holds

    @property
    def policy(self) -> TriggerPolicy:
        return self._policy

    @property
    def state(self) -> State:
        return self._state

    @property
    def next_seq(self) -> int:
        return self._manifest.next_seq

    @property
    def watermark(self) -> int:
        return self._manifest.next_seq - 1

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(
        cls,
        directory: str,
        policy: TriggerPolicy | None = None,
        sync: bool = True,
        crash_hook: CrashHook | None = None,
    ) -> "ShardLog":
        os.makedirs(directory, exist_ok=True)
        log = cls(directory, policy=policy, sync=sync, crash_hook=crash_hook)
        log._recover()
        return log

    def _journal_dir(self) -> str:
        return os.path.join(self._dir, JOURNAL_DIR_NAME)

    def _crash(self, point: str) -> None:
        self._crash_hook(point)

    def _recover(self) -> None:
        self._holds.load()
        self._remove_temp_files()
        manifest = load_manifest(self._dir)
        if manifest is None:
            self._recover_orphan_shards_without_manifest()
            manifest = Manifest()
            publish_manifest(self._dir, manifest, sync=self._sync)
        self._manifest = manifest
        self._recover_compactions()
        manifest = load_manifest(self._dir)
        assert manifest is not None
        self._manifest = manifest
        self._reconcile_shard_files(manifest)
        self._reopen_active(manifest)
        report = replay_log(self, verify=True)
        self._state = report.state
        self._state_before_active = report.state_before_active
        if manifest.next_seq != report.next_seq:
            raise Corruption(
                f"manifest next_seq={manifest.next_seq} but replay ended at {report.next_seq}"
            )

    def _remove_temp_files(self) -> None:
        for pattern in ("*.tmp",):
            for path in glob.glob(os.path.join(self._dir, pattern)):
                os.remove(path)
        staging = os.path.join(self._dir, ".manifest.tmp")
        if os.path.exists(staging):
            os.remove(staging)
        journal_dir = self._journal_dir()
        if os.path.isdir(journal_dir):
            for path in glob.glob(os.path.join(journal_dir, "*.tmp")):
                os.remove(path)

    def _recover_orphan_shards_without_manifest(self) -> None:
        shard_files = sorted(glob.glob(os.path.join(self._dir, "log-*.shard")))
        for path in shard_files:
            _header, _records, _torn, footer = iter_shard_records(path)
            if footer is None:
                os.remove(path)
            else:
                raise Corruption(
                    f"{os.path.basename(path)} is sealed but no manifest exists; refusing to invent history"
                )

    def _reconcile_shard_files(self, manifest: Manifest) -> None:
        known = set(manifest.shards)
        on_disk: set[int] = set()
        for path in sorted(glob.glob(os.path.join(self._dir, "log-*.shard"))):
            name = os.path.basename(path)
            try:
                index = int(name[len("log-"):-len(".shard")])
            except ValueError:
                continue
            on_disk.add(index)
            if index not in known:
                if index == manifest.active_index:
                    # The active shard is managed by _reopen_active, not here.
                    continue
                size = os.path.getsize(path)
                if size == 0:
                    # Pre-header create artifact; never reached a manifest publish.
                    os.remove(path)
                    continue
                _header, _records, _torn, footer = iter_shard_records(path)
                if footer is None:
                    os.remove(path)
                else:
                    raise Corruption(
                        f"sealed shard {name!r} exists but the manifest does not reference it"
                    )
        for index in known:
            if index not in on_disk and not manifest.shards[index].compacted:
                raise Corruption(
                    f"manifest references non-compacted shard {index} but its file is missing"
                )

    def _reopen_active(self, manifest: Manifest) -> None:
        if manifest.active_index < 0:
            self._writer = None
            return
        path = shard_path(self._dir, manifest.active_index)
        if not os.path.exists(path):
            raise Corruption("active shard file is missing")
        if os.path.getsize(path) == 0:
            # A pre-header artifact left by a crash before ShardHandle.create
            # fsynced its header. The manifest announced the slot but no record
            # ever landed in it, so roll the counters back to the sealed prefix.
            os.remove(path)
            manifest.active_index = -1
            manifest.active_committed_entries = 0
            manifest.active_committed_bytes = 0
            last_sealed = max(manifest.shards) if manifest.shards else -1
            manifest.next_seq = (
                manifest.shards[last_sealed].summary.seq_end + 1
                if last_sealed >= 0
                else 1
            )
            publish_manifest(self._dir, manifest, sync=self._sync)
            self._writer = None
            return
        _header, records, _torn, footer = iter_shard_records(path)
        if footer is not None:
            self._adopt_sealed_active(manifest)
            return
        writer = ShardHandle.resume(path, sync=self._sync)
        self._writer = writer
        committed_entries = writer.entry_count
        committed_bytes = HEADER_SIZE + sum(
            record_frame_len(entry) for entry, _flags in records
        )
        if (
            manifest.active_committed_entries != committed_entries
            or manifest.active_committed_bytes != committed_bytes
            or manifest.next_seq != writer.seq_start + committed_entries
        ):
            manifest.active_committed_entries = committed_entries
            manifest.active_committed_bytes = committed_bytes
            manifest.next_seq = writer.seq_start + committed_entries
            publish_manifest(self._dir, manifest, sync=self._sync)

    def _adopt_sealed_active(self, manifest: Manifest) -> None:
        index = manifest.active_index
        summary = read_shard_footer(shard_path(self._dir, index))
        manifest.shards[index] = ShardRef(summary=summary)
        manifest.active_index = -1
        manifest.active_committed_bytes = 0
        manifest.active_committed_entries = 0
        manifest.next_seq = summary.seq_end + 1
        publish_manifest(self._dir, manifest, sync=self._sync)

    # -- appending ---------------------------------------------------------

    def _ensure_writer(self) -> ShardHandle:
        if self._writer is None:
            index = (max(self._manifest.shards) + 1) if self._manifest.shards else 0
            if self._manifest.shards:
                prev_hash = self._manifest.shards[max(self._manifest.shards)].summary.body_hash
            else:
                prev_hash = ZERO_HASH
            seq_start = self._manifest.next_seq
            path = shard_path(self._dir, index)
            self._crash("before_active_create")
            writer = ShardHandle.create(path, index, seq_start, prev_hash, sync=self._sync)
            self._writer = writer
            self._state_before_active = state_digest(self._state)
            self._manifest.active_index = index
            self._manifest.active_committed_bytes = HEADER_SIZE
            self._manifest.active_committed_entries = 0
            publish_manifest(self._dir, self._manifest, sync=self._sync)
        return self._writer

    def append(
        self,
        entry: JournalEntry,
        hold_case_id: str = "",
        hold_note: str = "",
        at: str = "",
    ) -> int:
        """Persist one committed command, fold it live, and roll/auto-compact."""

        if entry.sequence != self._manifest.next_seq:
            raise Corruption(
                f"expected seq {self._manifest.next_seq}, got {entry.sequence}"
            )
        if hold_case_id:
            self._holds.hold(entry.sequence, hold_case_id, hold_note, at, sync=self._sync)

        writer = self._ensure_writer()
        frame_len = record_frame_len(entry)
        self._crash("before_frame_write")
        writer.append(entry, held=bool(hold_case_id), sync=self._sync)
        apply_entry(self._state, entry.kind, entry.payload)

        self._manifest.next_seq += 1
        self._manifest.active_committed_entries += 1
        self._manifest.active_committed_bytes += frame_len
        self._manifest.total_appended_bytes += frame_len
        publish_manifest(self._dir, self._manifest, sync=self._sync)

        if self._policy.shard_rolls_over(writer.body_bytes, writer.entry_count):
            # Compact the already-sealed prefix before opening the next shard:
            # auto compaction must never observe a half-created new active file.
            self._maybe_auto_compact()
            self._rollover()
        else:
            self._maybe_auto_compact()
        return entry.sequence

    def _rollover(self) -> None:
        writer = self._writer
        if writer is None or writer.entry_count == 0:
            return
        state_after = state_digest(self._state)
        self._crash("before_seal")
        summary = writer.seal(self._state_before_active, state_after, sync=self._sync)
        self._writer = None
        self._manifest.shards[summary.index] = ShardRef(summary=summary)
        self._manifest.active_index = -1
        self._manifest.active_committed_bytes = 0
        self._manifest.active_committed_entries = 0
        self._crash("before_rollover_publish")
        publish_manifest(self._dir, self._manifest, sync=self._sync)

    # -- compaction --------------------------------------------------------

    def compactable_shards(self) -> tuple[list[int], int, int]:
        """Prefix of sealed non-compacted shards protected by no live hold."""

        indices: list[int] = []
        total_bytes = 0
        total_entries = 0
        for index in sorted(self._manifest.shards):
            ref = self._manifest.shards[index]
            if ref.compacted or index == self._manifest.active_index:
                continue
            summary = ref.summary
            if self._holds.range_touches_hold(summary.seq_start, summary.seq_end) is not None:
                break
            indices.append(index)
            total_bytes += summary.body_bytes
            total_entries += summary.entry_count
        return indices, total_bytes, total_entries

    def compact_due(self) -> bool:
        _indices, total_bytes, total_entries = self.compactable_shards()
        return self._policy.compact_due(total_bytes, total_entries)

    def _maybe_auto_compact(self) -> None:
        try:
            if self.compact_due():
                self.compact()
        except CompactionBlocked:
            return

    def compact(self, force: bool = False) -> CompactionResult:
        """Fold the compactable prefix into a snapshot envelope.

        Raises :class:`CompactionBlocked` when a live forensic hold protects
        the very next eligible shard (the prefix barrier), or when no
        threshold has been reached unless ``force`` is set.
        """

        indices, input_bytes, input_entries_now = self.compactable_shards()
        if not indices:
            raise CompactionBlocked(
                "no eligible shards: empty prefix or forensic hold barrier"
            )
        if not force and not self._policy.compact_due(input_bytes, input_entries_now):
            raise CompactionBlocked("compaction threshold not reached")

        self._crash("before_intent")
        prev_envelope = self._manifest.envelope
        base_total = 0
        if prev_envelope is not None:
            previous = read_envelope(os.path.join(self._dir, prev_envelope.file_name))
            base_total = sum(summary.entry_count for summary in previous.shards)
        state, total_entries, summaries, _before = _fold_shard_indices(
            self._dir, self._manifest, indices, prev_envelope
        )
        digest = state_digest(state)
        envelope_id = self._envelope_id(summaries)
        envelope = SnapshotEnvelope(
            envelope_id=envelope_id,
            seq_end=summaries[sorted(summaries)[-1]].seq_end,
            state_digest=digest,
            state=state,
            shards=[summaries[index] for index in sorted(summaries)],
            prev_envelope_id=prev_envelope.envelope_id if prev_envelope else "",
            hold_digest=self._holds.digest,
            entry_count=total_entries,
        )

        os.makedirs(self._journal_dir(), exist_ok=True)
        intent = {
            "phase": "intent",
            "envelope_id": envelope_id,
            "shard_indices": indices,
            "input_bytes": input_bytes,
            "entries_now": input_entries_now,
            "base_total": base_total,
            "entries_total": total_entries,
            "seq_end": envelope.seq_end,
            "state_digest": digest,
            "prev_envelope_id": envelope.prev_envelope_id,
            "hold_digest": envelope.hold_digest,
            "created_at": time.time_ns(),
        }
        self._write_journal(envelope_id, intent)

        self._crash("before_envelope_write")
        write_envelope_atomic(self._dir, envelope, sync=self._sync)

        self._crash("before_compact_publish")
        env_path = envelope_path(self._dir, envelope_id)
        ref = EnvelopeRef(
            envelope_id=envelope_id,
            file_name=envelope_file_name(envelope_id),
            body_hash=self._envelope_body_hash(env_path),
            state_digest=digest,
            seq_end=envelope.seq_end,
            shard_indices=tuple(indices),
            prev_envelope_id=envelope.prev_envelope_id,
            hold_digest=envelope.hold_digest,
        )
        manifest = self._manifest
        for index in indices:
            shard_ref = manifest.shards[index]
            manifest.shards[index] = ShardRef(
                summary=shard_ref.summary, compacted=True, envelope_id=envelope_id
            )
        manifest.envelope = ref
        manifest.total_compacted_input_bytes += input_bytes
        envelope_bytes = os.path.getsize(env_path)
        manifest.total_envelope_bytes += envelope_bytes
        publish_manifest(self._dir, manifest, sync=self._sync)

        self._crash("after_commit")
        self._finish_compaction(envelope_id)
        return CompactionResult(
            envelope_id=envelope_id,
            shard_indices=tuple(indices),
            entries_in_envelope=total_entries,
            entries_compacted_now=input_entries_now,
            input_bytes=input_bytes,
            envelope_bytes=envelope_bytes,
            seq_end=envelope.seq_end,
            state_digest=digest,
        )

    def _envelope_id(self, summaries: dict[int, object]) -> str:
        chain = ",".join(str(index) for index in sorted(summaries))
        return f"{self._manifest.next_seq - 1:012d}-{uuid.uuid5(uuid.NAMESPACE_URL, chain).hex[:12]}"

    def _journal_file(self, envelope_id: str) -> str:
        return os.path.join(self._journal_dir(), f"compact-{envelope_id}.json")

    def _write_journal(self, envelope_id: str, payload: dict[str, object]) -> None:
        path = self._journal_file(envelope_id)
        temporary = f"{path}.tmp"
        os.makedirs(self._journal_dir(), exist_ok=True)
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        with open(temporary, "wb") as handle:
            handle.write(raw)
            handle.flush()
            if self._sync:
                os.fsync(handle.fileno())
        os.replace(temporary, path)

    def _file_hash(self, path: str) -> str:
        with open(path, "rb") as handle:
            return sha256_hex(handle.read())

    @staticmethod
    def _envelope_body_hash(path: str) -> str:
        with open(path, "rb") as handle:
            raw = handle.read()
        marker = b"\nBAGSNAP1 "
        split_at = raw.rfind(marker)
        if split_at < 0:
            raise Corruption(f"envelope {path!r}: missing checksum marker")
        return sha256_hex(raw[:split_at])

    def _recover_compactions(self) -> None:
        journal_dir = self._journal_dir()
        if not os.path.isdir(journal_dir):
            return
        for path in sorted(glob.glob(os.path.join(journal_dir, "compact-*.json"))):
            with open(path, "rb") as handle:
                intent = json.loads(handle.read())
            envelope_id = str(intent["envelope_id"])
            env_path = envelope_path(self._dir, envelope_id)
            manifest = load_manifest(self._dir)
            committed = (
                manifest is not None
                and manifest.envelope is not None
                and manifest.envelope.envelope_id == envelope_id
            )
            if not committed:
                if not os.path.exists(env_path):
                    os.remove(path)
                    continue
                envelope = read_envelope(env_path)
                if not envelope.verify():
                    os.remove(env_path)
                    os.remove(path)
                    continue
                self._commit_recovered_compaction(manifest, envelope, intent)
            for index in intent["shard_indices"]:
                shard_file = shard_path(self._dir, int(index))
                if os.path.exists(shard_file):
                    os.remove(shard_file)
            os.remove(path)

    def _commit_recovered_compaction(
        self, manifest: Manifest | None, envelope: SnapshotEnvelope, intent: dict[str, object]
    ) -> None:
        if manifest is None:
            raise Corruption("compaction intent found but manifest is missing")
        for index in intent["shard_indices"]:
            index = int(index)
            if index not in manifest.shards:
                raise Corruption(f"compaction journal references unknown shard {index}")
            ref = manifest.shards[index]
            manifest.shards[index] = ShardRef(
                summary=ref.summary,
                compacted=True,
                envelope_id=envelope.envelope_id,
            )
        manifest.envelope = EnvelopeRef(
            envelope_id=envelope.envelope_id,
            file_name=envelope_file_name(envelope.envelope_id),
            body_hash=self._envelope_body_hash(envelope_path(self._dir, envelope.envelope_id)),
            state_digest=envelope.state_digest,
            seq_end=envelope.seq_end,
            shard_indices=tuple(int(index) for index in intent["shard_indices"]),
            prev_envelope_id=envelope.prev_envelope_id,
            hold_digest=envelope.hold_digest,
        )
        manifest.total_compacted_input_bytes += int(intent["input_bytes"])
        manifest.total_envelope_bytes += os.path.getsize(
            envelope_path(self._dir, envelope.envelope_id)
        )
        publish_manifest(self._dir, manifest, sync=self._sync)

    def _finish_compaction(self, envelope_id: str) -> None:
        for index, ref in self._manifest.shards.items():
            if ref.compacted and ref.envelope_id == envelope_id:
                path = shard_path(self._dir, index)
                if os.path.exists(path):
                    os.remove(path)
        journal = self._journal_file(envelope_id)
        if os.path.exists(journal):
            os.remove(journal)

    # -- verification ------------------------------------------------------

    def verify(self) -> ReplayReport:
        report = replay_log(self, verify=True)
        if state_digest(report.state) != state_digest(self._state):
            raise Corruption("live state disagrees with replayed state")
        return report

    def release_hold(self, seq: int, case_id: str, note: str = "", at: str = ""):
        """Release a hold and immediately compact any prefix that frees up."""

        record = self._holds.release(seq, case_id, note, at, sync=self._sync)
        self._maybe_auto_compact()
        return record
