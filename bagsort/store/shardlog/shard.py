"""Binary shard files: framing, per-record CRC, hash chain and sealed footer.

On-disk layout of one shard (little-endian everywhere)::

    header  ("BSHARD1", index, seq_start, prev_body_hash)   56 bytes
    record* (magic, length, flags, payload, crc32)          variable
    footer  ("BSHARD2", digests, counts, state digests)     240 bytes

A shard *with* a valid footer is **sealed** and immutable; its whole body is
covered by ``body_hash`` and the records form a SHA-256 chain anchored at the
previous shard's ``body_hash``. A shard without a footer is the *active*
shard: its final record may be a torn tail (a crash between write and
``fsync``) which readers detect and ignore.

Record flags include :data:`RECORD_FLAG_HELD`, marking commands that are under
forensic hold. Held records are ordinary log data — the flag is what stops the
compactor from folding their shard away.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from ..journal import JournalEntry
from .coding import ZERO_HASH, canonical_entry, sha256_hex

HEADER_MAGIC = b"BSHARD01"
FOOTER_MAGIC = b"BSHARD02"
RECORD_MAGIC = b"SHR1"
HEADER_SIZE = 8 + 8 + 8 + 32
RECORD_HEADER_SIZE = 4 + 4 + 1
RECORD_FOOTER_SIZE = 4
FOOTER_SIZE = 8 + 8 * 5 + 32 * 6

RECORD_FLAG_HELD = 0x01
_RECORD_FLAGS_MASK = 0xFF

_HEADER = struct.Struct("<8sQQ32s")
_RECORD = struct.Struct("<4sIB")
_FOOTER = struct.Struct("<8sQQQQQ32s32s32s32s32s32s")


class Corruption(RuntimeError):
    """A shard, envelope or manifest failed its integrity checks."""


def shard_path(directory: str, index: int) -> str:
    return os.path.join(directory, f"log-{index:010d}.shard")


def record_frame_len(entry: JournalEntry) -> int:
    """Byte length of one entry's on-disk frame (header + payload + crc)."""

    return RECORD_HEADER_SIZE + len(canonical_entry(entry)) + RECORD_FOOTER_SIZE


def _chain_step(previous: str, payload: bytes) -> str:
    return sha256_hex(bytes.fromhex(previous) + hashlib.sha256(payload).digest())


@dataclass(frozen=True)
class ShardSummary:
    """Everything the manifest/envelope needs to reference one shard safely."""

    index: int
    seq_start: int
    seq_end: int
    entry_count: int
    body_bytes: int
    body_hash: str
    prev_hash: str
    first_hash: str
    last_hash: str
    state_before: str
    state_after: str

    @property
    def seq_range(self) -> tuple[int, int]:
        return self.seq_start, self.seq_end

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "seq_start": self.seq_start,
            "seq_end": self.seq_end,
            "entry_count": self.entry_count,
            "body_bytes": self.body_bytes,
            "body_hash": self.body_hash,
            "prev_hash": self.prev_hash,
            "first_hash": self.first_hash,
            "last_hash": self.last_hash,
            "state_before": self.state_before,
            "state_after": self.state_after,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> "ShardSummary":
        fields = {
            key: int(raw[key])
            for key in ("index", "seq_start", "seq_end", "entry_count", "body_bytes")
        }
        for key in ("body_hash", "prev_hash", "first_hash", "last_hash",
                    "state_before", "state_after"):
            fields[key] = str(raw[key])
        return cls(**fields)


def _parse_record(frame: bytes) -> tuple[int, bytes]:
    """Return ``(flags, payload)`` for one complete frame, validating CRC."""

    magic, length, flags = _RECORD.unpack_from(frame)
    if magic != RECORD_MAGIC:
        raise Corruption("bad record magic")
    payload_start = RECORD_HEADER_SIZE
    payload = frame[payload_start : payload_start + length]
    (crc,) = struct.unpack_from("<I", frame, payload_start + length)
    if zlib.crc32(bytes([flags]) + payload) & 0xFFFFFFFF != crc:
        raise Corruption("record crc mismatch")
    return flags, payload


def _frame_record(payload: bytes, flags: int) -> bytes:
    return (
        _RECORD.pack(RECORD_MAGIC, len(payload), flags)
        + payload
        + struct.pack("<I", zlib.crc32(bytes([flags]) + payload) & 0xFFFFFFFF)
    )


def iter_shard_records(
    path: str,
) -> tuple[dict[str, object], list[tuple[JournalEntry, int]], bool, ShardSummary | None]:
    """Read and verify a shard file.

    Returns ``(header, records, torn, footer_summary)``. For a sealed shard
    every check is strict and ``torn`` is False. For the active shard a torn
    final record is tolerated and reported via ``torn`` so callers can truncate
    before resuming appends.
    """

    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) < HEADER_SIZE:
        raise Corruption(f"shard {path!r} is shorter than its header")

    magic, index, seq_start, prev_raw = _HEADER.unpack_from(data)
    if magic != HEADER_MAGIC:
        raise Corruption(f"shard {path!r}: bad header magic")
    header = {"index": index, "seq_start": seq_start, "prev_hash": prev_raw.hex()}

    footer: ShardSummary | None = None
    body_end = len(data)
    if len(data) >= FOOTER_SIZE and bytes(data[-FOOTER_SIZE:-FOOTER_SIZE + 8]) == FOOTER_MAGIC:
        footer = _parse_footer(data)
        expected_body = footer.body_bytes
        if expected_body != len(data) - FOOTER_SIZE:
            raise Corruption(f"shard {path!r}: footer body length does not match file size")
        if footer.index != index or footer.seq_start != seq_start or footer.prev_hash != header["prev_hash"]:
            raise Corruption(f"shard {path!r}: footer disagrees with header")
        if sha256_hex(data[:expected_body]) != footer.body_hash:
            raise Corruption(f"shard {path!r}: body hash mismatch")
        body_end = expected_body

    records: list[tuple[JournalEntry, int]] = []
    offset = HEADER_SIZE
    first_hash = ZERO_HASH
    last_hash = header["prev_hash"]
    torn = False
    while offset < body_end:
        if body_end - offset < RECORD_HEADER_SIZE:
            torn = True
            break
        _, length, _ = _RECORD.unpack_from(data, offset)
        frame_end = offset + RECORD_HEADER_SIZE + length + RECORD_FOOTER_SIZE
        if frame_end > body_end:
            torn = True
            break
        frame = data[offset:frame_end]
        try:
            flags, payload = _parse_record(frame)
            entry = JournalEntry.from_dict(json.loads(payload.decode("utf-8")))
        except (Corruption, ValueError, UnicodeDecodeError):
            torn = True
            break
        records.append((entry, flags))
        rec_hash = _chain_step(last_hash, payload)
        if not records[:-1]:
            first_hash = rec_hash
        last_hash = rec_hash
        offset = frame_end

    if footer is not None:
        if torn:  # body hash already proved this cannot happen; stay strict.
            raise Corruption(f"shard {path!r}: sealed shard ends mid-record")
        if len(records) != footer.entry_count:
            raise Corruption(f"shard {path!r}: entry count disagrees with footer")
        if records:
            seq_end = records[-1][0].sequence
            if seq_end != footer.seq_end:
                raise Corruption(f"shard {path!r}: seq_end disagrees with footer")
            if first_hash != footer.first_hash or last_hash != footer.last_hash:
                raise Corruption(f"shard {path!r}: record hash chain disagrees with footer")
    return header, records, torn, footer


def _parse_footer(data: bytes) -> ShardSummary:
    unpacked = _FOOTER.unpack_from(data, len(data) - FOOTER_SIZE)
    (
        magic,
        index,
        seq_start,
        seq_end,
        entry_count,
        body_bytes,
        body_hash_raw,
        prev_hash_raw,
        first_hash_raw,
        last_hash_raw,
        before_raw,
        after_raw,
    ) = unpacked
    if magic != FOOTER_MAGIC:
        raise Corruption("bad footer magic")
    return ShardSummary(
        index=index,
        seq_start=seq_start,
        seq_end=seq_end,
        entry_count=entry_count,
        body_bytes=body_bytes,
        body_hash=body_hash_raw.hex(),
        prev_hash=prev_hash_raw.hex(),
        first_hash=first_hash_raw.hex(),
        last_hash=last_hash_raw.hex(),
        state_before=before_raw.hex(),
        state_after=after_raw.hex(),
    )


def verify_shard_file(path: str, expected_prev: str | None = None) -> ShardSummary:
    """Structurally verify one shard independently and return its summary.

    Sealed shards return their footer summary; a recovered (unsealed) shard
    returns a provisional summary with zero state digests and a zero body hash
    when its tail was torn. Linkage against ``expected_prev`` is checked when
    given, so each shard can be validated on its own before trusting a chain.
    """

    with open(path, "rb") as handle:
        data = handle.read()
    header, records, torn, footer = iter_shard_records(path)
    if expected_prev is not None and header["prev_hash"] != expected_prev:
        raise Corruption(f"shard {path!r}: prev_hash link broken")
    if footer is not None:
        return footer
    seq_end = records[-1][0].sequence if records else int(header["seq_start"]) - 1
    first = last = ZERO_HASH
    for pos, (entry, _flags) in enumerate(records):
        rec_hash = _chain_step(last if pos else header["prev_hash"], canonical_entry(entry))
        if pos == 0:
            first = rec_hash
        last = rec_hash
    body_bytes = HEADER_SIZE + sum(record_frame_len(entry) for entry, _flags in records)
    body_hash = ZERO_HASH if torn else sha256_hex(data[:body_bytes])
    return ShardSummary(
        index=int(header["index"]),
        seq_start=int(header["seq_start"]),
        seq_end=seq_end,
        entry_count=len(records),
        body_bytes=body_bytes,
        body_hash=body_hash,
        prev_hash=str(header["prev_hash"]),
        first_hash=first,
        last_hash=last,
        state_before=ZERO_HASH,
        state_after=ZERO_HASH,
    )


class ShardHandle:
    """Write handle for the active shard; seals it into an immutable footer."""

    def __init__(self, handle: BinaryIO, index: int, seq_start: int, prev_hash: str) -> None:
        self._handle = handle
        self.index = index
        self.seq_start = seq_start
        self.prev_hash = prev_hash
        self._entry_count = 0
        self._seq_end = seq_start
        self._first_hash = ZERO_HASH
        self._last_hash = prev_hash
        self._body_hasher = hashlib.sha256()
        self._body_hasher.update(
            _HEADER.pack(HEADER_MAGIC, index, seq_start, bytes.fromhex(prev_hash))
        )

    @classmethod
    def create(cls, path: str, index: int, seq_start: int, prev_hash: str, sync: bool = True) -> "ShardHandle":
        # "x+b" refuses to truncate an existing file, so a stale or recovered
        # shard at this index can never be silently overwritten. The header is
        # always flushed to the OS; fsync (disk-level durability) follows sync.
        handle = open(path, "x+b")
        handle.write(_HEADER.pack(HEADER_MAGIC, index, seq_start, bytes.fromhex(prev_hash)))
        handle.flush()
        if sync:
            os.fsync(handle.fileno())
        return cls(handle, index, seq_start, prev_hash)

    @classmethod
    def resume(cls, path: str, sync: bool = True) -> "ShardHandle":
        """Reopen the active shard after a crash, dropping a torn tail."""

        header, records, torn, footer = iter_shard_records(path)
        if footer is not None:
            raise Corruption(f"cannot resume sealed shard {path!r}")
        good_length = HEADER_SIZE + sum(
            RECORD_HEADER_SIZE + len(canonical_entry(entry)) + RECORD_FOOTER_SIZE
            for entry, _flags in records
        )
        with open(path, "rb") as source:
            body = source.read(good_length)
        handle = open(path, "r+b")
        if torn:
            handle.truncate(good_length)
        handle.seek(0, os.SEEK_END)
        writer = cls(
            handle,
            int(header["index"]),
            int(header["seq_start"]),
            str(header["prev_hash"]),
        )
        writer._body_hasher = hashlib.sha256(body)
        for entry, _flags in records:
            writer._track(canonical_entry(entry), entry.sequence)
        if torn:
            handle.flush()
            if sync:
                os.fsync(handle.fileno())
        return writer

    def _track(self, payload: bytes, sequence: int) -> None:
        self._entry_count += 1
        self._seq_end = sequence
        rec_hash = _chain_step(self._last_hash, payload)
        if self._entry_count == 1:
            self._first_hash = rec_hash
        self._last_hash = rec_hash

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def body_bytes(self) -> int:
        return self._handle.tell()

    def append(self, entry: JournalEntry, held: bool = False, sync: bool = True) -> int:
        """Append one committed command; returns the frame's byte length."""

        payload = canonical_entry(entry)
        flags = RECORD_FLAG_HELD if held else 0
        frame = _frame_record(payload, flags)
        self._handle.write(frame)
        self._handle.flush()
        if sync:
            os.fsync(self._handle.fileno())
        self._body_hasher.update(frame)
        self._track(payload, entry.sequence)
        return len(frame)

    def body_hash(self) -> str:
        """Hash of the header plus every appended record frame so far."""

        return self._body_hasher.hexdigest()

    def seal(
        self,
        state_before: str,
        state_after: str,
        sync: bool = True,
    ) -> ShardSummary:
        """Write the footer and close the file; the shard is immutable after."""

        body_hash = self.body_hash()
        body_bytes = self._handle.tell()
        footer = _FOOTER.pack(
            FOOTER_MAGIC,
            self.index,
            self.seq_start,
            self._seq_end,
            self._entry_count,
            body_bytes,
            bytes.fromhex(body_hash),
            bytes.fromhex(self.prev_hash),
            bytes.fromhex(self._first_hash),
            bytes.fromhex(self._last_hash),
            bytes.fromhex(state_before),
            bytes.fromhex(state_after),
        )
        self._handle.write(footer)
        self._handle.flush()
        if sync:
            os.fsync(self._handle.fileno())
        summary = ShardSummary(
            index=self.index,
            seq_start=self.seq_start,
            seq_end=self._seq_end,
            entry_count=self._entry_count,
            body_bytes=body_bytes,
            body_hash=body_hash,
            prev_hash=self.prev_hash,
            first_hash=self._first_hash,
            last_hash=self._last_hash,
            state_before=state_before,
            state_after=state_after,
        )
        self._handle.close()
        return summary

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()


def read_shard_footer(path: str) -> ShardSummary:
    _header, _records, _torn, footer = iter_shard_records(path)
    if footer is None:
        raise Corruption(f"shard {path!r} has no footer")
    return footer


def iter_sealed_records(path: str) -> Iterator[tuple[JournalEntry, int]]:
    _header, records, _torn, footer = iter_shard_records(path)
    if footer is None:
        raise Corruption(f"shard {path!r} is not sealed")
    yield from records
