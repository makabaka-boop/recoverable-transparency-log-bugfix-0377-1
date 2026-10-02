"""Durable, append-only record storage.

On-disk record frame:

    magic  (4 bytes)  = b"VLOG"
    length (8 bytes, big-endian uint64)
    payload(length bytes, canonical UTF-8 JSON supplied by the caller)
    check  (32 bytes, SHA-256)

The checksum is ``SHA256(b"vlog-record-v1" || u64be(length) || payload)``.
A separate canonical-JSON tree-head file names the number and byte length of
committed records.  At startup, complete records already durable before a
crash are recovered and published; only a physically incomplete final frame
is truncated.  Corruption in a complete frame, including a committed middle
record, is fatal.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from threading import RLock
from typing import Callable

from . import canonical, merkle

MAGIC = b"VLOG"
LENGTH_SIZE = 8
RECORD_CHECK_PREFIX = b"vlog-record-v1"
HEAD_VERSION = 1
MAX_RECORD_SIZE = 16 * 1024 * 1024


class CorruptLogError(RuntimeError):
    """Raised when durable log or tree-head contents fail verification."""


class CrashInjected(RuntimeError):
    """Raised by an in-process crash hook used by tests."""


def record_checksum(payload: bytes) -> bytes:
    return hashlib.sha256(
        RECORD_CHECK_PREFIX + len(payload).to_bytes(8, "big") + payload
    ).digest()


def build_frame(payload: bytes) -> bytes:
    return (
        MAGIC
        + len(payload).to_bytes(8, "big")
        + payload
        + record_checksum(payload)
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Store:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        crash_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.log_path = self.directory / "log"
        self.head_path = self.directory / "tree-head.json"
        self.tmp_head_path = self.directory / "tree-head.json.tmp"
        self._lock = RLock()
        self._crash_hook = crash_hook

        self.entries: list[bytes] = []
        self.hashes: list[bytes] = []
        self.log_bytes = 0
        self.tree_size = 0
        self.root = merkle.EMPTY_ROOT

        # A missing head is recoverable by a checksum-scan of the append log.
        # A malformed head, by contrast, is intentionally not ignored: doing so
        # would allow a stale/malicious tree-head file to roll back the tree.
        self._recover()

    def _crash_point(self, stage: str) -> None:
        configured = os.environ.get("VLOG_CRASH_AT")
        if configured == stage:
            os._exit(99)
        if self._crash_hook is not None:
            self._crash_hook(stage)

    def _write_head(
        self, size: int, log_bytes: int, root: bytes, crash_points: bool = True
    ) -> None:
        head = canonical.dumps_canonical(
            {
                "version": HEAD_VERSION,
                "tree_size": size,
                "log_bytes": log_bytes,
                "root_hash": root.hex(),
            }
        )
        with open(self.tmp_head_path, "wb") as handle:
            handle.write(head)
            handle.flush()
            os.fsync(handle.fileno())
            if crash_points:
                self._crash_point("head_written")
        os.replace(self.tmp_head_path, self.head_path)
        if crash_points:
            self._crash_point("head_replaced")
        _fsync_directory(self.directory)
        if crash_points:
            self._crash_point("head_fsynced")

    def _read_head(self) -> tuple[int, int, bytes]:
        try:
            head = canonical.loads(self.head_path.read_bytes())
        except (OSError, UnicodeError, ValueError) as exc:
            raise CorruptLogError(f"cannot read tree head: {exc}") from exc
        if not isinstance(head, dict) or head.get("version") != HEAD_VERSION:
            raise CorruptLogError("unsupported or malformed tree head")
        try:
            size = int(head["tree_size"])
            log_bytes = int(head["log_bytes"])
            root = bytes.fromhex(str(head["root_hash"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptLogError(f"malformed tree-head field: {exc}") from exc
        if size < 0 or log_bytes < 0 or len(root) != merkle.HASH_SIZE:
            raise CorruptLogError("invalid tree-head hash, size, or byte offset")
        return size, log_bytes, root

    @staticmethod
    def _read_exact(handle: os.BinaryIO, amount: int) -> bytes:
        chunks: list[bytes] = []
        remaining = amount
        while remaining:
            chunk = handle.read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_frame(
        self, handle: os.BinaryIO, *, committed: bool
    ) -> tuple[bytes | None, int, bool]:
        """Return (payload, frame_start, physically_incomplete)."""

        frame_start = handle.tell()
        header = self._read_exact(handle, len(MAGIC) + LENGTH_SIZE)
        if len(header) < len(MAGIC) + LENGTH_SIZE:
            if len(header) != 0:
                return None, frame_start, True
            return None, frame_start, False
        if header[: len(MAGIC)] != MAGIC:
            raise CorruptLogError(f"bad record magic at byte {frame_start}")
        length = int.from_bytes(header[len(MAGIC) :], "big")
        if length > MAX_RECORD_SIZE:
            raise CorruptLogError(
                f"record length {length} exceeds limit {MAX_RECORD_SIZE} at byte {frame_start}"
            )
        payload = self._read_exact(handle, length)
        if len(payload) != length:
            return None, frame_start, True
        checksum = self._read_exact(handle, merkle.HASH_SIZE)
        if len(checksum) != merkle.HASH_SIZE:
            return None, frame_start, True
        if checksum != record_checksum(payload):
            raise CorruptLogError(f"checksum mismatch at byte {frame_start}")
        return payload, frame_start, False

    def _recover(self) -> None:
        if self.head_path.exists():
            committed_size, committed_bytes, committed_root = self._read_head()
        else:
            committed_size = 0
            committed_bytes = 0
            committed_root = merkle.EMPTY_ROOT
        entries: list[bytes] = []
        hashes: list[bytes] = []

        if not self.log_path.exists():
            if committed_size != 0 or committed_bytes != 0:
                raise CorruptLogError("tree head commits records but log is absent")
            self._set_state(0, 0, merkle.EMPTY_ROOT)
            self.entries = []
            self.hashes = []
            if not self.head_path.exists():
                self._write_head(0, 0, merkle.EMPTY_ROOT, crash_points=False)
            return

        truncated = False
        truncate_end = 0
        file_size = 0
        with open(self.log_path, "rb") as handle:
            file_size = handle.seek(0, os.SEEK_END)
            handle.seek(0)
            if committed_bytes > file_size:
                raise CorruptLogError("committed log offset is beyond end of file")

            while handle.tell() < committed_bytes:
                start = handle.tell()
                payload, frame_start, incomplete = self._read_frame(
                    handle, committed=True
                )
                end = handle.tell()
                if incomplete:
                    raise CorruptLogError(
                        f"committed record beginning at byte {frame_start} is incomplete"
                    )
                if payload is None or end > committed_bytes:
                    raise CorruptLogError(
                        f"committed log offset {committed_bytes} splits a record"
                    )
                entries.append(payload)
                hashes.append(merkle.leaf_hash(payload))

            if handle.tell() != committed_bytes:
                raise CorruptLogError("committed byte offset is not a frame boundary")
            if len(entries) != committed_size:
                raise CorruptLogError(
                    f"tree head announces {committed_size} records but log prefix "
                    f"contains {len(entries)}"
                )
            calculated_committed_root = merkle.root_hash(hashes)
            if calculated_committed_root != committed_root:
                raise CorruptLogError("committed root hash does not match log records")

            while True:
                start = handle.tell()
                payload, frame_start, incomplete = self._read_frame(
                    handle, committed=False
                )
                if payload is None:
                    if incomplete:
                        truncate_end = frame_start
                        truncated = True
                    break
                entries.append(payload)
                hashes.append(merkle.leaf_hash(payload))

        if truncated:
            with open(self.log_path, "r+b") as truncate_handle:
                truncate_handle.truncate(truncate_end)
                truncate_handle.flush()
                os.fsync(truncate_handle.fileno())
            _fsync_directory(self.directory)

        size = len(entries)
        root = merkle.root_hash(hashes)
        effective_end = truncate_end
        self.entries = entries
        self.hashes = hashes
        self.tree_size = size
        self.log_bytes = effective_end
        self.root = root

        if (
            size != committed_size
            or effective_end != committed_bytes
            or root != committed_root
        ):
            # Records and their fsync survived, but the old head did not publish
            # them.  They are complete and must not be discarded.
            self._write_head(size, effective_end, root, crash_points=False)

    def _set_state(self, size: int, log_bytes: int, root: bytes) -> None:
        self.tree_size = size
        self.log_bytes = log_bytes
        self.root = root

    def append_entries(self, payloads: list[bytes]) -> tuple[int, list[bytes], bytes]:
        if not payloads:
            raise ValueError("at least one record is required")
        if any(not isinstance(item, bytes) for item in payloads):
            raise TypeError("record payloads must be bytes")

        frames = [build_frame(payload) for payload in payloads]
        with self._lock:
            start_index = self.tree_size
            start_bytes = self.log_bytes
            with open(self.log_path, "ab") as handle:
                for frame in frames:
                    view = memoryview(frame)
                    while view:
                        written = handle.write(view)
                        if written == 0:
                            raise OSError("short write to append log")
                        view = view[written:]
                handle.flush()
                os.fsync(handle.fileno())
                durable_bytes = start_bytes + sum(len(frame) for frame in frames)
                self._crash_point("records_fsynced")

            new_entries = self.entries + payloads
            new_hashes = self.hashes + [merkle.leaf_hash(item) for item in payloads]
            new_root = merkle.root_hash(new_hashes)
            self._write_head(start_index + len(payloads), durable_bytes, new_root)

            self.entries = new_entries
            self.hashes = new_hashes
            self.tree_size = start_index + len(payloads)
            self.log_bytes = durable_bytes
            self.root = new_root
            return start_index, list(payloads), new_root

    def get_entry(self, index: int) -> bytes:
        with self._lock:
            if index < 0:
                raise IndexError("record index must not be negative")
            try:
                return self.entries[index]
            except IndexError as exc:
                raise IndexError(
                    f"record {index} does not exist; tree size is {self.tree_size}"
                ) from exc

    def tree_head(self) -> tuple[int, bytes]:
        with self._lock:
            return self.tree_size, self.root

    def snapshot(self) -> tuple[list[bytes], list[bytes]]:
        with self._lock:
            return list(self.entries), list(self.hashes)

    def inclusion(self, index: int, tree_size: int | None = None):
        with self._lock:
            size = self.tree_size if tree_size is None else tree_size
            if size is None or size < 0 or size > self.tree_size:
                raise IndexError("requested tree size is unavailable")
            if not 0 <= index < size:
                raise IndexError("record index is outside requested tree")
            proof = merkle.inclusion_proof(self.hashes, index, size)
            root = merkle.root_hash(self.hashes[:size])
            return self.entries[index], size, root, proof

    def consistency(self, old_size: int, new_size: int | None = None):
        with self._lock:
            size = self.tree_size if new_size is None else new_size
            if not 0 <= old_size <= size <= self.tree_size:
                raise IndexError("requested tree sizes are unavailable")
            old_root = merkle.EMPTY_ROOT
            if old_size:
                old_root = merkle.root_hash(self.hashes[:old_size])
            new_root = merkle.root_hash(self.hashes[:size])
            proof = merkle.consistency_proof(self.hashes, old_size, size)
            return old_root, size, new_root, proof
