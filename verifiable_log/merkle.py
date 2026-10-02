"""Merkle tree hashing and transparency-log proofs.

Leaf and internal hashes use distinct SHA-256 domain prefixes:

* leaf:     SHA256(0x00 || data)
* internal: SHA256(0x01 || left_hash || right_hash)

The consistency proof is represented as a canonical, verifier-derived list of
balanced subtree hashes.  The verifier needs no directions or trusted metadata
from the service: all ranges follow only from the old and new tree sizes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

EMPTY_ROOT = hashlib.sha256(b"").digest()
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
HASH_SIZE = 32


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise ValueError("Merkle node children must be 32-byte hashes")
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _largest_power_of_two(n: int) -> int:
    if n <= 0:
        raise ValueError("size must be positive")
    return 1 << (n.bit_length() - 1)


def _split_point(n: int) -> int:
    if n <= 1:
        raise ValueError("cannot split a node smaller than two leaves")
    # A perfect node splits in half; an imperfect tree splits at its largest
    # complete power-of-two left subtree.
    if _is_power_of_two(n):
        return n // 2
    return _largest_power_of_two(n)


def subtree_hash(leaves: Sequence[bytes], start: int, size: int) -> bytes:
    if size == 0:
        return EMPTY_ROOT
    if size == 1:
        value = leaves[start]
        if len(value) != HASH_SIZE:
            raise ValueError("leaf hash must be 32 bytes")
        return value
    k = _split_point(size)
    return node_hash(
        subtree_hash(leaves, start, k),
        subtree_hash(leaves, start + k, size - k),
    )


def root_hash(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    return subtree_hash(leaves, 0, len(leaves))


def root_from_entries(entries: Sequence[bytes]) -> bytes:
    return root_hash([leaf_hash(entry) for entry in entries])


def inclusion_proof(
    leaves: Sequence[bytes], leaf_index: int, tree_size: int | None = None
) -> list[bytes]:
    size = len(leaves) if tree_size is None else tree_size
    if not 0 <= leaf_index < size:
        raise IndexError("leaf index is outside the tree")
    if size > len(leaves):
        raise ValueError("tree size exceeds available leaves")

    def collect(start: int, node_size: int, index: int) -> list[bytes]:
        if node_size == 1:
            return []
        k = _split_point(node_size)
        if index < k:
            sibling = subtree_hash(leaves, start + k, node_size - k)
            return [sibling] + collect(start, k, index)
        sibling = subtree_hash(leaves, start, k)
        return [sibling] + collect(start + k, node_size - k, index - k)

    return collect(0, size, leaf_index)


def verify_inclusion(
    *,
    leaf_data: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    if tree_size <= 0 or not 0 <= leaf_index < tree_size:
        return False
    if len(expected_root) != HASH_SIZE:
        return False
    if any(len(item) != HASH_SIZE for item in proof):
        return False

    current = leaf_hash(leaf_data)
    start = 0
    size = tree_size
    index = leaf_index
    used = 0

    steps: list[tuple[str, bytes]] = []
    while size > 1:
        k = _split_point(size)
        if used >= len(proof):
            return False
        sibling = proof[used]
        used += 1
        if index < k:
            steps.append(("right", sibling))
            size = k
        else:
            steps.append(("left", sibling))
            start += k
            size -= k
            index -= k
    # Proof hashes arrive outer-to-inner; replay them inner-to-outer.
    for side, sibling in reversed(steps):
        if side == "right":
            current = node_hash(current, sibling)
        else:
            current = node_hash(sibling, current)

    return used == len(proof) and start + size <= tree_size and current == expected_root


def _components(size: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    start = 0
    while size:
        k = _largest_power_of_two(size)
        result.append((start, k))
        start += k
        size -= k
    return result


def _is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def consistency_ranges(old_size: int, new_size: int) -> list[tuple[int, int]]:
    if not 0 <= old_size <= new_size:
        raise ValueError("expected 0 <= old_size <= new_size")
    if old_size in (0, new_size):
        return []

    result: list[tuple[int, int]] = []

    def walk(start: int, size: int) -> None:
        end = start + size
        if end <= old_size or start >= old_size:
            result.append((start, size))
            return
        k = _split_point(size)
        walk(start, k)
        walk(start + k, size - k)

    walk(0, new_size)
    return result


def consistency_proof(
    leaves: Sequence[bytes], old_size: int, new_size: int
) -> list[bytes]:
    if new_size > len(leaves):
        raise ValueError("new tree size exceeds available leaves")
    return [
        subtree_hash(leaves, start, size)
        for start, size in consistency_ranges(old_size, new_size)
    ]


def _fold_right(anchors: Sequence[bytes]) -> bytes:
    """Hash canonical left-to-right component anchors into a tree root."""

    if not anchors:
        return EMPTY_ROOT
    current = anchors[-1]
    for anchor in reversed(anchors[:-1]):
        current = node_hash(anchor, current)
    return current


def verify_consistency(
    *,
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    if not 0 <= old_size <= new_size:
        return False
    if len(old_root) != HASH_SIZE or len(new_root) != HASH_SIZE:
        return False
    if any(len(item) != HASH_SIZE for item in proof):
        return False

    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if old_size == 0:
        return len(proof) == 0 and old_root == EMPTY_ROOT

    expected_ranges = consistency_ranges(old_size, new_size)
    if len(proof) != len(expected_ranges):
        return False

    proof_by_range = dict(zip(expected_ranges, proof, strict=True))

    def reconstruct(start: int, size: int) -> bytes:
        end = start + size
        if end <= old_size or start >= old_size:
            return proof_by_range[(start, size)]
        k = _split_point(size)
        return node_hash(
            reconstruct(start, k),
            reconstruct(start + k, size - k),
        )

    calculated_new = reconstruct(0, new_size)
    if calculated_new != new_root:
        return False

    old_ranges = [(start, size) for start, size in expected_ranges if start < old_size]
    calculated_old = _fold_right(
        [proof_by_range[item] for item in old_ranges]
    )
    return calculated_old == old_root
