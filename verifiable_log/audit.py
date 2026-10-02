"""Independent audit commands.

This module intentionally does not import the service's Merkle implementation.
It repeats the verifier math locally and treats service-provided proof bytes,
records, roots, and sizes as untrusted input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.request
from typing import Any, Sequence

from . import canonical

HASH_SIZE = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


class AuditError(ValueError):
    pass


def _http_json(url: str, method: str = "GET", payload: bytes | None = None):
    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise AuditError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise AuditError(f"request failed: {exc}") from exc
    try:
        return canonical.loads(body)
    except ValueError as exc:
        raise AuditError(f"service returned invalid JSON: {exc}") from exc


def _base(url: str) -> str:
    return url.rstrip("/")


def _hash(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _leaf(data: bytes) -> bytes:
    return _hash(b"\x00" + data)


def _node(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_SIZE or len(right) != HASH_SIZE:
        raise AuditError("proof contains a hash with the wrong length")
    return _hash(b"\x01" + left + right)


def _hex_hash(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise AuditError(f"{name} must be a hexadecimal string")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise AuditError(f"{name} is not hexadecimal") from exc
    if len(decoded) != HASH_SIZE:
        raise AuditError(f"{name} must be {HASH_SIZE} bytes")
    return decoded


def _proof_hashes(value: Any) -> list[bytes]:
    if not isinstance(value, list):
        raise AuditError("proof must be an array of hexadecimal hashes")
    return [_hex_hash(item, "proof element") for item in value]


def _largest_power_of_two(n: int) -> int:
    if n <= 0:
        raise AuditError("non-positive tree component encountered")
    return 1 << (n.bit_length() - 1)


def _split_point(n: int) -> int:
    if n <= 1:
        raise AuditError("cannot split a node smaller than two leaves")
    if _power_of_two(n):
        return n // 2
    return _largest_power_of_two(n)


def _root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT

    def subtree(start: int, size: int) -> bytes:
        if size == 1:
            return leaves[start]
        k = _split_point(size)
        return _node(subtree(start, k), subtree(start + k, size - k))

    return subtree(0, len(leaves))


def _components(size: int) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    start = 0
    while size:
        k = _largest_power_of_two(size)
        result.append((start, k))
        start += k
        size -= k
    return result


def _power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def _consistency_ranges(old: int, new: int) -> list[tuple[int, int]]:
    if old in (0, new):
        return []
    ranges: list[tuple[int, int]] = []

    def walk(start: int, size: int) -> None:
        end = start + size
        if end <= old or start >= old:
            ranges.append((start, size))
            return
        k = _split_point(size)
        walk(start, k)
        walk(start + k, size - k)

    walk(0, new)
    return ranges


def _fold(hashes: Sequence[bytes]) -> bytes:
    """Hash canonical left-to-right component anchors into a tree root."""

    if not hashes:
        return EMPTY_ROOT
    current = hashes[-1]
    for value in reversed(hashes[:-1]):
        current = _node(value, current)
    return current


def tree_head(base_url: str) -> dict[str, Any]:
    return _http_json(_base(base_url) + "/v1/tree-head")


def record(base_url: str, index: int) -> bytes:
    value = _http_json(f"{_base(base_url)}/v1/records/{int(index)}")
    text = value.get("canonical_json")
    if not isinstance(text, str):
        raise AuditError("record response lacks canonical_json")
    data = text.encode("utf-8")
    parsed = canonical.loads(data)
    if canonical.dumps_canonical(parsed) != data:
        raise AuditError("service-supplied JSON is not canonical")
    if parsed != value.get("data"):
        raise AuditError("record response data and canonical_json disagree")
    return data


def audit_root(base_url: str) -> dict[str, Any]:
    head = tree_head(base_url)
    if not isinstance(head.get("tree_size"), int):
        raise AuditError("malformed tree size")
    claimed = _hex_hash(head.get("root_hash"), "root hash")
    size = head["tree_size"]
    if size < 0:
        raise AuditError("negative tree size")
    leaves = []
    for index in range(size):
        leaves.append(_leaf(record(base_url, index)))
    calculated = _root(leaves)
    return {
        "ok": calculated == claimed,
        "tree_size": size,
        "claimed_root_hash": claimed.hex(),
        "calculated_root_hash": calculated.hex(),
        "records_checked": size,
    }


def audit_inclusion(
    base_url: str,
    index: int,
    tree_size: int | None = None,
    root_hash_hex: str | None = None,
) -> dict[str, Any]:
    query = f"index={int(index)}"
    if tree_size is not None:
        query += f"&tree_size={int(tree_size)}"
    proof_response = _http_json(f"{_base(base_url)}/v1/inclusion?{query}")
    claimed_index = proof_response.get("leaf_index")
    if claimed_index != index:
        raise AuditError("service returned a different leaf index")
    size = proof_response.get("tree_size")
    if not isinstance(size, int) or size <= 0 or not 0 <= index < size:
        raise AuditError("invalid tree size or leaf index")

    data_from_proof = proof_response.get("canonical_json")
    if not isinstance(data_from_proof, str):
        raise AuditError("proof response lacks canonical_json")
    data_from_record = record(base_url, index).decode("utf-8")
    if data_from_proof != data_from_record:
        raise AuditError("proof response and record endpoint disagree")

    claimed_leaf = _hex_hash(proof_response.get("leaf_hash"), "leaf hash")
    data = data_from_record.encode("utf-8")
    calculated_leaf = _leaf(data)
    if claimed_leaf != calculated_leaf:
        raise AuditError("service supplied an incorrect leaf hash")

    proof = _proof_hashes(proof_response.get("proof"))
    proof_root = _hex_hash(proof_response.get("root_hash"), "root hash")
    if root_hash_hex is None:
        head = tree_head(base_url)
        if tree_size is not None and head.get("tree_size") != tree_size:
            raise AuditError(
                "historical --tree-size requires an externally supplied --root-hash"
            )
        root_hash_hex = head.get("root_hash")
    expected_root = _hex_hash(root_hash_hex, "root hash")
    if proof_root != expected_root:
        raise AuditError("proof root does not match the anchored tree head")

    # Independently walk the coordinate path implied solely by index/size.
    current = calculated_leaf
    start = 0
    node_size = size
    leaf = index
    used = 0
    steps: list[tuple[str, bytes]] = []
    while node_size > 1:
        k = _split_point(node_size)
        if used >= len(proof):
            raise AuditError("proof is too short")
        sibling = proof[used]
        used += 1
        if leaf < k:
            steps.append(("right", sibling))
            node_size = k
        else:
            steps.append(("left", sibling))
            start += k
            leaf -= k
            node_size -= k
    # The proof is ordered outer-to-inner; replay it inner-to-outer.
    for side, sibling in reversed(steps):
        if side == "right":
            current = _node(current, sibling)
        else:
            current = _node(sibling, current)
    if used != len(proof):
        raise AuditError("proof is too long")
    if start + node_size > size:
        raise AuditError("proof path leaves the tree")
    return {
        "ok": current == expected_root,
        "leaf_index": index,
        "tree_size": size,
        "root_hash": expected_root.hex(),
        "leaf_hash": calculated_leaf.hex(),
    }


def verify_consistency_response(
    old_size: int,
    old_root: bytes,
    response: dict[str, Any],
) -> dict[str, Any]:
    new_size = response.get("new_size")
    if not isinstance(new_size, int) or not 0 <= old_size <= new_size:
        raise AuditError("invalid old/new tree sizes")
    if response.get("old_size") != old_size:
        raise AuditError("service returned a different old size")
    new_root = _hex_hash(response.get("new_root_hash"), "new root hash")
    # old_root_hash in response is explicitly not trusted.
    proof = _proof_hashes(response.get("proof"))

    ok = False
    if old_size == new_size:
        ok = len(proof) == 0 and old_root == new_root
    elif old_size == 0:
        ok = len(proof) == 0 and old_root == EMPTY_ROOT
    else:
        expected_ranges = _consistency_ranges(old_size, new_size)
        if len(proof) == len(expected_ranges):
            by_range = dict(zip(expected_ranges, proof, strict=True))

            def reconstruct(start: int, size: int) -> bytes:
                end = start + size
                if end <= old_size or start >= old_size:
                    return by_range[(start, size)]
                k = _split_point(size)
                return _node(
                    reconstruct(start, k),
                    reconstruct(start + k, size - k),
                )

            old_ranges = [
                (start, size) for start, size in expected_ranges if start < old_size
            ]
            calculated_old = _fold([by_range[item] for item in old_ranges])
            ok = (
                calculated_old == old_root
                and reconstruct(0, new_size) == new_root
            )

    return {
        "ok": ok,
        "old_size": old_size,
        "new_size": new_size,
        "old_root_hash": old_root.hex(),
        "new_root_hash": new_root.hex(),
        "proof_hashes": [item.hex() for item in proof],
    }


def audit_consistency(
    base_url: str,
    old_size: int,
    old_root_hex: str,
    new_size: int | None = None,
    new_root_hex: str | None = None,
) -> dict[str, Any]:
    old_root = _hex_hash(old_root_hex, "old root hash")
    if new_root_hex is None:
        head = tree_head(base_url)
        if new_size is not None and head.get("tree_size") != new_size:
            raise AuditError(
                "historical --new-size requires an externally supplied --new-root"
            )
        new_root_hex = head.get("root_hash")
    anchored_new_root = _hex_hash(new_root_hex, "new root hash")
    query = f"old_size={int(old_size)}"
    if new_size is not None:
        query += f"&new_size={int(new_size)}"
    response = _http_json(f"{_base(base_url)}/v1/consistency?{query}")
    result = verify_consistency_response(old_size, old_root, response)
    result["ok"] = result["ok"] and result["new_root_hash"] == anchored_new_root.hex()
    result["anchored_new_root_hash"] = anchored_new_root.hex()
    return result


def _print(value: dict[str, Any]) -> int:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if value.get("ok") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifiable-log audit",
        description="Independently verify records and transparency proofs",
    )
    sub = parser.add_subparsers(dest="audit_command", required=True)

    p = sub.add_parser("root", help="fetch every record and recompute the root")
    p.add_argument("url")

    p = sub.add_parser("inclusion", help="verify an inclusion proof")
    p.add_argument("url")
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--tree-size", type=int)
    p.add_argument("--root-hash", help="required when --tree-size names a historical tree")

    p = sub.add_parser("consistency", help="verify old head is a prefix of new head")
    p.add_argument("url")
    p.add_argument("--old-size", type=int, required=True)
    p.add_argument("--old-root", required=True, help="hex root hash from the old tree head")
    p.add_argument("--new-size", type=int)
    p.add_argument("--new-root", help="required when --new-size names a historical tree")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.audit_command == "root":
            result = audit_root(args.url)
        elif args.audit_command == "inclusion":
            result = audit_inclusion(
                args.url, args.index, args.tree_size, args.root_hash
            )
        elif args.audit_command == "consistency":
            result = audit_consistency(
                args.url,
                args.old_size,
                args.old_root,
                args.new_size,
                args.new_root,
            )
        else:  # pragma: no cover - argparse enforces this
            raise AssertionError(args.audit_command)
    except AuditError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    return _print(result)
