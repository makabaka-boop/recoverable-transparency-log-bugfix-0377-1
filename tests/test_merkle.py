import hashlib
import unittest

from verifiable_log import merkle


# Deliberately independent, straightforward tree construction.  It builds
# levels by pairing adjacent nodes and uses the same public hash definitions,
# but it does not use the production range/proof code under test.
def naive_root(entries):
    level = [hashlib.sha256(b"\x00" + item).digest() for item in entries]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return hashlib.sha256(b"").digest() if not level else level[0]


class MerkleTest(unittest.TestCase):
    def test_small_trees_match_independent_builder(self):
        entries = [str(i).encode() for i in range(100)]
        for size in range(len(entries) + 1):
            leaves = [merkle.leaf_hash(item) for item in entries[:size]]
            self.assertEqual(merkle.root_hash(leaves), naive_root(entries[:size]))

    def test_domain_separation(self):
        data = b"x"
        self.assertNotEqual(merkle.leaf_hash(data), hashlib.sha256(data).digest())
        h = merkle.leaf_hash(data)
        self.assertNotEqual(merkle.node_hash(h, h), hashlib.sha256(h + h).digest())

    def test_inclusion_proofs_all_small_positions(self):
        entries = [str(i).encode() for i in range(80)]
        for size in range(1, len(entries) + 1):
            leaves = [merkle.leaf_hash(item) for item in entries[:size]]
            root = merkle.root_hash(leaves)
            for index in range(size):
                proof = merkle.inclusion_proof(leaves, index, size)
                self.assertTrue(
                    merkle.verify_inclusion(
                        leaf_data=entries[index],
                        leaf_index=index,
                        tree_size=size,
                        proof=proof,
                        expected_root=root,
                    ),
                    (size, index),
                )

    def test_tampered_inclusion_proof_rejected(self):
        entries = [b"a", b"b", b"c"]
        leaves = [merkle.leaf_hash(item) for item in entries]
        root = merkle.root_hash(leaves)
        proof = list(merkle.inclusion_proof(leaves, 1, 3))
        proof[0] = hashlib.sha256(proof[0]).digest()
        self.assertFalse(
            merkle.verify_inclusion(
                leaf_data=b"b",
                leaf_index=1,
                tree_size=3,
                proof=proof,
                expected_root=root,
            )
        )

    def test_consistency_all_small_size_pairs(self):
        entries = [str(i).encode() for i in range(100)]
        leaves = [merkle.leaf_hash(item) for item in entries]
        for old_size in range(101):
            for new_size in range(old_size, 101):
                old_root = merkle.root_hash(leaves[:old_size])
                new_root = merkle.root_hash(leaves[:new_size])
                proof = merkle.consistency_proof(leaves, old_size, new_size)
                self.assertTrue(
                    merkle.verify_consistency(
                        old_size=old_size,
                        new_size=new_size,
                        old_root=old_root,
                        new_root=new_root,
                        proof=proof,
                    ),
                    (old_size, new_size),
                )

    def test_tampered_consistency_proof_rejected(self):
        entries = [str(i).encode() for i in range(8)]
        leaves = [merkle.leaf_hash(item) for item in entries]
        proof = list(merkle.consistency_proof(leaves, 3, 7))
        proof[-1] = hashlib.sha256(proof[-1]).digest()
        self.assertFalse(
            merkle.verify_consistency(
                old_size=3,
                new_size=7,
                old_root=merkle.root_hash(leaves[:3]),
                new_root=merkle.root_hash(leaves[:7]),
                proof=proof,
            )
        )


if __name__ == "__main__":
    unittest.main()
