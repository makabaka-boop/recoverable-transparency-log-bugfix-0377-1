import os
import tempfile
import threading
import unittest
from pathlib import Path

from verifiable_log import canonical, merkle
from verifiable_log import store as storage


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def open_store(self, crash_hook=None):
        return storage.Store(self.path, crash_hook=crash_hook)

    def test_canonical_framing_and_checksum(self):
        store = self.open_store()
        payload = canonical.dumps_canonical({"z": 1, "a": [True, None, "中文"]})
        start, stored, _ = store.append_entries([payload])
        self.assertEqual(start, 0)
        self.assertEqual(stored, [payload])

        raw = (self.path / "log").read_bytes()
        self.assertTrue(raw.startswith(b"VLOG" + (len(payload)).to_bytes(8, "big") + payload))
        self.assertEqual(raw[-32:], storage.record_checksum(payload))

    def test_batch_appends_have_unique_contiguous_sequence_numbers(self):
        store = self.open_store()
        results = []

        def worker(worker_id: int):
            payloads = [canonical.dumps_canonical({"w": worker_id, "i": i}) for i in range(25)]
            start, _, _ = store.append_entries(payloads)
            results.append((start, worker_id))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        starts = sorted(start for start, _ in results)
        self.assertEqual(starts, list(range(0, 12 * 25, 25)))
        reopen = self.open_store()
        self.assertEqual(reopen.tree_size, 300)
        owner_by_start = {start: worker for start, worker in results}
        for index in range(300):
            value = canonical.loads(reopen.get_entry(index))
            owner = max(start for start in owner_by_start if start <= index)
            self.assertEqual(value, {"w": owner_by_start[owner], "i": index - owner})

    def test_complete_unpublished_records_are_recovered_after_head_crash(self):
        hook = lambda stage: (_ for _ in ()).throw(AssertionError("hook not used"))  # noqa: E731

        def crash_once(stage):
            if stage == "records_fsynced":
                raise RuntimeError("crash between records and tree-head publication")

        store = self.open_store(crash_hook=crash_once)
        with self.assertRaises(RuntimeError):
            store.append_entries([canonical.dumps_canonical({"n": i}) for i in range(3)])
        self.assertFalse((self.path / "tree-head.json.tmp").exists())

        recovered = self.open_store(crash_hook=hook)
        self.assertEqual(recovered.tree_size, 3)
        self.assertEqual(
            canonical.loads(recovered.get_entry(2)),
            {"n": 2},
        )
        self.assertEqual(
            recovered.root,
            merkle.root_from_entries(
                [canonical.dumps_canonical({"n": i}) for i in range(3)]
            ),
        )

    def test_physically_incomplete_tail_is_truncated_on_restart(self):
        store = self.open_store()
        payloads = [canonical.dumps_canonical({"i": i}) for i in range(3)]
        store.append_entries(payloads)
        log = self.path / "log"
        data = log.read_bytes()
        log.write_bytes(data + b"VLOG" + (99).to_bytes(8, "big") + b"{partial")

        recovered = self.open_store()
        self.assertEqual(recovered.tree_size, 3)
        self.assertEqual(log.stat().st_size, len(data))
        self.assertEqual(
            canonical.loads((self.path / "tree-head.json").read_bytes())["tree_size"],
            3,
        )

    def test_complete_middle_corruption_is_fatal_never_skipped(self):
        store = self.open_store()
        payloads = [canonical.dumps_canonical({"i": i}) for i in range(4)]
        store.append_entries(payloads[:2])
        store.append_entries(payloads[2:])

        log = self.path / "log"
        data = bytearray(log.read_bytes())
        frame_one = len(b"VLOG") + 8
        data[frame_one + 1] ^= 0x01
        log.write_bytes(data)

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()

    def test_complete_tail_checksum_corruption_is_fatal(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": 0})])
        store.append_entries([canonical.dumps_canonical({"i": 1})])
        log = self.path / "log"
        data = bytearray(log.read_bytes())
        data[-1] ^= 0x01
        log.write_bytes(data)

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()

    def test_committed_offset_split_record_is_fatal(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": 0})])
        head_path = self.path / "tree-head.json"
        head = canonical.loads(head_path.read_bytes())
        head["log_bytes"] -= 1
        head_path.write_bytes(canonical.dumps_canonical(head))

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()

    def test_wrong_published_root_is_fatal(self):
        store = self.open_store()
        store.append_entries([b'{"i":1}'])
        head_path = self.path / "tree-head.json"
        head = canonical.loads(head_path.read_bytes())
        head["root_hash"] = "00" * 32
        head_path.write_bytes(canonical.dumps_canonical(head))

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()

    def test_missing_head_recovers_from_checksum_scan(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": 0})])
        os.unlink(self.path / "tree-head.json")

        recovered = self.open_store()
        self.assertEqual(recovered.tree_size, 1)
        self.assertEqual(canonical.loads(recovered.get_entry(0)), {"i": 0})
        self.assertTrue((self.path / "tree-head.json").exists())

    def test_malformed_head_is_fatal(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": 0})])
        (self.path / "tree-head.json").write_bytes(b"{not-json")

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()

    def test_clean_restart_then_append_then_restart_stays_consistent(self):
        store = self.open_store()
        first = [canonical.dumps_canonical({"batch": 1, "i": i}) for i in range(2)]
        store.append_entries(first)
        published_head = canonical.loads((self.path / "tree-head.json").read_bytes())

        # A clean restart must observe the same persistent state without
        # rewriting the published head or losing the committed byte offset.
        reopened = self.open_store()
        self.assertEqual(reopened.tree_size, 2)
        self.assertEqual(reopened.log_bytes, (self.path / "log").stat().st_size)
        self.assertEqual(
            canonical.loads((self.path / "tree-head.json").read_bytes()),
            published_head,
        )

        second = [canonical.dumps_canonical({"batch": 2, "i": i}) for i in range(3)]
        start, _, _ = reopened.append_entries(second)
        self.assertEqual(start, 2)

        recovered = self.open_store()
        self.assertEqual(recovered.tree_size, 5)
        self.assertEqual(recovered.log_bytes, (self.path / "log").stat().st_size)
        head = canonical.loads((self.path / "tree-head.json").read_bytes())
        self.assertEqual(head["tree_size"], 5)
        self.assertEqual(head["log_bytes"], recovered.log_bytes)
        self.assertEqual(head["root_hash"], recovered.root.hex())
        self.assertEqual(recovered.root, merkle.root_from_entries(first + second))

        # Records, inclusion proofs, and consistency proofs all describe the
        # same recovered state.
        for index in range(5):
            self.assertEqual(recovered.get_entry(index), (first + second)[index])
            entry, size, root, proof = recovered.inclusion(index)
            self.assertTrue(
                merkle.verify_inclusion(
                    leaf_data=entry,
                    leaf_index=index,
                    tree_size=size,
                    proof=proof,
                    expected_root=root,
                )
            )
        old_root, new_size, new_root, proof = recovered.consistency(2)
        self.assertEqual(old_root, merkle.root_from_entries(first))
        self.assertTrue(
            merkle.verify_consistency(
                old_size=2,
                new_size=new_size,
                old_root=old_root,
                new_root=new_root,
                proof=proof,
            )
        )

    def test_unpublished_tail_records_and_torn_frame_recover_together(self):
        store = self.open_store()
        published = [canonical.dumps_canonical({"n": i}) for i in range(2)]
        store.append_entries(published)
        unpublished = [canonical.dumps_canonical({"n": i}) for i in range(2, 4)]

        log = self.path / "log"
        with open(log, "ab") as handle:
            for payload in unpublished:
                handle.write(storage.build_frame(payload))
            handle.flush()
            os.fsync(handle.fileno())
        with open(log, "ab") as handle:
            handle.write(b"VLOG" + (50).to_bytes(8, "big") + b'{"n":')

        recovered = self.open_store()
        self.assertEqual(recovered.tree_size, 4)
        self.assertEqual(recovered.log_bytes, log.stat().st_size)
        head = canonical.loads((self.path / "tree-head.json").read_bytes())
        self.assertEqual(head["tree_size"], 4)
        self.assertEqual(head["log_bytes"], recovered.log_bytes)
        self.assertEqual(recovered.root, merkle.root_from_entries(published + unpublished))

        # The republished state must survive another restart unchanged.
        again = self.open_store()
        self.assertEqual(again.tree_size, 4)
        self.assertEqual(again.log_bytes, recovered.log_bytes)
        self.assertEqual(again.root, recovered.root)

    def test_committed_corruption_with_torn_tail_is_fatal_and_untouched(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": i}) for i in range(3)])

        log = self.path / "log"
        data = bytearray(log.read_bytes())
        data[20] ^= 0x01
        data += b"VLOG" + (10).to_bytes(8, "big") + b"{pa"
        log.write_bytes(data)

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()
        # Fatal corruption must not be "repaired" by truncating the tail:
        # the on-disk bytes stay exactly as they were found.
        self.assertEqual(log.read_bytes(), bytes(data))


if __name__ == "__main__":
    unittest.main()
