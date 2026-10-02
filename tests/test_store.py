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

    def test_clean_restart_then_append_survives_a_second_restart(self):
        # The reported failure: a normal restart must remember the committed
        # byte offset, otherwise the next append publishes a tree head whose
        # offset splits previously committed records.
        store = self.open_store()
        first = [canonical.dumps_canonical({"i": i}) for i in range(3)]
        store.append_entries(first)
        del store

        restarted = self.open_store()
        log_size = (self.path / "log").stat().st_size
        self.assertEqual(restarted.tree_size, 3)
        self.assertEqual(restarted.log_bytes, log_size)

        restarted.append_entries([canonical.dumps_canonical({"i": 3})])
        del restarted

        second_restart = self.open_store()
        self.assertEqual(second_restart.tree_size, 4)
        self.assertEqual(
            second_restart.log_bytes, (self.path / "log").stat().st_size
        )
        self.assertEqual(
            canonical.loads(second_restart.get_entry(3)), {"i": 3}
        )
        self.assertEqual(
            second_restart.root,
            merkle.root_from_entries(
                [canonical.dumps_canonical({"i": i}) for i in range(4)]
            ),
        )

    def test_truncated_tail_followed_by_append_then_restart(self):
        store = self.open_store()
        store.append_entries([canonical.dumps_canonical({"i": i}) for i in range(3)])
        del store

        log = self.path / "log"
        log.write_bytes(
            log.read_bytes() + b"VLOG" + (99).to_bytes(8, "big") + b"{partial"
        )
        recovered = self.open_store()
        boundary = log.stat().st_size
        recovered.append_entries([canonical.dumps_canonical({"i": 99})])
        del recovered

        again = self.open_store()
        self.assertEqual(again.tree_size, 4)
        self.assertEqual(again.log_bytes, log.stat().st_size)
        self.assertEqual(canonical.loads(again.get_entry(3)), {"i": 99})
        self.assertGreater(log.stat().st_size, boundary)

    def test_committed_corruption_with_dangling_tails_is_fatal_without_side_effects(
        self,
    ):
        # Complete-but-unpublished tail records and an unfinished tail frame
        # coexist with corruption inside the published prefix.  Opening must be
        # fatal, and neither tail truncation nor a head rewrite may happen
        # first: every interface must keep seeing the same durable state.
        store = self.open_store()
        payloads = [canonical.dumps_canonical({"i": i}) for i in range(5)]
        store.append_entries(payloads[:2])
        store.append_entries(payloads[2:])
        del store

        log = self.path / "log"
        original = log.read_bytes()
        original_head = (self.path / "tree-head.json").read_bytes()
        with open(log, "ab") as handle:
            handle.write(storage.build_frame(canonical.dumps_canonical({"tail": 0})))
            handle.write(storage.build_frame(canonical.dumps_canonical({"tail": 1})))
            handle.write(b"VLOG" + (99).to_bytes(8, "big") + b"{partial")
        dangling_size = log.stat().st_size

        # Corrupt the final checksum byte of committed record 1.
        frame_one_start = len(b"VLOG") + 8 + len(payloads[0]) + 32
        checksum_byte = (
            frame_one_start + len(b"VLOG") + 8 + len(payloads[1]) + 31
        )
        data = bytearray(log.read_bytes())
        data[checksum_byte] ^= 0x01
        log.write_bytes(data)

        with self.assertRaises(storage.CorruptLogError):
            self.open_store()
        self.assertEqual(log.stat().st_size, dangling_size)
        self.assertEqual((self.path / "tree-head.json").read_bytes(), original_head)
        self.assertFalse((self.path / "tree-head.json.tmp").exists())
        # The dangling tails beyond the committed prefix are untouched; nothing
        # was truncated or silently healed.
        tails = (
            storage.build_frame(canonical.dumps_canonical({"tail": 0}))
            + storage.build_frame(canonical.dumps_canonical({"tail": 1}))
            + b"VLOG" + (99).to_bytes(8, "big") + b"{partial"
        )
        self.assertEqual(log.read_bytes()[len(original) :], tails)

    def test_unpublished_complete_tails_plus_partial_frame_are_republished_together(
        self,
    ):
        store = self.open_store()
        payloads = [canonical.dumps_canonical({"i": i}) for i in range(5)]
        store.append_entries(payloads)
        del store

        log = self.path / "log"
        with open(log, "ab") as handle:
            handle.write(storage.build_frame(canonical.dumps_canonical({"tail": 0})))
            handle.write(storage.build_frame(canonical.dumps_canonical({"tail": 1})))
            handle.write(b"VLOG" + (99).to_bytes(8, "big") + b"{partial")

        recovered = self.open_store()
        self.assertEqual(recovered.tree_size, 7)
        self.assertEqual(recovered.log_bytes, log.stat().st_size)
        self.assertEqual(
            canonical.loads(recovered.get_entry(6)), {"tail": 1}
        )
        head = canonical.loads((self.path / "tree-head.json").read_bytes())
        self.assertEqual(head["tree_size"], 7)
        self.assertEqual(head["log_bytes"], log.stat().st_size)
        self.assertEqual(bytes.fromhex(head["root_hash"]), recovered.root)

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


if __name__ == "__main__":
    unittest.main()
