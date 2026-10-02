import http.client
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from verifiable_log import audit, canonical


class ServiceCliTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.data = Path(self.directory.name) / "data"
        self.process = None

    def tearDown(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=10)
            self._close_process_streams()
        self.directory.cleanup()

    def start_server(self, env=None):
        args = [
            sys.executable,
            "-m",
            "verifiable_log",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--data",
            str(self.data),
        ]
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        self.process = subprocess.Popen(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full_env,
        )
        assert self.process.stdout is not None
        line = self.process.stdout.readline().strip()
        if not line:
            err = self.process.stderr.read() if self.process.stderr else ""
            raise AssertionError(f"server did not print a port: {err}")
        port = int(line)
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                audit.tree_head(base)
                return base
            except Exception:
                time.sleep(0.02)
        raise AssertionError("server did not become ready")

    def _close_process_streams(self):
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()

    def request(self, base, method, path, body=None):
        data = canonical.dumps_canonical(body) if body is not None else None
        request = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return canonical.loads(response.read())

    def test_endpoints_and_independent_audit_commands(self):
        base = self.start_server()
        first_batch = [{"z": 1}, {"a": "中"}]
        second = [{"n": i} for i in range(2, 12)]
        r1 = self.request(base, "POST", "/v1/records", {"records": first_batch})
        old_head = audit.tree_head(base)
        r2 = self.request(base, "POST", "/v1/records", {"records": second})
        self.assertEqual((r1["start_index"], r1["count"]), (0, 2))
        self.assertEqual((r2["start_index"], r2["count"]), (2, 10))

        self.assertEqual(
            canonical.loads(audit.record(base, 1)),
            {"a": "中"},
        )
        root_result = audit.audit_root(base)
        self.assertTrue(root_result["ok"])

        for index in range(12):
            result = audit.audit_inclusion(base, index)
            self.assertTrue(result["ok"], result)
        old_result = audit.audit_inclusion(
            base, 1, 2, old_head["root_hash"]
        )
        self.assertTrue(old_result["ok"])

        result = audit.audit_consistency(
            base,
            old_head["tree_size"],
            old_head["root_hash"],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["new_size"], 12)

    def test_audit_rejects_fake_service_conclusion_without_trusting_it(self):
        base = self.start_server()
        self.request(base, "POST", "/v1/records", {"records": [{"x": i} for i in range(6)]})
        response = self.request(base, "GET", "/v1/consistency?old_size=3")
        response["proof"][-1] = bytes.fromhex(response["proof"][-1])[::-1].hex()
        root_3 = self.request(base, "GET", "/v1/consistency?old_size=3")["old_root_hash"]
        result = audit.verify_consistency_response(3, bytes.fromhex(root_3), response)
        self.assertFalse(result["ok"])

    def test_process_crash_between_durable_records_and_tree_head_publication(self):
        base = self.start_server({"VLOG_CRASH_AT": "records_fsynced"})
        with self.assertRaises((urllib.error.URLError, http.client.RemoteDisconnected)):
            self.request(
                base,
                "POST",
                "/v1/records",
                {"records": [{"durable": True}, {"durable": True}]},
            )
        self.process.wait(timeout=10)
        self.assertEqual(self.process.returncode, 99)
        self._close_process_streams()
        self.process = None

        base = self.start_server()
        head = audit.tree_head(base)
        self.assertEqual(head["tree_size"], 2)
        self.assertTrue(audit.audit_root(base)["ok"])
        self.assertTrue(audit.audit_inclusion(base, 0)["ok"])
        self.assertTrue(audit.audit_inclusion(base, 1)["ok"])

    def test_crash_after_tree_head_replacement_still_publishes_records(self):
        base = self.start_server({"VLOG_CRASH_AT": "head_replaced"})
        with self.assertRaises((urllib.error.URLError, http.client.RemoteDisconnected)):
            self.request(base, "POST", "/v1/records", {"records": [{"x": 1}]})
        self.process.wait(timeout=10)
        self.assertEqual(self.process.returncode, 99)
        self._close_process_streams()
        self.process = None

        base = self.start_server()
        head = audit.tree_head(base)
        self.assertEqual(head["tree_size"], 1)
        self.assertTrue(audit.audit_root(base)["ok"])


if __name__ == "__main__":
    unittest.main()
