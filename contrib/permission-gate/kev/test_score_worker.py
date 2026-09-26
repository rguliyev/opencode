"""Contract tests for the staged v2 Kev socket worker; no checkpoint needed."""

import hashlib
import json
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import score_worker


def request(kind, evidence, context=None):
    return {
        "version": 2,
        "kind": kind,
        "request_id": "permission-test-1",
        "command_index": 0,
        "source_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        "review_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
        "state": {
            "evidence": evidence,
            "context": context or {
                "agent": "solo",
                "workdir": "/workspace",
                "human_request": "Inspect the local fixture.",
                "human_history": "Earlier request: check the fixture status.",
                "delegated_task": "Report whether the file exists.",
                "immediate_effect": "Reads local data and returns it to the agent.",
                "subagent": True,
                "command_index": 0,
                "command_count": 1,
            },
            **({"scripts": []} if kind == "bash" else {}),
        },
        "redactions": [],
    }


class ScoreWorkerTest(unittest.TestCase):
    def parse(self, value):
        return score_worker.parse_request(json.dumps(value).encode())

    def test_action_is_received_with_context_but_not_mis_scored(self):
        evidence = json.dumps({"permission": "read", "patterns": ["src/main.ts"]}, separators=(",", ":"))
        parsed = self.parse(request("action", evidence))
        calls = []
        result = score_worker.review(parsed, lambda state: calls.append(state))
        self.assertEqual(result["status"], "unsupported_action")
        self.assertEqual(result["context_status"], "received")
        self.assertEqual(calls, [])
        self.assertEqual(len(result["state_sha256"]), 64)

    def test_shell_receives_full_human_context_before_jev(self):
        parsed = self.parse(request("bash", "printf hello"))
        states = []

        def score(state):
            states.append(state)
            return 0.9

        result = score_worker.review(parsed, score)
        self.assertEqual(result["status"], "score")
        self.assertEqual(result["model_scope"], "shell_only_unvalidated_context")
        self.assertEqual(states[0], {"command": "printf hello", "scripts": []})
        self.assertEqual(states[1]["context"]["human_request"], "Inspect the local fixture.")
        self.assertEqual(states[1]["context"]["human_history"], "Earlier request: check the fixture status.")
        self.assertEqual(states[1]["context"]["delegated_task"], "Report whether the file exists.")

    def test_shell_keeps_baseline_when_context_exceeds_checkpoint_window(self):
        parsed = self.parse(request("bash", "printf hello"))

        def score(state):
            if "context" in state:
                raise ValueError("state exceeds 384 tokens: 400")
            return 0.9

        result = score_worker.review(parsed, score)
        self.assertEqual(result["status"], "score")
        self.assertEqual(result["p_allow"], 0.9)
        self.assertEqual(result["context_status"], "model_overflow")
        self.assertNotIn("context_p_allow", result)

    def test_shell_baseline_overflow_is_explicit(self):
        parsed = self.parse(request("bash", "printf hello"))

        def score(_state):
            raise ValueError("state exceeds 384 tokens: 400")

        result = score_worker.review(parsed, score)
        self.assertEqual(result["status"], "context_rejected")
        self.assertEqual(result["context_status"], "model_overflow")

    def test_rejects_unmasked_secrets_and_missing_human_context(self):
        safe = request("bash", "printf hello")
        unsafe = request("bash", "echo sk-" + "x" * 32)
        with self.assertRaisesRegex(ValueError, "sensitive_literal"):
            self.parse(unsafe)
        del safe["state"]["context"]["human_request"]
        with self.assertRaisesRegex(ValueError, "required_context"):
            self.parse(safe)
        missing_delegation = request("bash", "printf hello")
        del missing_delegation["state"]["context"]["delegated_task"]
        with self.assertRaisesRegex(ValueError, "delegated_task"):
            self.parse(missing_delegation)

    def test_rejects_bad_digest_and_duplicate_json_keys(self):
        value = request("bash", "printf hello")
        value["review_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "review_sha256_mismatch"):
            self.parse(value)
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            score_worker.parse_request(b'{"version":2,"version":2}')

    def test_socket_reply_contains_only_status_and_hash(self):
        evidence = json.dumps({"permission": "read", "patterns": ["src/main.ts"]})
        value = request("action", evidence)
        with tempfile.TemporaryDirectory(prefix="kev-v2-test-") as directory:
            address = str(Path(directory) / "score.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(address)
            listener.listen(1)
            thread = threading.Thread(target=score_worker.serve_one, args=(listener, lambda _: 0.9))
            thread.start()
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(address)
                client.sendall(json.dumps(value).encode() + b"\n")
                result = json.loads(client.recv(2048))
            thread.join(timeout=2)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["status"], "unsupported_action")
        self.assertNotIn(evidence, json.dumps(result))

    def test_server_scores_two_shell_requests_concurrently(self):
        barrier = threading.Barrier(2)

        def score(_state):
            barrier.wait(timeout=3)
            return 0.9

        with tempfile.TemporaryDirectory(prefix="kev-v2-test-") as directory:
            address = str(Path(directory) / "score.sock")
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(address)
            listener.listen(2)
            stop = threading.Event()
            server = threading.Thread(target=score_worker.serve_forever, args=(listener, score, stop))
            server.start()

            def client(command):
                with socket.socket(socket.AF_UNIX) as connection:
                    connection.settimeout(4)
                    connection.connect(address)
                    connection.sendall(json.dumps(request("bash", command)).encode() + b"\n")
                    return json.loads(connection.recv(2048))

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(client, ("printf one", "printf two")))
            finally:
                stop.set()
                server.join(timeout=3)
                listener.close()
        self.assertFalse(server.is_alive())
        self.assertEqual([result["status"] for result in results], ["score", "score"])


if __name__ == "__main__":
    unittest.main()
