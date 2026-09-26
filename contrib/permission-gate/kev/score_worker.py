#!/usr/bin/env python3
"""Versioned, local-only Kev scorer for sanitized OpenCode review evidence.

This process never approves a permission. The currently available checkpoint
was trained on shell commands and scripts only, so non-Bash actions are
acknowledged as unsupported rather than assigned a misleading probability.
No request text is logged or persisted by this worker.
"""

import hashlib
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import BoundedSemaphore


MAX_REQUEST_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 2048
MAX_MODEL_TOKENS = 2048
CONTEXT_KEYS = {
    "agent", "role_policy", "workdir", "command_index", "command_count",
    "session_title", "parent_title", "purpose", "full_command",
    "human_request", "human_history", "delegated_task", "immediate_effect", "subagent",
}
SENSITIVE = (
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\b(?:4/0A[A-Za-z0-9_-]{20,}|1//[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9_-]{20,})"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I),
)


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def parse_request(data):
    """Reject malformed, oversized, or obviously unsanitized v2 evidence."""
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("oversized")
    request = json.loads(
        data,
        object_pairs_hook=_no_duplicates,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")),
    )
    if not isinstance(request, dict) or set(request) != {
        "version", "kind", "request_id", "command_index", "source_sha256",
        "review_sha256", "state", "redactions",
    }:
        raise ValueError("request_shape")
    if request["version"] != 2 or request["kind"] not in ("bash", "action"):
        raise ValueError("protocol")
    if not isinstance(request["request_id"], str) or not 1 <= len(request["request_id"]) <= 256:
        raise ValueError("request_id")
    index = request["command_index"]
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 100:
        raise ValueError("command_index")
    for field in ("source_sha256", "review_sha256"):
        value = request[field]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(field)
    redactions = request["redactions"]
    if not isinstance(redactions, list) or len(redactions) > 20 or any(
        not isinstance(item, str) or not re.fullmatch(r"[A-Z_]{1,40}", item)
        for item in redactions
    ):
        raise ValueError("redactions")
    state = request["state"]
    if not isinstance(state, dict):
        raise ValueError("state")
    expected = {"evidence", "context"} | ({"scripts", "scripts_unavailable"} if request["kind"] == "bash" else set())
    if set(state) - expected or not {"evidence", "context"} <= set(state):
        raise ValueError("state_shape")
    evidence = state["evidence"]
    if not isinstance(evidence, str) or not evidence or len(evidence.encode()) > 64 * 1024:
        raise ValueError("evidence")
    if hashlib.sha256(evidence.encode()).hexdigest() != request["review_sha256"]:
        raise ValueError("review_sha256_mismatch")
    context = state["context"]
    if not isinstance(context, dict) or set(context) - CONTEXT_KEYS:
        raise ValueError("context")
    if not all(isinstance(context.get(key), str) and context[key] for key in (
        "agent", "workdir", "human_request", "immediate_effect",
    )):
        raise ValueError("required_context")
    if not isinstance(context.get("subagent"), bool):
        raise ValueError("subagent")
    if context["subagent"] and not isinstance(context.get("delegated_task"), str):
        raise ValueError("delegated_task")
    if (
        isinstance(context.get("command_index"), bool)
        or context.get("command_index") != index
        or isinstance(context.get("command_count"), bool)
        or not isinstance(context.get("command_count"), int)
    ):
        raise ValueError("context_index")
    if not 1 <= context["command_count"] <= 100 or index >= context["command_count"]:
        raise ValueError("context_count")
    if any(not isinstance(value, str) for key, value in context.items() if key not in (
        "command_index", "command_count", "subagent",
    )):
        raise ValueError("context_values")
    if len(json.dumps(context, ensure_ascii=False).encode()) > 12 * 1024:
        raise ValueError("context_size")
    if request["kind"] == "action":
        try:
            action = json.loads(evidence, object_pairs_hook=_no_duplicates)
        except (TypeError, ValueError) as error:
            raise ValueError("action_json") from error
        if not isinstance(action, dict) or not isinstance(action.get("permission"), str):
            raise ValueError("action_shape")
        if not isinstance(action.get("patterns"), list) or not action["patterns"] or any(
            not isinstance(pattern, str) for pattern in action["patterns"]
        ):
            raise ValueError("action_patterns")
    else:
        scripts = state.get("scripts", [])
        if not isinstance(scripts, list) or len(scripts) > 4:
            raise ValueError("scripts")
        for script in scripts:
            if not isinstance(script, dict) or set(script) - {"path", "content", "redactions"}:
                raise ValueError("script_shape")
            if not isinstance(script.get("path"), str) or not isinstance(script.get("content"), str):
                raise ValueError("script_content")
        if len(json.dumps(scripts, ensure_ascii=False).encode()) > 12 * 1024:
            raise ValueError("scripts_size")
        note = state.get("scripts_unavailable")
        if note is not None and (not isinstance(note, str) or len(note) > 512):
            raise ValueError("scripts_unavailable")
    if any(pattern.search(data.decode()) for pattern in SENSITIVE):
        raise ValueError("sensitive_literal")
    return request


def load_model():
    """Load the shell-only checkpoint; required paths are explicit at startup."""
    repo = Path(os.environ["KEV_REPO"])
    checkpoint = os.environ["KEV_CHECKPOINT"]
    questions = Path(os.environ["KEV_QUESTIONS"])
    sys.path.insert(0, str(repo))
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
    import torch
    from kev.api import SystemOneRequest, to_record
    from kev.checkpoint import Checkpoint, LoadOptions

    torch.set_num_threads(4)
    torch.set_num_interop_threads(1)
    question = json.loads(questions.read_text(encoding="utf-8"))["verdict"]
    tokenizer, model = Checkpoint(checkpoint).load("cpu", LoadOptions())

    def score(state):
        request = SystemOneRequest.model_validate({"state": state, "questions": {"verdict": question}})
        record, meta = to_record(request)
        encoding = model.encode(tokenizer, record, strict=True)
        if len(encoding["ids"]) > MAX_MODEL_TOKENS:
            return None
        with torch.inference_mode():
            probabilities = model.probs(encoding)[0].float().cpu().tolist()
        return round(float(probabilities[meta[0]["keys"].index("allow")]), 6)

    return score


def review(request, score):
    """Return advisory scores only; unsupported actions never get a fake score."""
    def score_or_overflow(state):
        try:
            return score(state)
        except ValueError as error:
            # Checkpoint.encode(strict=True) raises before our own token-count
            # check. Preserve the shell baseline when only context overflows.
            if str(error).startswith("state exceeds ") and " tokens:" in str(error):
                return None
            raise

    state = request["state"]
    receipt = hashlib.sha256(json.dumps(state, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    if request["kind"] == "action":
        return {"version": 2, "status": "unsupported_action", "context_status": "received", "state_sha256": receipt}
    command = state["evidence"]
    scripts = state.get("scripts", [])
    started = time.perf_counter()
    baseline = score_or_overflow({"command": command, "scripts": scripts})
    if baseline is None:
        return {"version": 2, "status": "context_rejected", "context_status": "model_overflow", "state_sha256": receipt}
    contextual = score_or_overflow({
        "command": command,
        "scripts": scripts,
        "context": state["context"],
        **({"scripts_unavailable": state["scripts_unavailable"]} if state.get("scripts_unavailable") else {}),
    })
    return {
        "version": 2,
        "status": "score",
        "model_scope": "shell_only_unvalidated_context",
        "p_allow": baseline,
        "context_status": "score" if contextual is not None else "model_overflow",
        **({"context_p_allow": contextual} if contextual is not None else {}),
        "latency_ms": round(1000 * (time.perf_counter() - started), 1),
        "state_sha256": receipt,
    }


def serve_connection(connection, score):
    with connection:
        connection.settimeout(5)
        data = bytearray()
        try:
            while len(data) <= MAX_REQUEST_BYTES:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in data:
                    break
            request = parse_request(bytes(data).split(b"\n", 1)[0])
            result = review(request, score)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            result = {"version": 2, "status": "withheld"}
        except Exception:
            # Model failures may contain request text in exception messages.
            result = {"version": 2, "status": "unavailable"}
        encoded = json.dumps(result, separators=(",", ":")).encode() + b"\n"
        if len(encoded) <= MAX_RESPONSE_BYTES:
            try:
                connection.sendall(encoded)
            except OSError:
                pass


def serve_one(listener, score):
    connection, _ = listener.accept()
    serve_connection(connection, score)


def serve_forever(listener, score, stop=None):
    """Bound the queue and score up to four requests concurrently."""
    slots = BoundedSemaphore(16)
    if stop is not None:
        listener.settimeout(0.2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        while stop is None or not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                with connection:
                    try:
                        connection.sendall(b'{"version":2,"status":"unavailable"}\n')
                    except OSError:
                        pass
                continue
            try:
                future = pool.submit(serve_connection, connection, score)
            except Exception:
                slots.release()
                connection.close()
                raise
            future.add_done_callback(lambda _future: slots.release())


def main():
    address = Path(os.environ["KEV_SCORE_SOCKET"])
    score = load_model()
    if address.exists():
        raise RuntimeError(f"Refusing to replace an existing socket: {address}")
    listener = socket.socket(socket.AF_UNIX)
    inode = None
    try:
        listener.bind(str(address))
        inode = address.stat().st_ino
        os.chmod(address, 0o600)
        listener.listen(16)
        serve_forever(listener, score)
    finally:
        listener.close()
        if inode is not None:
            try:
                if address.stat().st_ino == inode:
                    address.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    main()
