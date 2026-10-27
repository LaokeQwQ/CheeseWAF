#!/usr/bin/env python3
"""Minimal OpenAI-compatible mock for AI/ALAP prompt-injection tests."""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = None
    lock = threading.Lock()
    response_text = "OK"

    def log_message(self, *a):
        return

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/models"):
            self._json(200, {"object": "list", "data": [{"id": "mock-model", "object": "model"}]})
            return
        self._json(200, {"ok": True})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b""
        with self.lock:
            with open(self.log_path, "a") as fh:
                fh.write(json.dumps({"ts": time.time(), "path": self.path, "body": raw.decode("utf-8", "replace")}) + "\n")
                fh.flush()
        try:
            req = json.loads(raw or b"{}")
        except Exception:
            req = {}
        text = self.response_text
        # Echo the last user message length so tests can prove prompt injection reached the model.
        msgs = req.get("messages") or []
        if msgs:
            last = msgs[-1].get("content")
            if isinstance(last, str):
                text = json.dumps({"injected": "CWX" in last, "response": "OK"})
        self._json(200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model", "mock-model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--pid", required=True)
    ap.add_argument("--response", default="OK")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.log), exist_ok=True)
    open(a.log, "a").close()
    open(a.pid, "w").write(str(os.getpid()))
    H.log_path = a.log
    H.response_text = a.response
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
