#!/usr/bin/env python3
"""Mock origin for the CheeseWAF attack-chain audit.

Records every received request as one JSON line so a WAF bypass can be proven
from the origin's point of view, not from the WAF's response alone.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def read_chunked(rfile):
    chunks = []
    while True:
        line = rfile.readline(65536)
        if not line:
            break
        size_str = line.split(b";", 1)[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            # consume trailers
            while True:
                trailer = rfile.readline(65536)
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        chunks.append(rfile.read(size))
        rfile.read(2)
    return b"".join(chunks)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log_path = None
    lock = threading.Lock()

    def log_message(self, fmt, *args):
        return

    def _record(self, body):
        entry = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path.split("?", 1)[0],
            "query": self.path.split("?", 1)[1] if "?" in self.path else "",
            "headers": {k: self.headers.get_all(k) for k in self.headers.keys()},
            "body_b64": base64.b64encode(body or b"").decode(),
            "client": self.client_address[0],
            "http_version": self.request_version,
        }
        with self.lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower().find("chunked") >= 0:
            return read_chunked(self.rfile)
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    def _respond(self, code=200, body=b"ORIGIN_OK\n", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _echo(self, body):
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": {k: self.headers.get_all(k) for k in self.headers.keys()},
            "body_len": len(body or b""),
            "body_b64": base64.b64encode(body or b"").decode(),
        }, ensure_ascii=False).encode()
        self._respond(200, b"ORIGIN_OK\n" + payload, "application/json")

    def _maybe_ws(self):
        if self.path.split("?", 1)[0] != "/ws":
            return False
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return False
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        while True:
            hdr = self.rfile.read(2)
            if len(hdr) < 2:
                break
            b1, b2 = hdr
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            ln = b2 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self.rfile.read(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self.rfile.read(8))[0]
            mask = self.rfile.read(4) if masked else b"\x00" * 4
            data = bytearray(self.rfile.read(ln))
            for i in range(len(data)):
                data[i] ^= mask[i % 4]
            if opcode == 8:
                break
            # echo text/binary frame
            out = bytes(data)
            self.wfile.write(bytes([0x80 | (opcode & 0x0F), len(out)]) + out)
            self.wfile.flush()
        return True

    def _handle(self):
        body = self._read_body()
        self._record(body)
        if self._maybe_ws():
            return
        if self.path.split("?", 1)[0] == "/redirect":
            self._respond(302, b"", extra={"Location": "/landed"})
            return
        if self.path.split("?", 1)[0] == "/big":
            self._respond(200, b"A" * (1024 * 1024), "application/octet-stream")
            return
        self._echo(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle
    do_HEAD = _handle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--pid", required=True)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    open(args.log, "a").close()
    with open(args.pid, "w") as fh:
        fh.write(str(os.getpid()))
    Handler.log_path = args.log
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
