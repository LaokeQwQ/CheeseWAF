#!/usr/bin/env python3
"""Raw HTTP helper: sends exact bytes and records exact bytes back."""
import argparse
import base64
import json
import socket
import ssl
import sys
import time


def recv_all(sock, timeout=3.0):
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    except socket.timeout:
        pass
    except Exception:
        pass
    return b"".join(chunks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sub", choices=["request"])
    ap.add_argument("--raw-file", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.raw_file, "rb") as fh:
        raw = fh.read()

    ctx = ssl._create_unverified_context() if args.tls else None
    s = socket.create_connection((args.host, args.port), timeout=5)
    if ctx:
        s = ctx.wrap_socket(s, server_hostname=args.host)
    start = time.time()
    s.sendall(raw)
    resp = recv_all(s)
    try:
        s.close()
    except Exception:
        pass

    first_line = resp.split(b"\r\n", 1)[0].decode("latin1") if resp else ""
    status = 0
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    headers = {}
    body = b""
    if b"\r\n\r\n" in resp:
        head, body = resp.split(b"\r\n\r\n", 1)
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers.setdefault(k.decode("latin1").strip(), []).append(v.decode("latin1").strip())
    result = {
        "request_b64": base64.b64encode(raw).decode(),
        "request_text": raw.decode("latin1"),
        "response_b64": base64.b64encode(resp).decode(),
        "response_text": resp.decode("latin1"),
        "status": status,
        "headers": headers,
        "body_b64": base64.b64encode(body).decode(),
        "duration_ms": int((time.time() - start) * 1000),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"status": status, "out": args.out, "bytes": len(resp)}))


if __name__ == "__main__":
    main()
