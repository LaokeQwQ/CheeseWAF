#!/usr/bin/env python3
"""Cookie/CSRF-aware management API client for the audit harness."""
import argparse
import http.client
import json
import os
import ssl
import sys
import urllib.parse


def parse_url(url):
    u = urllib.parse.urlparse(url)
    return u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80), u.path + (("?" + u.query) if u.query else "")


def conn_for(scheme, host, port, insecure=True):
    if scheme == "https":
        ctx = ssl._create_unverified_context() if insecure else None
        return http.client.HTTPSConnection(host, port, context=ctx, timeout=15)
    return http.client.HTTPConnection(host, port, timeout=15)


def load_jar(path):
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {}


def save_jar(path, jar):
    with open(path, "w") as fh:
        json.dump(jar, fh, indent=2)


def do_login(args):
    scheme, host, port, path = parse_url(args.admin_url)
    body = json.dumps({"username": args.user, "password": args.password}).encode()
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    c = conn_for(scheme, host, port, True)
    c.request("POST", "/api/auth/login", body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    jar = {}
    for sc in r.msg.get_all("Set-Cookie") or []:
        pair = sc.split(";", 1)[0]
        if "=" in pair:
            k, v = pair.split("=", 1)
            jar[k.strip()] = v.strip()
    save_jar(args.jar, jar)
    print(json.dumps({"status": r.status, "body": data.decode("utf-8", "replace")[:500], "cookies": sorted(jar)}))
    return 0 if r.status == 200 else 1


def do_request(args):
    jar = load_jar(args.jar)
    scheme, host, port, path = parse_url(args.url)
    headers = {}
    for h in args.header or []:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if jar:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
    method = args.method
    body = None
    if args.data is not None:
        body = args.data.encode()
        headers.setdefault("Content-Type", "application/json")
    if method not in ("GET", "HEAD", "OPTIONS") and args.csrf and "cheesewaf_csrf" in jar:
        headers.setdefault("X-CSRF-Token", jar["cheesewaf_csrf"])
    if body is not None:
        headers["Content-Length"] = str(len(body))
    c = conn_for(scheme, host, port, True)
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    print(json.dumps({"status": r.status, "headers": dict(r.getheaders()), "body": data.decode("utf-8", "replace")}))


def do_mint(args):
    jar = load_jar(args.jar)
    scheme, host, port, _ = parse_url(args.admin_url)
    body = json.dumps({"name": args.name, "scopes": args.scopes.split(","), "ttl": args.ttl}).encode()
    headers = {"Content-Type": "application/json", "Cookie": "; ".join(f"{k}={v}" for k, v in jar.items())}
    if "cheesewaf_csrf" in jar:
        headers["X-CSRF-Token"] = jar["cheesewaf_csrf"]
    c = conn_for(scheme, host, port, True)
    c.request("POST", "/api/system/api-tokens", body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    print(json.dumps({"status": r.status, "body": data.decode("utf-8", "replace")}))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    lg = sub.add_parser("login")
    lg.add_argument("--admin-url", required=True)
    lg.add_argument("--user", default="admin")
    lg.add_argument("--password", required=True)
    lg.add_argument("--jar", required=True)
    lg.set_defaults(func=do_login)

    rq = sub.add_parser("request")
    rq.add_argument("--method", default="GET")
    rq.add_argument("--url", required=True)
    rq.add_argument("--jar", default="")
    rq.add_argument("--csrf", action="store_true")
    rq.add_argument("--data", default=None)
    rq.add_argument("--header", action="append")
    rq.set_defaults(func=do_request)

    mt = sub.add_parser("mint-token")
    mt.add_argument("--admin-url", required=True)
    mt.add_argument("--jar", required=True)
    mt.add_argument("--name", default="audit-token")
    mt.add_argument("--scopes", default="read:*")
    mt.add_argument("--ttl", default="1h")
    mt.set_defaults(func=do_mint)
    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
