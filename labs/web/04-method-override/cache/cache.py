#!/usr/bin/env python3
import os
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer

APP_HOST = os.environ.get("APP_HOST", "app")
APP_PORT = int(os.environ.get("APP_PORT", "8000"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))

_store = {}


def _cache_key(method, path):
    return method + " " + path


def _cacheable_response(status, headers):
    if status != 200:
        return False
    for k, v in headers:
        if k.lower() == "cache-control" and "public" in v.lower():
            return True
    return False


def _fetch_from_origin(method, path, headers, body):
    conn = HTTPConnection(APP_HOST, APP_PORT, timeout=10)
    fwd = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("connection", "content-length"):
            continue
        fwd[k] = v
    conn.request(method, path, body=body, headers=fwd)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.getheaders(), data


class Handler(BaseHTTPRequestHandler):
    server_version = "CacheEdge/1.0"

    def _send(self, status, headers, data, cache_flag):
        self.send_response(status)
        for k, v in headers:
            if k.lower() in ("connection", "transfer-encoding", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("X-Cache", cache_flag)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else None

    def _handle(self):
        if self.command == "GET":
            key = _cache_key(self.command, self.path)
            if key in _store:
                status, headers, data = _store[key]
                self._send(status, headers, data, "HIT")
                return
            status, headers, data = _fetch_from_origin(
                self.command, self.path, self.headers, None)
            if _cacheable_response(status, headers):
                _store[key] = (status, headers, data)
            self._send(status, headers, data, "MISS")
            return
        body = self._read_body() if self.command in ("POST", "PUT", "PATCH") else None
        status, headers, data = _fetch_from_origin(
            self.command, self.path, self.headers, body)
        self._send(status, headers, data, "BYPASS")

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
