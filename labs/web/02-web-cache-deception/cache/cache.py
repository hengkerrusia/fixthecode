#!/usr/bin/env python3
"""
cache.py — reverse proxy dengan cache di edge.

Meneruskan request ke aplikasi origin. Respons GET untuk path ber-ekstensi
statis disimpan di cache memori dan disajikan ulang untuk request berikutnya.
Header X-Cache menandai MISS/HIT/BYPASS untuk tiap respons.
"""
import os
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

APP_HOST = os.environ.get("APP_HOST", "app")
APP_PORT = int(os.environ.get("APP_PORT", "8000"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))

# Ekstensi path yang dianggap konten statis.
STATIC_EXTS = {
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".avif",
    ".bmp", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
    ".exe", ".dmg", ".iso", ".csv", ".txt", ".xml", ".json",
}

_store = {}


def _cacheable_path(path):
    segment = urlsplit(path).path.rsplit("/", 1)[-1]
    if "." not in segment:
        return False
    ext = "." + segment.rsplit(".", 1)[-1].lower()
    return ext in STATIC_EXTS


def _fetch_from_origin(method, path, headers, body):
    conn = HTTPConnection(APP_HOST, APP_PORT, timeout=10)
    fwd = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("host", "connection", "content-length"):
            continue
        fwd[k] = v
    fwd["Host"] = "%s:%d" % (APP_HOST, APP_PORT)
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
        if self.command == "GET" and _cacheable_path(self.path):
            if self.path in _store:
                status, headers, data = _store[self.path]
                self._send(status, headers, data, "HIT")
                return
            status, headers, data = _fetch_from_origin(
                self.command, self.path, self.headers, None)
            if status == 200:
                _store[self.path] = (status, headers, data)
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
