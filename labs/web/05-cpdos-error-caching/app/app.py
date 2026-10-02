#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))

ALLOWED_HOSTS = set(
    h.strip()
    for h in os.environ.get(
        "ALLOWED_HOSTS", "127.0.0.1:8080,localhost:8080").split(",")
    if h.strip()
)

INDEX_PAGE = """<!DOCTYPE html>
<html><head><title>Welcome</title></head><body>
<h1>Welcome</h1>
<p>This is the public landing page.</p>
<p><a href="/static/app.js">app.js</a></p>
</body></html>
"""

STATIC_JS = 'console.log("lab5");\n'

FORBIDDEN_PAGE = """<!DOCTYPE html>
<html><head><title>Forbidden</title></head><body>
<h1>Forbidden</h1>
<p>Unrecognized host.</p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "OriginApp/1.0"

    def _send(self, status, body, content_type="text/html", extra_headers=()):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _effective_host(self):
        forwarded = self.headers.get("X-Forwarded-Host")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return (self.headers.get("Host") or "").strip()

    def do_GET(self):
        if self._effective_host() not in ALLOWED_HOSTS:
            self._send(403, FORBIDDEN_PAGE,
                       extra_headers=[("Cache-Control", "public, max-age=60")])
            return
        path = urlsplit(self.path).path
        if path == "/static/app.js":
            self._send(200, STATIC_JS, "text/javascript",
                       [("Cache-Control", "public, max-age=3600")])
        elif path == "/":
            self._send(200, INDEX_PAGE,
                       extra_headers=[("Cache-Control", "public, max-age=60")])
        else:
            self._send(404, "Not Found")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
