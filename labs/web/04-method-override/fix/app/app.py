#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))

INDEX_PAGE = """<!DOCTYPE html>
<html><head><title>Welcome</title></head><body>
<h1>Welcome</h1>
<p>This is the public landing page.</p>
<p><a href="/static/app.js">app.js</a></p>
</body></html>
"""

STATIC_JS = 'console.log("lab4");\n'


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

    def do_GET(self):
        path = urlsplit(self.path).path
        override = (self.headers.get("X-HTTP-Method-Override") or "").upper()
        empty = (override == "HEAD")
        if path == "/static/app.js":
            self._send(200, "" if empty else STATIC_JS, "text/javascript",
                       [("Cache-Control", "public, max-age=3600")])
        elif path == "/":
            self._send(200, "" if empty else INDEX_PAGE,
                       extra_headers=[("Cache-Control", "public, max-age=60")])
        else:
            self._send(404, "Not Found")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
