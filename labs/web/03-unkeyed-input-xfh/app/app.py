#!/usr/bin/env python3
"""
app.py — aplikasi origin.

Menyajikan halaman publik dan satu file statis. Halaman utama memuat URL
absolut untuk aset statisnya. Komentar di file ini hanya menjelaskan fungsi
generik tiap bagian.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))

INDEX_PAGE = """<!DOCTYPE html>
<html><head><title>Welcome</title></head><body>
<h1>Welcome</h1>
<p>This is the public landing page.</p>
<script src="https://{host}/static/app.js"></script>
</body></html>
"""

STATIC_JS = 'console.log("lab3");\n'


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

    def _page_host(self):
        # Tentukan host yang dipakai untuk membangun URL absolut di halaman.
        forwarded = self.headers.get("X-Forwarded-Host")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.headers.get("Host", "localhost")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            host = self._page_host()
            self._send(200, INDEX_PAGE.format(host=host),
                       extra_headers=[("Cache-Control", "public, max-age=60")])
        elif path == "/static/app.js":
            self._send(200, STATIC_JS, "text/javascript",
                       [("Cache-Control", "public, max-age=3600")])
        else:
            self._send(404, "Not Found")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
