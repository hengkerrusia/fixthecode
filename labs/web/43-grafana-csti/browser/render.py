#!/usr/bin/env python3
"""Render shim: headless Chromium untuk lab client-side.

POST /render  {"html": "<...>"}  ->  {"dom": "<...>"}

Menjalankan HTML di Chromium headless dan mengembalikan DOM hasil render
(setelah JavaScript dieksekusi). Dipakai exploit untuk membuktikan eksekusi
JS tanpa dependency di host — cukup HTTP stdlib.
"""
import json
import os
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

CHROME = (shutil.which("chromium") or shutil.which("chromium-browser")
          or "chromium")


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if urlsplit_path(self.path) != "/render":
            self._json(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            payload = {}
        html = payload.get("html", "")
        if not isinstance(html, str) or not html or len(html) > 200000:
            self._json(400, {"error": "field 'html' (string, <=200k) wajib"})
            return
        with tempfile.NamedTemporaryFile("w", suffix=".html",
                                         delete=False) as f:
            f.write(html)
            path = f.name
        try:
            p = subprocess.run(
                [CHROME, "--headless=new", "--no-sandbox", "--disable-gpu",
                 "--virtual-time-budget=5000", "--dump-dom",
                 "file://" + path],
                capture_output=True, text=True, timeout=90)
            dom = p.stdout
        except subprocess.TimeoutExpired:
            dom = ""
        finally:
            os.unlink(path)
        self._json(200, {"dom": dom})

    def log_message(self, *args):
        pass


def urlsplit_path(p):
    return p.split("?", 1)[0]


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
