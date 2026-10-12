#!/usr/bin/env python3
"""Simulasi GitLab Maven Package Registry.

Menyediakan API upload/download artefak Maven per proyek.
"""
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE = "/data/packages"


def parse_maven_path(raw_path):
    path = urllib.parse.urlparse(raw_path).path
    prefix = "/api/v4/projects/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    parts = rest.split("/")
    if len(parts) < 4 or parts[1] != "packages" or parts[2] != "maven":
        return None
    project_id = parts[0]
    file_name_enc = parts[-1]
    maven_path = "/".join(parts[3:-1])
    file_name = urllib.parse.unquote(file_name_enc)
    return project_id, maven_path, file_name


def storage_path(maven_path, file_name):
    return os.path.join(STORAGE, maven_path, file_name)


class Handler(BaseHTTPRequestHandler):
    server_version = "MavenRegistry/1.0"

    def _send(self, status, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        parsed = parse_maven_path(self.path)
        if not parsed:
            self._send(404, "not found")
            return
        _, maven_path, file_name = parsed
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        data = self.rfile.read(length)
        dest = storage_path(maven_path, file_name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
        self._send(200, "uploaded")

    def do_GET(self):
        parsed = parse_maven_path(self.path)
        if not parsed:
            self._send(404, "not found")
            return
        _, maven_path, file_name = parsed
        dest = storage_path(maven_path, file_name)
        if not os.path.isfile(dest):
            self._send(404, "not found")
            return
        with open(dest, "rb") as fh:
            self._send(200, fh.read())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    os.makedirs(STORAGE, exist_ok=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
