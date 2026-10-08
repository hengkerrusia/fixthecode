#!/usr/bin/env python3
import base64
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("PORT", "8080"))
LOG_PATH = os.environ.get("LOG_PATH", "/tmp/access.log")

ADMIN_USER = "admin"
ADMIN_PASS = "s3cr3t!"

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>Portal</title></head>
<body>
<h1>Portal</h1>
<p>Area admin di <a href="/admin">/admin</a> (HTTP Basic auth).</p>
</body></html>"""

ADMIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin</title></head>
<body>
<h1>Admin panel</h1>
<p>Selamat datang.</p>
</body></html>"""


def parse_basic(auth):
    try:
        scheme, _, creds = auth.partition(" ")
        if scheme.lower() != "basic":
            return None, None
        decoded = base64.b64decode(creds.strip()).decode("latin-1")
        user, _, pwd = decoded.partition(":")
        return user, pwd
    except Exception:
        return None, None


class Handler(BaseHTTPRequestHandler):
    server_version = "Portal/1.0"

    def log_message(self, *a):
        pass

    def _log(self, user, status, size):
        ip = self.client_address[0]
        line = '%s - %s "%s %s" %d %d\n' % (
            ip, user, self.command, urlsplit(self.path).path, status, size)
        with open(LOG_PATH, "a") as f:
            f.write(line)

    def _send(self, code, body, ctype="text/html", user="-"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="admin"')
        self.end_headers()
        self.wfile.write(data)
        self._log(user, code, len(data))

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/logs":
            try:
                with open(LOG_PATH) as f:
                    content = f.read()
            except OSError:
                content = ""
            self._send(200, content, "text/plain")
        elif path == "/admin":
            user, pwd = parse_basic(self.headers.get("Authorization", ""))
            if user is None:
                user = "-"
            if user == ADMIN_USER and pwd == ADMIN_PASS:
                self._send(200, ADMIN_HTML, user=user)
            else:
                self._send(401, "auth required", "text/plain", user=user)
        else:
            self._send(404, "not found", "text/plain")


def main():
    open(LOG_PATH, "w").close()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
