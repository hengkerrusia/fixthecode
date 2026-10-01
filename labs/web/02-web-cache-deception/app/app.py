#!/usr/bin/env python3
"""
app.py — aplikasi origin.

Menyajikan halaman publik, satu file statis, dan halaman akun yang butuh
sesi login. Komentar di file ini hanya menjelaskan fungsi generik tiap bagian.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))

# Kredensial akun uji (didokumentasikan di README lab).
LOGIN_USER = "victim"
LOGIN_PASS = "victim-pass"
SESSION_TOKEN = "victim-session-token"

INDEX_PAGE = """<!DOCTYPE html>
<html><head><title>Welcome</title></head><body>
<h1>Welcome</h1>
<p>This is the public landing page.</p>
<p><a href="/login">Login</a></p>
</body></html>
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Login</title></head><body>
<h1>Login</h1>
<form method="post" action="/login">
<p><label>Username<br><input type="text" name="user"></label></p>
<p><label>Password<br><input type="password" name="pass"></label></p>
<p><button type="submit">Login</button></p>
</form>
</body></html>
"""

LOGIN_OK_PAGE = """<!DOCTYPE html>
<html><head><title>Login</title></head><body>
<h1>Login successful</h1>
<p><a href="/account">Go to your account</a></p>
</body></html>
"""

STATIC_CSS = "body { color: #333; }\n"

ACCOUNT_PAGE = """<!DOCTYPE html>
<html><head><title>Account</title></head><body>
<h1>Account page</h1>
<p>ACCOUNT-OWNER: rina</p>
<p>Name: Rina Wijaya</p>
<p>Balance: 12.450.000</p>
<p>Card: **** **** **** 1234</p>
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

    def _session_ok(self):
        return ("session=" + SESSION_TOKEN) in (self.headers.get("Cookie") or "")

    def _serve_account(self):
        if not self._session_ok():
            self._send(401, "Unauthorized",
                       extra_headers=[("Cache-Control", "no-store")])
            return
        self._send(200, ACCOUNT_PAGE,
                   extra_headers=[("Cache-Control", "private")])

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, INDEX_PAGE)
        elif path == "/login":
            self._send(200, LOGIN_PAGE)
        elif path == "/static/app.css":
            self._send(200, STATIC_CSS, "text/css",
                       [("Cache-Control", "public, max-age=3600")])
        elif path == "/account" or path.startswith("/account/"):
            self._serve_account()
        else:
            self._send(404, "Not Found")

    def do_POST(self):
        path = urlsplit(self.path).path
        if path != "/login":
            self._send(404, "Not Found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        fields = parse_qs(self.rfile.read(length).decode("utf-8")) if length else {}
        user = fields.get("user", [""])[0]
        password = fields.get("pass", [""])[0]
        if user == LOGIN_USER and password == LOGIN_PASS:
            self._send(200, LOGIN_OK_PAGE, extra_headers=[
                ("Set-Cookie",
                 "session=%s; Path=/; HttpOnly" % SESSION_TOKEN)])
        else:
            self._send(401, "Unauthorized")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
