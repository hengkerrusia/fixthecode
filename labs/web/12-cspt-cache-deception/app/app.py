#!/usr/bin/env python3
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

ID_RE = re.compile(r"^[a-z0-9]{6,16}$")
VICTIM_USER = "victim"
VICTIM_PASS = "victim123"
VICTIM_TOKEN = "sk-live-7f3a9c2e4b1d8f6a"
USER_ID = "user123"
USER_NAME = "Victim User"

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "static", "profile.js")) as f:
    PROFILE_JS = f.read()

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>Lab 12 — Profile Demo</title></head>
<body>
<h1>Profile demo</h1>
<p><a href="/profile?id=user123">Open profile user123</a></p>
<p><a href="/login">Login</a></p>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<h1>Login</h1>
<form id="f">
<input name="username" value="victim">
<input name="password" type="password" value="victim123">
<button>Login</button>
</form>
<div id="r"></div>
<script>
document.getElementById("f").addEventListener("submit", function (e) {
  e.preventDefault();
  var fd = new FormData(e.target);
  fetch("/login", {method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: fd.get("username"), password: fd.get("password")})
  }).then(function (r) { return r.json(); }).then(function (j) {
    document.getElementById("r").textContent = j.token ? "logged in" : "failed";
  });
});
</script>
</body></html>"""

PROFILE_HTML = """<!DOCTYPE html>
<html><head><title>Profile</title></head>
<body>
<h1>Profile</h1>
<div id="result">loading...</div>
<script src="/static/profile.js"></script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab12/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        return self.headers.get("X-Auth-Token", "") == VICTIM_TOKEN

    def do_GET(self):
        u = urlsplit(self.path)
        path, qs = u.path, parse_qs(u.query)
        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/login":
            self._send(200, LOGIN_HTML)
        elif path == "/profile":
            self._send(200, PROFILE_HTML)
        elif path == "/static/profile.js":
            self._send(200, PROFILE_JS, "application/javascript")
        elif path == "/v1/users/me":
            if not self._authed():
                return self._send(401, '{"error":"unauthorized"}',
                                  "application/json")
            self._send(200, json.dumps({"id": USER_ID, "name": USER_NAME}),
                       "application/json",
                       [("Cache-Control", "private, no-store")])
        elif path.startswith("/v1/users/info/"):
            if not self._authed():
                return self._send(401, '{"error":"unauthorized"}',
                                  "application/json")
            uid = unquote(path[len("/v1/users/info/"):])
            self._send(200, json.dumps({"id": uid, "name": USER_NAME}),
                       "application/json",
                       [("Cache-Control", "private, no-store")])
        elif path == "/v1/token.css":
            if not self._authed():
                return self._send(401, '{"error":"unauthorized"}',
                                  "application/json")
            self._send(200, json.dumps({"token": VICTIM_TOKEN}),
                       "application/json",
                       [("Cache-Control", "public, max-age=60")])
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        u = urlsplit(self.path)
        path = u.path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/login":
            try:
                data = json.loads(body.decode() or "{}")
            except Exception:
                data = {}
            if (data.get("username") == VICTIM_USER
                    and data.get("password") == VICTIM_PASS):
                self._send(200, json.dumps({"token": VICTIM_TOKEN}),
                           "application/json", [
                               ("Set-Cookie",
                                "auth_token=%s; SameSite=Lax; Path=/" % VICTIM_TOKEN),
                           ])
            else:
                self._send(401, '{"error":"bad credentials"}',
                           "application/json")
        else:
            self._send(404, "not found", "text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
