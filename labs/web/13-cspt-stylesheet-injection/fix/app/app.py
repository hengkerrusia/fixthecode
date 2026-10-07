#!/usr/bin/env python3
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

THEME_RE = re.compile(r"^[a-z]{3,8}$")
VICTIM_USER = "victim"
VICTIM_PASS = "victim123"
SECRET = "k7x2m9pq"
THEMES = ("light", "dark")

sessions = {}

HERE = os.path.dirname(os.path.abspath(__file__))
CSS = {}
for _t in THEMES:
    with open(os.path.join(HERE, "static", "theme.%s.css" % _t)) as _f:
        CSS[_t] = _f.read()

PAGE_HTML = """<!DOCTYPE html>
<html><head><title>Settings</title>
<link rel="stylesheet" href="/static/theme.__THEME__.css">
</head>
<body>
<h1>Settings</h1>
<input type="hidden" name="csrf_token" value="__SECRET__">
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
    document.getElementById("r").textContent = j.ok ? "logged in" : "failed";
  });
});
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab13/1.0"

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

    def _session(self):
        tok = ""
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "session":
                    tok = v
        return sessions.get(tok)

    def do_GET(self):
        u = urlsplit(self.path)
        path, qs = u.path, parse_qs(u.query)
        if path == "/login":
            self._send(200, LOGIN_HTML)
        elif path == "/":
            if not self._session():
                return self._send(401, "login required", "text/plain")
            theme = qs.get("theme", ["light"])[0]
            html = PAGE_HTML.replace("__THEME__", theme).replace("__SECRET__", SECRET)
            self._send(200, html)
        elif path.startswith("/static/theme.") and path.endswith(".css"):
            name = path[len("/static/theme."):-len(".css")]
            if name in CSS:
                self._send(200, CSS[name], "text/css")
            else:
                self._send(404, "no such theme", "text/plain")
        elif path == "/api/authorize":
            state = qs.get("state", [""])[0]
            self.send_response(302)
            self.send_header("Location", state)
            self.send_header("Content-Length", "0")
            self.end_headers()
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
                stok = "sess-" + os.urandom(8).hex()
                sessions[stok] = {"user": VICTIM_USER}
                self._send(200, '{"ok": true}', "application/json", [
                    ("Set-Cookie",
                     "session=%s; HttpOnly; SameSite=Lax; Path=/" % stok),
                ])
            else:
                self._send(401, '{"ok": false}', "application/json")
        else:
            self._send(404, "not found", "text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 80))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
