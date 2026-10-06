#!/usr/bin/env python3
import json
import os
import re
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

CODE_RE = re.compile(r"^[A-Za-z0-9]{9}$")
CARD_UUID = "a1b2c3d4-e5f6-4789-abcd-ef0123456789"
VICTIM_USER = "victim"
VICTIM_PASS = "victim123"
ORIGINS = ("http://127.0.0.1:8080", "http://localhost:8080")

sessions = {}
cards = {CARD_UUID: "active"}

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "static", "invite.js")) as f:
    INVITE_JS = f.read()

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>Lab 11 — Invite Demo</title></head>
<body>
<h1>Invite demo</h1>
<p><a href="/invite?code=INV123ABC">Open invite INV123ABC</a></p>
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
    document.getElementById("r").textContent = j.ok ? "logged in" : "failed";
  });
});
</script>
</body></html>"""

INVITE_HTML = """<!DOCTYPE html>
<html><head><title>Invite</title></head>
<body>
<h1>Invite check</h1>
<div id="result">checking...</div>
<script src="/static/invite.js"></script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab11/1.0"

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

    def _cookies(self):
        out = {}
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out[k] = v
        return out

    def _session(self):
        return sessions.get(self._cookies().get("session", ""))

    def do_GET(self):
        u = urlsplit(self.path)
        path, qs = u.path, parse_qs(u.query)
        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/login":
            self._send(200, LOGIN_HTML)
        elif path == "/invite":
            self._send(200, INVITE_HTML)
        elif path == "/static/invite.js":
            self._send(200, INVITE_JS, "application/javascript")
        elif path == "/api/cards":
            s = self._session()
            if not s:
                return self._send(401, '{"error":"login required"}',
                                  "application/json")
            self._send(200, json.dumps({"cards": [
                {"id": cid, "status": st} for cid, st in cards.items()]}),
                "application/json")
        elif path.startswith("/api/cards/"):
            s = self._session()
            if not s:
                return self._send(401, '{"error":"login required"}',
                                  "application/json")
            cid = unquote(path[len("/api/cards/"):])
            if cid in cards:
                self._send(200, json.dumps({"id": cid, "status": cards[cid]}),
                           "application/json")
            else:
                self._send(404, '{"error":"no such card"}', "application/json")
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
                stok = "sess-" + secrets.token_hex(8)
                xtok = "xsrf-" + secrets.token_hex(8)
                sessions[stok] = {"user": VICTIM_USER, "xsrf": xtok}
                self._send(200, '{"ok": true}', "application/json", [
                    ("Set-Cookie",
                     "session=%s; HttpOnly; SameSite=Lax; Path=/" % stok),
                    ("Set-Cookie",
                     "XSRF-TOKEN=%s; SameSite=Lax; Path=/" % xtok),
                ])
            else:
                self._send(401, '{"ok": false}', "application/json")
        elif path.startswith("/api/invite/") and path.endswith("/check"):
            code = unquote(path[len("/api/invite/"):-len("/check")])
            if CODE_RE.fullmatch(code):
                self._send(200, '{"valid": true}', "application/json")
            else:
                self._send(400, '{"valid": false}', "application/json")
        elif path.startswith("/api/cards/") and path.endswith("/cancel"):
            cid = unquote(path[len("/api/cards/"):-len("/cancel")])
            s = self._session()
            if not s:
                return self._send(401, '{"error":"login required"}',
                                  "application/json")
            if self.headers.get("X-XSRF-Token", "") != s["xsrf"]:
                return self._send(403, '{"error":"bad xsrf token"}',
                                  "application/json")
            if self.headers.get("Origin", "") not in ORIGINS:
                return self._send(403, '{"error":"bad origin"}',
                                  "application/json")
            if cid in cards and cards[cid] == "active":
                cards[cid] = "cancelled"
                self._send(200, '{"status": "cancelled"}', "application/json")
            else:
                self._send(404, '{"error":"no such card"}', "application/json")
        else:
            self._send(404, "not found", "text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 80))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
