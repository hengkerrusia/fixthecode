import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

USERS = {"admin": "admin-pw"}
SESSIONS = {}
APPS = []

PANEL = """<!doctype html>
<html><head><meta charset="utf-8"><title>Argo CD</title></head>
<body>
<h1>Argo CD</h1>
<form method="post" action="/api/v1/session">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Login</button>
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab37/1.0"

    def _cookies(self):
        out = {}
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _send(self, code, obj, cookies=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        return self.rfile.read(n) if n else b""

    def _parsed_body(self):
        raw = self._body()
        try:
            return json.loads(raw or b"{}")
        except Exception:
            pass
        return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

    def _authed(self):
        return self._cookies().get("argocd.token", "") in SESSIONS

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/":
            self._send_html(200, PANEL)
            return
        if parts.path == "/api/v1/applications":
            if not self._authed():
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"items": APPS})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urlparse(self.path)
        if parts.path == "/api/v1/session":
            data = self._parsed_body()
            username = str(data.get("username", "")).strip()
            if USERS.get(username) != data.get("password"):
                self._send(401, {"error": "invalid credentials"})
                return
            token = "tok_" + secrets.token_hex(16)
            SESSIONS[token] = username
            cookie = ("argocd.token=%s; Domain=lab.local; Path=/; "
                      "HttpOnly; SameSite=Lax" % token)
            self._send(200, {"token": token}, [cookie])
            return
        if parts.path == "/api/v1/applications":
            if not self._authed():
                self._send(401, {"error": "unauthorized"})
                return
            try:
                spec = json.loads(self._body() or b"{}")
            except Exception:
                self._send(400, {"error": "invalid body"})
                return
            name = str(spec.get("name", "")).strip()
            if not name:
                self._send(400, {"error": "name required"})
                return
            app = {"name": name, "spec": spec.get("spec", {})}
            APPS.append(app)
            self._send(201, app)
            return
        self._send(404, {"error": "not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
