import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

CONFIG = {"setupComplete": True}

USERS = {
    "admin": {"password": "admin-pw", "email": "admin@lab.test",
              "full_name": "Site Administrator", "is_admin": True},
}

SESSIONS = {}

SETUP_FLAG = "bootstrapStatusProvider.applicationConfig.setupComplete"


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab34/1.0"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        raw = self.rfile.read(n) if n else b""
        return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return SESSIONS.get(auth[7:])
        return None

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/server-info.action":
            q = parse_qs(parts.query)
            vals = q.get(SETUP_FLAG, [])
            if vals and vals[0] in ("0", "false", "False"):
                CONFIG["setupComplete"] = False
            self._send(200, {"version": "8.5.1",
                             "setupComplete": CONFIG["setupComplete"]})
            return
        if parts.path == "/setup/setupadministrator-start.action":
            if CONFIG["setupComplete"]:
                self._send(403, {"error": "setup already complete"})
                return
            self._send(200, {"setup": "administrator"})
            return
        if parts.path == "/me":
            username = self._auth()
            if not username:
                self._send(401, {"error": "unauthorized"})
                return
            u = USERS[username]
            self._send(200, {"username": username, "email": u["email"],
                             "is_admin": u["is_admin"]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urlparse(self.path)
        if parts.path == "/setup/setupadministrator.action":
            if CONFIG["setupComplete"]:
                self._send(403, {"error": "setup already complete"})
                return
            form = self._form()
            username = form.get("username", "").strip().lower()
            password = form.get("password", "")
            confirm = form.get("confirm", "")
            if not username or not password or password != confirm:
                self._send(400, {"error": "invalid administrator details"})
                return
            if username in USERS:
                self._send(409, {"error": "username exists"})
                return
            USERS[username] = {"password": password,
                               "email": form.get("email", ""),
                               "full_name": form.get("fullName", ""),
                               "is_admin": True}
            self._send(200, {"ok": True, "username": username})
            return
        if parts.path == "/dologin.action":
            form = self._form()
            username = form.get("os_username", "").strip().lower()
            u = USERS.get(username)
            if not u or u["password"] != form.get("os_password", ""):
                self._send(401, {"error": "invalid credentials"})
                return
            token = "tok_%s_%s" % (username, secrets.token_hex(4))
            SESSIONS[token] = username
            self._send(200, {"token": token})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
