import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

USERS = {
    1: {"email": "victim@lab.test", "password": "victim-pw",
        "name": "Victim User", "is_admin": False},
    2: {"email": "admin@lab.test", "password": "admin-pw",
        "name": "Admin User", "is_admin": True},
    100: {"email": "attacker@lab.test", "password": "attacker-pw",
          "name": "Attacker User", "is_admin": False},
}

SESSIONS = {}


def uid_of_email(email):
    for uid, u in USERS.items():
        if u["email"] == email:
            return uid
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab33/1.0"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        raw = self.rfile.read(n) if n else b""
        ctype = self.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in ctype:
            return {k: v[0] for k, v in parse_qs(raw.decode()).items()}
        try:
            return json.loads(raw.decode()) if raw else {}
        except (ValueError, UnicodeDecodeError):
            return {}

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return SESSIONS.get(auth[7:])
        return None

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/me":
            uid = self._auth()
            if not uid:
                self._send(401, {"error": "unauthorized"})
                return
            u = USERS[uid]
            self._send(200, {"user_id": uid, "email": u["email"],
                             "is_admin": u["is_admin"]})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urlparse(self.path)
        body = self._body()
        if parts.path == "/login":
            uid = uid_of_email(body.get("email", ""))
            if not uid or USERS[uid]["password"] != body.get("password", ""):
                self._send(401, {"error": "invalid credentials"})
                return
            token = "tok_%d_%s" % (uid, secrets.token_hex(4))
            SESSIONS[token] = uid
            self._send(200, {"token": token})
            return
        self._send(404, {"error": "not found"})

    def do_PUT(self):
        parts = urlparse(self.path)
        segs = parts.path.strip("/").split("/")
        if len(segs) == 5 and segs[:4] == ["admin", "settings", "users", "edit"]:
            me = self._auth()
            if not me:
                self._send(401, {"error": "unauthorized"})
                return
            try:
                uid = int(segs[4])
            except ValueError:
                uid = None
            target = USERS.get(uid)
            if target is None:
                self._send(404, {"error": "not found"})
                return
            caller = USERS[me]
            if not caller["is_admin"] and target["is_admin"]:
                self._send(403, {"error": "forbidden"})
                return
            body = self._body()
            new_pw = body.get("password", "")
            if not new_pw:
                self._send(400, {"error": "password required"})
                return
            target["password"] = new_pw
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
