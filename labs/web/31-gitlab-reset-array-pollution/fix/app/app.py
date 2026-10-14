import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, unquote

USERS = {
    "user_3101": {"name": "victim", "email": "victim@lab.test", "password": "victim-pw"},
}

SESSIONS = {}
RESETS = {}
INBOX = {}


def uid_of_email(email):
    for uid, u in USERS.items():
        if u["email"] == email:
            return uid
    return None


def deliver(to_addrs, subject, body):
    for addr in to_addrs:
        INBOX.setdefault(addr, []).append({"to": addr, "subject": subject, "body": body})


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab31/1.0"

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
        if parts.path.startswith("/inbox/"):
            email = unquote(parts.path[len("/inbox/"):])
            if not email.endswith("@attacker.lab"):
                self._send(403, {"error": "forbidden"})
                return
            self._send(200, {"messages": INBOX.get(email, [])})
            return
        if parts.path == "/me":
            uid = self._auth()
            if not uid:
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"user_id": uid, "email": USERS[uid]["email"]})
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
            token = "tok_%s_%s" % (uid, secrets.token_hex(4))
            SESSIONS[token] = uid
            self._send(200, {"token": token})
            return
        if parts.path == "/password-reset":
            user = body.get("user")
            email = user.get("email", "") if isinstance(user, dict) else ""
            addrs = email if isinstance(email, list) else [email]
            uid = None
            for addr in addrs:
                uid = uid_of_email(addr)
                if uid:
                    break
            if uid:
                token = "rst_%s" % secrets.token_hex(8)
                RESETS[token] = uid
                link = "http://127.0.0.1:8080/reset/confirm?token=" + token
                deliver(addrs, "Password reset",
                        "Reset your password: " + link)
            self._send(200, {"ok": True})
            return
        if parts.path == "/reset/confirm":
            uid = RESETS.pop(body.get("token", ""), None)
            new_pw = body.get("new_password", "")
            if not uid or not new_pw:
                self._send(400, {"error": "invalid reset"})
                return
            USERS[uid]["password"] = new_pw
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
