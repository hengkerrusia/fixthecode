#!/usr/bin/env python3
"""Mock PayPal business-management API. stdlib only."""

import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

MERCHANTS = {
    "acct_1001": {"name": "Toko Berkah"},
    "acct_1002": {"name": "Victim Corp"},
}

USERS = {
    "alice@tokoberkah.com": {"password": "alicepw", "accounts": ["acct_1001"]},
    "attacker@evil.com": {"password": "attacker_pw", "accounts": ["acct_1001"]},
    "bob@victimcorp.com": {"password": "bobpw", "accounts": ["acct_1002"]},
}

ACCOUNT_USERS = {
    "acct_1001": [{"email": "alice@tokoberkah.com", "role": "owner"},
                  {"email": "attacker@evil.com", "role": "member"}],
    "acct_1002": [{"email": "bob@victimcorp.com", "role": "owner"}],
}

SESSIONS = {}


def is_member(email, account_id):
    return any(u["email"] == email for u in ACCOUNT_USERS.get(account_id, []))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, ctype="application/json"):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return SESSIONS.get(auth[7:], "")
        return ""

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        parts = urlsplit(self.path)
        q = parse_qs(parts.query)
        if parts.path == "/":
            self._send(200, {"service": "demo merchant api"})
        elif parts.path == "/businessmanage/merchants":
            self._send(200, [{"id": k, "name": v["name"]}
                             for k, v in MERCHANTS.items()])
        elif parts.path == "/businessmanage/users":
            email = self._auth()
            if not email:
                self._send(401, {"error": "unauthorized"})
                return
            account_id = q.get("account_id", [""])[0]
            if account_id not in MERCHANTS or not is_member(email, account_id):
                self._send(403, {"error": "forbidden"})
                return
            self._send(200, ACCOUNT_USERS[account_id])
        elif parts.path == "/me":
            email = self._auth()
            if not email:
                self._send(401, {"error": "unauthorized"})
                return
            self._send(200, {"email": email, "accounts": USERS[email]["accounts"]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urlsplit(self.path)
        if parts.path == "/login":
            data = self._body()
            u = USERS.get(data.get("email", ""), {})
            if u and u["password"] == data.get("password", ""):
                tok = "sess_" + secrets.token_hex(8)
                SESSIONS[tok] = data["email"]
                self._send(200, {"token": tok})
            else:
                self._send(401, {"error": "bad credentials"})
            return
        if parts.path == "/businessmanage/users/api/v1/users":
            email = self._auth()
            if not email:
                self._send(401, {"error": "unauthorized"})
                return
            data = self._body()
            account_id = data.get("account_id", "")
            new_email = data.get("email", "")
            role = data.get("role", "member")
            if account_id not in MERCHANTS or not new_email:
                self._send(400, {"error": "bad request"})
                return
            members = ACCOUNT_USERS[account_id]
            for m in members:
                if m["email"] == new_email:
                    m["role"] = role
                    break
            else:
                members.append({"email": new_email, "role": role})
            self._send(201, {"account_id": account_id, "email": new_email,
                             "role": role})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
