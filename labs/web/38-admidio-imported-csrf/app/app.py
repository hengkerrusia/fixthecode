import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

USERS = {
    "manager": {"password": "manager-pw", "full_name": "Inventory Manager"},
}

SESSIONS = {}
ITEMS = {}
NEXT_ID = [1]

CATEGORIES = ["electronics", "furniture", "stationery"]

PANEL = """<!doctype html>
<html><head><meta charset="utf-8"><title>Inventory</title></head>
<body>
<h1>Inventory Login</h1>
<form method="post" action="/login">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Login</button>
</form>
</body></html>"""

NEW_FORM = """<!doctype html>
<html><head><meta charset="utf-8"><title>New item</title></head>
<body>
<h1>New inventory item</h1>
<form method="post" action="/inventory/item_save">
<input type="hidden" name="csrf_token" value="__CSRF__">
<input name="name" placeholder="item name">
<input name="category" placeholder="category">
<input name="quantity" placeholder="quantity">
<button type="submit">Save</button>
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab38/1.0"

    def _send(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "session=" + cookie + "; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code, html):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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

    def _session(self):
        cookie = self.headers.get("Cookie", "")
        sid = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                sid = part[len("session="):]
                break
        return SESSIONS.get(sid, (None, None))

    def _valid(self, name, category, quantity):
        if not name or len(name) > 100:
            return False
        if category not in CATEGORIES:
            return False
        try:
            q = int(quantity)
        except (TypeError, ValueError):
            return False
        return q >= 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/":
            self._send_html(200, PANEL)
            return
        user, csrf = self._session()
        if not user:
            self._send(401, {"error": "unauthorized"})
            return
        if parts.path == "/me":
            self._send(200, {"username": user,
                             "full_name": USERS[user]["full_name"]})
            return
        if parts.path == "/inventory":
            self._send(200, {"items": list(ITEMS.values())})
            return
        if parts.path == "/inventory/new":
            self._send_html(200, NEW_FORM.replace("__CSRF__", csrf))
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = urlparse(self.path)
        if parts.path == "/login":
            form = self._form()
            username = form.get("username", "").strip().lower()
            u = USERS.get(username)
            if not u or u["password"] != form.get("password", ""):
                self._send(401, {"error": "invalid credentials"})
                return
            sid = "sess_" + secrets.token_hex(8)
            csrf = "csrf_" + secrets.token_hex(16)
            SESSIONS[sid] = (username, csrf)
            self._send(200, {"ok": True, "csrf_token": csrf}, cookie=sid)
            return
        if parts.path == "/inventory/item_save":
            user, csrf = self._session()
            if not user:
                self._send(401, {"error": "unauthorized"})
                return
            form = self._form()
            imported = form.get("imported", "") in ("1", "true", "True")
            if imported:
                name = form.get("name", "")
                category = form.get("category", "")
                quantity = form.get("quantity", "")
            else:
                if form.get("csrf_token", "") != csrf:
                    self._send(403, {"error": "bad csrf token"})
                    return
                name = form.get("name", "")
                category = form.get("category", "")
                quantity = form.get("quantity", "")
                if not self._valid(name, category, quantity):
                    self._send(400, {"error": "invalid fields"})
                    return
                quantity = int(quantity)
            nid = NEXT_ID[0]
            NEXT_ID[0] += 1
            ITEMS[nid] = {"id": nid, "name": name,
                          "category": category, "quantity": quantity}
            self._send(200, {"ok": True, "id": nid})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
