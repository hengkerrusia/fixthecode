import base64
import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

USERS = {
    "dev": {"password": "dev-pw", "full_name": "Developer"},
}

SESSIONS = {}
EMAILS = []
NEXT_ID = [1]
CLIENTS = []
CLOCK = threading.Lock()

PANEL = """<!doctype html>
<html><head><meta charset="utf-8"><title>Mailpit</title></head>
<body>
<h1>Developer Login</h1>
<form method="post" action="/login">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button type="submit">Login</button>
</form>
</body></html>"""


def ws_accept(key):
    return base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_frame(payload):
    if isinstance(payload, str):
        payload = payload.encode()
    head = bytes([0x81])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + n.to_bytes(2, "big")
    else:
        head += bytes([127]) + n.to_bytes(8, "big")
    return head + payload


def ws_read_frame(rfile):
    head = rfile.read(2)
    if len(head) < 2:
        return None, None
    b1, b2 = head[0], head[1]
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    ln = b2 & 0x7F
    if ln == 126:
        ln = int.from_bytes(rfile.read(2), "big")
    elif ln == 127:
        ln = int.from_bytes(rfile.read(8), "big")
    mask = rfile.read(4) if masked else b""
    payload = rfile.read(ln) if ln else b""
    if masked and mask:
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return opcode, payload


def broadcast(obj):
    data = ws_frame(json.dumps(obj))
    dead = []
    with CLOCK:
        targets = list(CLIENTS)
    for c in targets:
        try:
            with c["lock"]:
                c["wfile"].write(data)
                c["wfile"].flush()
        except Exception:
            dead.append(c)
    if dead:
        with CLOCK:
            for c in dead:
                if c in CLIENTS:
                    CLIENTS.remove(c)


class Handler(BaseHTTPRequestHandler):
    server_version = "Lab40/1.0"
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", "session=" + cookie + "; Path=/")
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

    def log_message(self, *args):
        pass

    def _handle_ws(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        if (self.headers.get("Upgrade", "").lower() != "websocket" or not key):
            self._send(400, {"error": "not a websocket handshake"})
            return
        user, _ = self._session()
        if not user:
            self._send(401, {"error": "unauthorized"})
            return
        client = {"wfile": self.wfile, "lock": threading.Lock()}
        with CLOCK:
            CLIENTS.append(client)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self.wfile.flush()
        try:
            while True:
                opcode, payload = ws_read_frame(self.rfile)
                if opcode is None:
                    break
                if opcode == 0x8:
                    try:
                        self.wfile.write(ws_frame(b""))
                        self.wfile.flush()
                    except Exception:
                        pass
                    break
                if opcode == 0x9:
                    try:
                        self.wfile.write(bytes([0x8A, len(payload)]) + payload)
                        self.wfile.flush()
                    except Exception:
                        break
        except Exception:
            pass
        finally:
            with CLOCK:
                if client in CLIENTS:
                    CLIENTS.remove(client)
            self.close_connection = True

    def do_GET(self):
        parts = urlparse(self.path)
        if parts.path == "/":
            self._send_html(200, PANEL)
            return
        if parts.path == "/ws":
            self._handle_ws()
            return
        user, _ = self._session()
        if not user:
            self._send(401, {"error": "unauthorized"})
            return
        if parts.path == "/me":
            self._send(200, {"username": user,
                             "full_name": USERS[user]["full_name"]})
            return
        if parts.path == "/api/events":
            self._send(200, {"emails": EMAILS})
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
            SESSIONS[sid] = (username, None)
            self._send(200, {"ok": True}, cookie=sid)
            return
        user, _ = self._session()
        if not user:
            self._send(401, {"error": "unauthorized"})
            return
        if parts.path == "/api/send-test":
            form = self._form()
            with CLOCK:
                nid = NEXT_ID[0]
                NEXT_ID[0] += 1
                mail = {"id": nid,
                        "from": form.get("from", "billing@shop.example"),
                        "to": form.get("to", "dev@localhost"),
                        "subject": form.get("subject", "test message"),
                        "snippet": form.get("snippet", "hello world")}
                EMAILS.append(mail)
            broadcast({"type": "email", "id": mail["id"],
                       "from": mail["from"], "subject": mail["subject"],
                       "snippet": mail["snippet"]})
            self._send(200, {"ok": True, "id": nid})
            return
        self._send(404, {"error": "not found"})


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    srv.daemon_threads = True
    srv.serve_forever()
