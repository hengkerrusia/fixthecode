#!/usr/bin/env python3
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

INDEX_HTML = """<!DOCTYPE html>
<html><head><title>Shortlink</title></head>
<body>
<h1>Shortlink Service</h1>
<p>Legacy short links live under <code>/r/&lt;name&gt;</code>.</p>
<p><a href="/login">Login</a> for your dashboard.</p>
</body></html>"""

DASH_HTML = """<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
<h1>Dashboard</h1>
<p>Welcome back. Your shared files are listed under <code>/files/</code>.</p>
</body></html>"""

FILES_HTML = """<!DOCTYPE html>
<html><head><title>Files</title></head>
<body>
<h1>Shared files</h1>
<p>Nothing shared with you yet.</p>
</body></html>"""

sessions = {}


class Handler(BaseHTTPRequestHandler):
    server_version = "Shortlink/1.0"

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
        path = u.path
        if path == "/":
            self._send(200, INDEX_HTML)
        elif path == "/login":
            stok = "sess-" + os.urandom(8).hex()
            sessions[stok] = True
            self._send(200, "<html><body>logged in</body></html>",
                       extra=[("Set-Cookie", "session=%s; Path=/" % stok)])
        elif path == "/dashboard":
            if not self._session():
                return self._send(401, "login required", "text/plain")
            self._send(200, DASH_HTML)
        elif path.startswith("/r/"):
            target = "/files/" + unquote(path[len("/r/"):])
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/files/"):
            self._send(200, FILES_HTML)
        else:
            self._send(404, "not found", "text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
