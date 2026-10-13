#!/usr/bin/env python3
"""Mock OAuth proxy (ala Expo AuthSession) + mock IdP. stdlib only."""

import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs, urlparse

APP_HOST = "app.demo"
AUTH_CODE = "authcode123"
ISSUED = set()


def redirect_allowed(url):
    if url.startswith("https://"):
        return urlsplit(url).netloc == APP_HOST
    if url.startswith("http://"):
        return False
    return True


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(self, loc, extra=None):
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return ""

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            self._send(200, b"<h1>Demo OAuth Proxy</h1><p>Mulai: /start?returnUrl=...</p>")
        elif u.path == "/start":
            ru = q.get("returnUrl", [""])[0]
            self._redirect("/idp?client_id=demoapp",
                           {"Set-Cookie": "ru=%s; Path=/; HttpOnly" % ru})
        elif u.path == "/idp":
            body = (b"<h1>Fake IdP</h1><p>DemoApp meminta akses akunmu.</p>"
                    b'<form method="POST" action="/idp/approve">'
                    b'<button type="submit">Approve</button></form>')
            self._send(200, body)
        elif u.path == "/callback":
            if q.get("code", [""])[0] != AUTH_CODE:
                self._send(400, b"bad code")
                return
            ru = self._cookie("ru")
            if not ru or not redirect_allowed(ru):
                self._send(400, b"bad returnUrl")
                return
            tok = "tok_" + secrets.token_hex(4)
            ISSUED.add(tok)
            self._redirect("%s#access_token=%s" % (ru, tok))
        elif u.path == "/me":
            tok = q.get("access_token", [""])[0]
            if tok in ISSUED:
                self._send(200, json.dumps({"account": "victim@demo"}).encode(),
                           "application/json")
            else:
                self._send(401, b"unauthorized")
        else:
            self._send(404, b"not found")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/idp/approve":
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self._redirect("/callback?code=" + AUTH_CODE)
        else:
            self._send(404, b"not found")


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
