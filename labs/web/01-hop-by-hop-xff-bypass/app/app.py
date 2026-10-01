#!/usr/bin/env python3
"""
app/app.py — Backend aplikasi lab (VULNERABLE BY DESIGN).

Keputusan akses /admin dibuat HANYA berdasarkan header X-Forwarded-For:
request dianggap internal jika XFF ada dan SELURUH IP dalam rantai XFF berada
di TRUSTED_CIDR. Ini meniru pola nyata yang dieksploitasi lewat hop-by-hop
header abuse (Nathan Davison, "Abusing HTTP hop-by-hop request headers"):
ketika XFF di-strip di tengah rantai lalu ditulis ulang oleh hop berikutnya
dengan IP internal-nya sendiri, backend mengira request datang dari dalam.

Endpoint:
  GET /               -> halaman publik (200)
  GET /admin          -> 200 jika rantai XFF seluruhnya internal, 403 jika tidak
  GET /debug/headers  -> 200 JSON berisi header yang diterima backend
                         (alat observasi untuk fase 1)
"""
import ipaddress
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TRUSTED_CIDR = os.environ.get("TRUSTED_CIDR", "10.201.0.0/16")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8000"))
TRUSTED_NET = ipaddress.ip_network(TRUSTED_CIDR)


def xff_is_fully_internal(value):
    """True jika XFF ada dan setiap IP di rantainya masuk TRUSTED_CIDR."""
    if not value:
        return False
    ips = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            return False
        try:
            ips.append(ipaddress.ip_address(part))
        except ValueError:
            return False
    return bool(ips) and all(ip in TRUSTED_NET for ip in ips)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LabApp/1.0"

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "OK - public page\n")
        elif path == "/admin":
            if xff_is_fully_internal(self.headers.get("X-Forwarded-For")):
                self._send(200, "Welcome to the admin panel (internal access granted)\n")
            else:
                self._send(403, "Forbidden: admin access requires internal network\n")
        elif path == "/debug/headers":
            echo = {k: v for k, v in self.headers.items()}
            echo["__peer"] = self.client_address[0]
            self._send(200, json.dumps(echo, indent=2) + "\n", "application/json")
        else:
            self._send(404, "Not found\n")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print("[app] listening on 0.0.0.0:%d (TRUSTED_CIDR=%s)"
          % (LISTEN_PORT, TRUSTED_CIDR), flush=True)
    srv.serve_forever()
