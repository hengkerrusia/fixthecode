#!/usr/bin/env python3
import html
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"demo": "demo123"}
SESSIONS = {}

ENGINE = """<script>
(function () {
  function ev(x) {
    try { return Function("s", "with(s){return (" + x + ")}")({}); }
    catch (e) { return ""; }
  }
  function interp(t) {
    return t.replace(/\\{\\{([\\s\\S]*?)\\}\\}/g, function (m, e) {
      var v = ev(e);
      return v == null ? "" : String(v);
    });
  }
  function walk(n) {
    if (n.nodeType === 3) {
      if (n.nodeValue && n.nodeValue.indexOf("{{") >= 0) n.nodeValue = interp(n.nodeValue);
      return;
    }
    if (n.nodeType !== 1) return;
    for (var i = 0; i < n.attributes.length; i++) {
      var a = n.attributes[i];
      if (a.value.indexOf("{{") >= 0) a.value = interp(a.value);
    }
    for (var c = n.firstChild; c; c = c.nextSibling) walk(c);
  }
  document.addEventListener("DOMContentLoaded", function () { walk(document.body); });
})();
</script>"""


def shell_page(target):
    reflected = html.escape(target, quote=True)
    return f"""<!DOCTYPE html>
<html lang="id">
<head><meta charset="utf-8"><title>Pantau — Dasbor Pemantauan</title></head>
<body>
<header class="topbar">
  <span class="brand">Pantau</span>
  <nav>
    <a href="/">Ikhtisar</a>
    <a href="/dash">Dasbor</a>
    <a href="/explore">Jelajah</a>
    <a class="nav-login" href="/login?redirectTo={reflected}">Masuk</a>
  </nav>
</header>
<main>
  <h1>Pemantauan layanan</h1>
  <p>Selamat datang di Pantau. Masuk untuk melihat dasbor, panel, dan
  peringatan layanan Anda.</p>
  <section class="panels">
    <div class="panel"><h2>API publik</h2><p>Operasional — 99,98% dalam 30 hari.</p></div>
    <div class="panel"><h2>Gerbang pembayaran</h2><p>Operasional — 99,95% dalam 30 hari.</p></div>
    <div class="panel"><h2>Antrean pekerja</h2><p>Menurun — antrean di atas ambang wajar.</p></div>
  </section>
</main>
{ENGINE}
</body>
</html>"""


def login_page(redirect_to, error=""):
    rt = html.escape(redirect_to, quote=True)
    err = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="id">
<head><meta charset="utf-8"><title>Masuk — Pantau</title></head>
<body>
<main>
  <h1>Masuk ke Pantau</h1>
  {err}
  <form method="post" action="/login">
    <input type="hidden" name="redirectTo" value="{rt}">
    <label>Nama pengguna <input name="username" autocomplete="username"></label>
    <label>Kata sandi <input name="password" type="password" autocomplete="current-password"></label>
    <button type="submit">Masuk</button>
  </form>
</main>
</body>
</html>"""


def dashboard_page(user):
    return f"""<!DOCTYPE html>
<html lang="id">
<head><meta charset="utf-8"><title>Dasbor — Pantau</title></head>
<body>
<header class="topbar">
  <span class="brand">Pantau</span>
  <nav>
    <a href="/">Ikhtisar</a>
    <a href="/dash">Dasbor</a>
    <a href="/explore">Jelajah</a>
    <a class="nav-logout" href="/logout">Keluar ({html.escape(user)})</a>
  </nav>
</header>
<main>
  <h1>Dasbor utama</h1>
  <section class="panels">
    <div class="panel"><h2>CPU</h2><p>41%</p></div>
    <div class="panel"><h2>Memori</h2><p>63%</p></div>
    <div class="panel"><h2>Permintaan/dtk</h2><p>1.284</p></div>
    <div class="panel"><h2>Galat 5xx</h2><p>0,02%</p></div>
  </section>
</main>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _session_user(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("sess="):
                return SESSIONS.get(part[5:])
        return None

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/healthz":
            self._send(200, "ok", "text/plain; charset=utf-8")
            return
        if parsed.path == "/logout":
            user = self._session_user()
            if user:
                for tok in [t for t, u in SESSIONS.items() if u == user]:
                    del SESSIONS[tok]
            self._send(302, "", headers={
                "Location": "/",
                "Set-Cookie": "sess=; HttpOnly; Path=/; Max-Age=0"})
            return
        if parsed.path == "/login":
            qs = urllib.parse.parse_qs(parsed.query)
            rt = qs.get("redirectTo", ["/"])[0]
            self._send(200, login_page(rt))
            return
        if self._session_user():
            self._send(200, dashboard_page(self._session_user()))
            return
        self._send(200, shell_page(urllib.parse.unquote(self.path)))

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/login":
            self._send(404, "tidak ditemukan", "text/plain; charset=utf-8")
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        user = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        rt = form.get("redirectTo", ["/"])[0]
        if USERS.get(user) != password or not user:
            self._send(200, login_page(rt, "Nama pengguna atau kata sandi salah."))
            return
        token = secrets.token_hex(16)
        SESSIONS[token] = user
        if not rt.startswith("/") or rt.startswith("//"):
            rt = "/"
        self._send(302, "", headers={
            "Location": rt,
            "Set-Cookie": f"sess={token}; HttpOnly; Path=/"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
