#!/usr/bin/env python3
"""Verifier Lab 36: fastapi-users login CSRF -> OAuth account linking -> ATO."""

import json
import os
import secrets
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode, urlparse

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
ATTACKER_SSO = "attacker@evil.test"
passed, failed = 0, 0


def check(name, cond, got=""):
    global passed, failed
    if cond:
        passed += 1
        print("  [LULUS] %s -- dapat %s" % (name, got))
    else:
        failed += 1
        print("  [GAGAL] %s -- dapat %s" % (name, got))


def sh(cmd):
    return subprocess.run(cmd, cwd=LAB, capture_output=True, text=True, timeout=300)


class Jar:
    def __init__(self):
        self.cookies = {}

    def req(self, method, url, body=None):
        p = urlparse(url)
        path = p.path + ("?" + p.query if p.query else "")
        c = HTTPConnection(p.hostname or HOST, p.port or PORT, timeout=10)
        h = {}
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        data = None
        if body is not None:
            data = urlencode(body).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name = v.split(";", 1)[0]
                if "=" in name:
                    n, val = name.split("=", 1)
                    self.cookies[n.strip()] = val.strip()
        try:
            resp = json.loads(raw or b"{}")
        except Exception:
            resp = {}
        loc, status = r.getheader("Location", ""), r.status
        c.close()
        return status, resp, loc

    def get(self, path):
        return self.req("GET", "http://%s:%d%s" % (HOST, PORT, path))

    def post(self, path, form):
        return self.req("POST", "http://%s:%d%s" % (HOST, PORT, path), form)


def wait_ready(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s, _, _ = Jar().get("/")
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def parse_contract(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def run_exploit(path):
    p = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def sso_login_as_attacker():
    """Replay independen: login SSO sebagai attacker dari sesi bersih."""
    j = Jar()
    s, _, _ = j.get("/provider/login?as=attacker")
    if s != 200:
        return None
    s, d, _ = j.get("/oauth/authorize")
    if s != 200 or not d.get("authorization_url"):
        return None
    s, _, location = j.req("GET", d["authorization_url"])
    if s != 302 or "/oauth/callback" not in location:
        return None
    s, _, _ = j.req("GET", location)
    if s != 200:
        return None
    s, d, _ = j.get("/me")
    if s != 200:
        return None
    return d


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    victim = d.get("VICTIM", "")
    token = d.get("ATO_TOKEN", "")
    if not victim or not token:
        return False, "VICTIM/ATO_TOKEN kosong"
    j = Jar()
    j.cookies["session"] = token
    s, me, _ = j.get("/me")
    if not (s == 200 and me.get("username") == victim):
        return False, "token tidak valid utk victim s=%r me=%r" % (s, me)
    if me.get("sso") != ATTACKER_SSO:
        return False, "akun tidak ter-link ke SSO penyerang: %r" % me
    replay = sso_login_as_attacker()
    if not replay or replay.get("username") != victim:
        return False, "replay SSO independen gagal: %r" % replay
    return True, "sesi korban (%s), replay SSO independen OK" % victim


def fresh_callback_url(jar, who="attacker"):
    """Authorize + provider leg -> URL callback segar (satu pakai)."""
    s, _, _ = jar.get("/provider/login?as=" + who)
    if s != 200:
        return ""
    s, d, _ = jar.get("/oauth/authorize")
    if s != 200 or not d.get("authorization_url"):
        return ""
    s, _, location = jar.req("GET", d["authorization_url"])
    if s != 302 or "/oauth/callback" not in location:
        return ""
    return location


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    j = Jar()
    s, _, _ = j.get("/")
    check("baseline: GET / panel -> 200", s == 200, s)
    s, _, _ = j.post("/register", {"username": "baseline", "password": "baseline-pw"})
    check("baseline: register -> 200", s == 200, s)
    s, _, _ = j.post("/login", {"username": "baseline", "password": "baseline-pw"})
    check("baseline: login -> cookie sesi", s == 200 and bool(j.cookies.get("session")), s)
    s, d, _ = j.get("/me")
    check("baseline: /me -> baseline", s == 200 and d.get("username") == "baseline",
          d.get("username"))
    s, d, _ = j.get("/oauth/authorize")
    check("baseline: /oauth/authorize -> authorization_url + state",
          s == 200 and "state=" in d.get("authorization_url", ""), s)
    p = Jar()
    s, _, _ = p.get("/provider/login?as=attacker")
    check("baseline: provider login attacker -> psession",
          s == 200 and bool(p.cookies.get("psession")), s)

    print("== [HEALTH] serangan referensi: login CSRF -> linking -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/VICTIM/ATO_TOKEN", ok, got)

    print("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    p = os.path.join(LAB, "exploit", "exploit.py")
    try:
        src = open(p).read()
    except FileNotFoundError:
        src = ""
    if "NotImplementedError" in src:
        check("exploit: sudah dikerjakan (bukan scaffold)", False, "masih scaffold")
        return
    rc, out, err = run_exploit(p)
    d = parse_contract(out)
    check("exploit: STATUS 200", d.get("STATUS") == "200", repr(d.get("STATUS")))
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: ATO terbukti (oracle + replay SSO independen)", ok, got)


def fase2():
    print("== FASE 2: cek scaffold fix ==")
    pristine = open(os.path.join(LAB, "app", "app.py"), "rb").read()
    fixed = open(os.path.join(LAB, "fix", "app", "app.py"), "rb").read()
    check("fix: fix/app/app.py sudah diubah (tidak identik pristine)",
          pristine != fixed, "identik" if pristine == fixed else "berbeda")
    if pristine == fixed:
        return
    print("== FASE 2: membangun lab dengan FIX ==")
    sh(["docker", "compose", "-f", "docker-compose.yml",
        "-f", "docker-compose.fix.yml", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    j = Jar()
    s, _, _ = j.post("/register", {"username": "legit", "password": "legit-pw"})
    s, _, _ = j.post("/login", {"username": "legit", "password": "legit-pw"})
    check("fungsi normal: register+login -> sesi", s == 200 and bool(j.cookies.get("session")), s)

    sso = Jar()
    cb = fresh_callback_url(sso, "victim")
    if cb:
        s, d, _ = sso.req("GET", cb)
    else:
        s, d = -1, {}
    check("fungsi normal: alur SSO lengkap -> 200 + sesi",
          s == 200 and bool(sso.cookies.get("session")), (s, d.get("username")))
    s, d, _ = sso.get("/me")
    check("fungsi normal: /me user SSO baru",
          s == 200 and d.get("username") == "victim" and d.get("sso") == "victim@mail.test",
          d.get("username"))

    print("== FASE 2: serangan login CSRF terhadap fix ==")
    atk = Jar()
    cb = fresh_callback_url(atk)
    korban = Jar()
    korban.cookies["session"] = "sess_" + secrets.token_hex(8)
    if cb:
        s, d, _ = korban.req("GET", cb)
    else:
        s, d = -1, {}
    check("serangan GAGAL: callback CSRF tanpa cookie pengikat -> 400",
          s == 400, (s, d.get("error")))
    atk2 = Jar()
    cb2 = fresh_callback_url(atk2)
    korban2 = Jar()
    korban2.cookies["session"] = "sess_" + secrets.token_hex(8)
    korban2.cookies["oauth_csrf"] = "salah"
    if cb2:
        s, d, _ = korban2.req("GET", cb2)
    else:
        s, d = -1, {}
    check("serangan GAGAL: callback dengan cookie pengikat salah -> 400",
          s == 400, (s, d.get("error")))

    print("== FASE 2: menjalankan serangan referensi terhadap fix ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, _ = contract_ok(d)
    check("serangan referensi GAGAL total (tidak ada kontrak valid)",
          rc != 0 or not ok, "rc=%d" % rc)


if __name__ == "__main__":
    fase1()
    fase2()
    print("== HASIL: %d/%d cek lulus ==" % (passed, passed + failed))
    sh(["docker", "compose", "down"])
    sys.exit(0 if failed == 0 else 1)
