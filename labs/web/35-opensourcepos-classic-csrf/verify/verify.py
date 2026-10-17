#!/usr/bin/env python3
"""Verifier Lab 35: OpenSourcePOS classic CSRF -> rogue admin -> takeover."""

import json
import os
import secrets
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ADMIN = ("admin", "admin-pw")


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


def req(method, path, body=None, cookie=None, headers=None, form=False):
    c = HTTPConnection(HOST, PORT, timeout=10)
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = "session=" + cookie
    data = None
    if body is not None:
        if form:
            data = urlencode(body).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    try:
        resp = json.loads(raw or b"{}")
    except Exception:
        resp = {}
    set_cookie = r.getheader("Set-Cookie", "")
    c.close()
    return r.status, resp, set_cookie


def sid_of(set_cookie):
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            return part[len("session="):]
    return ""


def wait_ready(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s, _, _ = req("GET", "/")
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def login(username, password):
    s, d, raw = req("POST", "/login",
                    {"username": username, "password": password}, form=True)
    if s != 200:
        return "", {}
    return sid_of(raw), d


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


def admin_token_ok(admin_token):
    if not admin_token:
        return False, "token kosong"
    s, d, _ = req("GET", "/me", cookie=admin_token)
    if s == 200 and d.get("is_admin") is True:
        return True, "sesi admin (%s)" % d.get("username")
    return False, "s=%r me=%r" % (s, d)


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    return admin_token_ok(d.get("ADMIN_TOKEN", ""))


def forged_create(victim_cookie, username):
    return req("POST", "/users",
               {"username": username, "password": "pw-" + username,
                "is_admin": "1", "full_name": "Forged"},
               cookie=victim_cookie, form=True)


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    s, _, _ = req("GET", "/")
    check("baseline: GET / panel -> 200", s == 200, s)
    sid, _ = login("admin", "salah")
    check("baseline: login password salah -> 401", sid == "", repr(sid))
    victim, _ = login(*ADMIN)
    check("baseline: login admin bawaan -> cookie sesi", bool(victim),
          "sesi" if victim else "gagal")
    s, d, _ = req("GET", "/me", cookie=victim)
    check("baseline: /me -> is_admin true",
          s == 200 and d.get("is_admin") is True, d.get("username"))
    s, _, _ = req("POST", "/users",
                  {"username": "anon", "password": "x", "is_admin": "1"},
                  form=True)
    check("baseline: POST /users tanpa sesi -> 401", s == 401, s)
    s, d, _ = req("GET", "/users", cookie=victim)
    names = [u["username"] for u in d.get("users", [])]
    check("baseline: GET /users admin -> daftar user", s == 200 and "admin" in names, names)

    print("== [HEALTH] serangan referensi: CSRF tempaan -> admin baru ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/ADMIN_TOKEN", ok, got)

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
    check("exploit: admin takeover terbukti via oracle (/me is_admin)", ok, got)


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
    victim, info = login(*ADMIN)
    check("fungsi normal: login admin -> 200 + sesi", bool(victim),
          "sesi" if victim else "gagal")
    evil = "evil" + secrets.token_hex(3)
    s, d, _ = forged_create(victim, evil)
    check("serangan GAGAL: POST /users tempaan tanpa token -> 403", s == 403, s)
    s, d, _ = req("GET", "/users", cookie=victim)
    names = [u["username"] for u in d.get("users", [])]
    check("serangan GAGAL: akun tempaan tidak tercipta", evil not in names, names)
    s, _, _ = req("POST", "/users",
                  {"username": "evil2", "password": "x", "is_admin": "1",
                   "csrf_token": "salah"},
                  cookie=victim, form=True)
    check("serangan GAGAL: token CSRF salah -> 403", s == 403, s)
    csrf = info.get("csrf_token", "")
    legit = "legit" + secrets.token_hex(3)
    s, d, _ = req("POST", "/users",
                  {"username": legit, "password": "pw-" + legit,
                   "is_admin": "1", "csrf_token": csrf},
                  cookie=victim, form=True)
    check("fungsi normal: POST /users dengan token valid -> 200",
          s == 200 and d.get("username") == legit, s)
    sid2, _ = login(legit, "pw-" + legit)
    s, d, _ = req("GET", "/me", cookie=sid2)
    check("fungsi normal: admin baru bisa login, /me is_admin",
          s == 200 and d.get("is_admin") is True, d.get("username"))
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
