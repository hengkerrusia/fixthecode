#!/usr/bin/env python3
"""Verifier Lab 34: Confluence BFLA -> setup chain -> admin takeover."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ADMIN = ("admin", "admin-pw")
SETUP_FLAG = "bootstrapStatusProvider.applicationConfig.setupComplete"


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


def req(method, path, body=None, token=None, form=False):
    c = HTTPConnection(HOST, PORT, timeout=10)
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
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
    c.close()
    return r.status, resp


def wait_ready(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s, _ = req("GET", "/server-info.action")
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def dologin(username, password):
    s, d = req("POST", "/dologin.action",
               {"os_username": username, "os_password": password}, form=True)
    return d.get("token", "") if s == 200 else ""


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
    s, d = req("GET", "/me", token=admin_token)
    if s == 200 and d.get("is_admin") is True:
        return True, "sesi admin (%s)" % d.get("username")
    return False, "s=%r me=%r" % (s, d)


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    return admin_token_ok(d.get("ADMIN_TOKEN", ""))


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    s, d = req("GET", "/server-info.action")
    check("baseline: /server-info.action -> 200, setupComplete true",
          s == 200 and d.get("setupComplete") is True, d.get("setupComplete"))
    s, d = req("GET", "/setup/setupadministrator-start.action")
    check("baseline: setup wizard -> 403 (setup sudah selesai)", s == 403, s)
    s, d = req("POST", "/setup/setupadministrator.action",
               {"username": "x", "fullName": "x", "email": "x@x",
                "password": "x", "confirm": "x"}, form=True)
    check("baseline: buat admin via setup -> 403", s == 403, s)
    tok = dologin(*ADMIN)
    check("baseline: dologin admin bawaan -> token", bool(tok),
          "token" if tok else "gagal")
    s, d = req("GET", "/me", token=tok)
    check("baseline: /me -> is_admin true",
          s == 200 and d.get("is_admin") is True, d.get("username"))

    print("== [HEALTH] serangan referensi: rantai setup -> admin baru ==")
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
    s, d = req("GET", "/server-info.action?" + SETUP_FLAG + "=0")
    check("serangan GAGAL: setupComplete tidak bisa di-flip",
          s == 200 and d.get("setupComplete") is True, d.get("setupComplete"))
    s, d = req("GET", "/setup/setupadministrator-start.action")
    check("serangan GAGAL: setup wizard tetap 403", s == 403, s)
    s, d = req("POST", "/setup/setupadministrator.action",
               {"username": "evil", "fullName": "Evil", "email": "e@e",
                "password": "evilpw", "confirm": "evilpw"}, form=True)
    check("serangan GAGAL: buat admin via setup -> 403", s == 403, s)
    s, d = req("GET", "/server-info.action")
    check("fungsi normal: /server-info.action -> 200 setupComplete true",
          s == 200 and d.get("setupComplete") is True, s)
    tok = dologin(*ADMIN)
    check("fungsi normal: dologin admin bawaan -> token", bool(tok),
          "token" if tok else "gagal")
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
