#!/usr/bin/env python3
"""Verifier Lab 37: Argo CD CSRF via SameSite site-boundary + no content-type check."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
API_HOST = "argo.lab.local:8080"
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


def req(method, path, body=None, headers=None):
    c = HTTPConnection(HOST, PORT, timeout=10)
    h = dict(headers or {})
    h.setdefault("Host", API_HOST)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else urlencode(body).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    hdrs = r.getheaders()
    try:
        resp = json.loads(raw or b"{}")
    except Exception:
        resp = {}
    status = r.status
    c.close()
    return status, resp, hdrs


def set_cookies(hdrs):
    out = []
    for k, v in hdrs:
        if k.lower() == "set-cookie":
            out.append(v)
    return out


def login():
    s, d, hdrs = req("POST", "/api/v1/session",
                     {"username": "admin", "password": "admin-pw"})
    cookie = ""
    lax = False
    for sc in set_cookies(hdrs):
        if sc.startswith("argocd.token="):
            cookie = sc.split(";", 1)[0]
            lax = "samesite=lax" in sc.lower()
    return s, cookie, lax


def list_apps(cookie):
    s, d, _ = req("GET", "/api/v1/applications",
                  headers={"Cookie": cookie} if cookie else {})
    return s, [a["name"] for a in d.get("items", [])]


def create_app(cookie, name, content_type):
    body = json.dumps({"name": name, "spec": {}}).encode()
    return req("POST", "/api/v1/applications", body,
               {"Cookie": cookie, "Content-Type": content_type})


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


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    app = d.get("APP", "")
    if not app:
        return False, "APP kosong"
    s, cookie, _ = login()
    if s != 200:
        return False, "login oracle gagal"
    s, names = list_apps(cookie)
    if s == 200 and app in names:
        return True, "app '%s' tercipta" % app
    return False, "app '%s' tidak ada di %r" % (app, names)


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    t0 = time.time()
    ready = False
    while time.time() - t0 < 90:
        try:
            s, _, _ = req("GET", "/")
            if s == 200:
                ready = True
                break
        except Exception:
            pass
        time.sleep(2)
    if not ready:
        check("lab siap", False, "timeout")
        return
    s, _, _ = req("GET", "/")
    check("baseline: GET / panel -> 200", s == 200, s)
    s, cookie, lax = login()
    check("baseline: login admin -> cookie sesi", s == 200 and bool(cookie), s)
    check("baseline: cookie memakai SameSite=Lax", lax, "lax" if lax else "tidak")
    s, names = list_apps(cookie)
    check("baseline: GET /api/v1/applications -> 200", s == 200, names)
    s, _, _ = create_app(cookie, "probe-json", "application/json")
    check("baseline: POST create application/json -> 201", s == 201, s)
    s, _, _ = create_app(cookie, "probe-plain", "text/plain")
    check("baseline: POST create text/plain (JSON body) -> 201 [BUG]",
          s == 201, s)
    s, _, hdrs = req("OPTIONS", "/api/v1/applications",
                     headers={"Origin": "http://evil.com"})
    acao = any(k.lower() == "access-control-allow-origin" for k, _ in hdrs)
    check("baseline: OPTIONS tanpa ACAO (preflight gagal)", s == 204 and not acao, s)

    print("== [HEALTH] serangan referensi: sibling-subdomain CSRF -> app jahat ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/APP", ok, got)

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
    check("exploit: app jahat tercipta (oracle /api/v1/applications)", ok, got)


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
    t0 = time.time()
    ready = False
    while time.time() - t0 < 90:
        try:
            s, _, _ = req("GET", "/")
            if s == 200:
                ready = True
                break
        except Exception:
            pass
        time.sleep(2)
    if not ready:
        check("lab siap", False, "timeout")
        return
    s, cookie, _ = login()
    check("fungsi normal: login admin -> 200 + cookie", s == 200 and bool(cookie), s)
    s, _, _ = create_app(cookie, "legit-app", "application/json")
    check("fungsi normal: POST create application/json -> 201", s == 201, s)
    s, names = list_apps(cookie)
    check("fungsi normal: app tercatat di oracle",
          s == 200 and "legit-app" in names, names)
    print("== FASE 2: serangan CSRF terhadap fix ==")
    s, _, _ = create_app(cookie, "evil-plain", "text/plain")
    check("serangan GAGAL: POST text/plain -> 4xx", 400 <= s < 500, s)
    s, _, _ = req("POST", "/api/v1/applications",
                  json.dumps({"name": "evil-none"}).encode(),
                  {"Cookie": cookie})
    check("serangan GAGAL: tanpa content-type JSON -> 4xx", 400 <= s < 500, s)
    s, names = list_apps(cookie)
    check("serangan GAGAL: app jahat tidak tercipta",
          "evil-plain" not in names and "evil-none" not in names, names)
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
