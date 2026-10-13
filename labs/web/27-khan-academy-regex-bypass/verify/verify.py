#!/usr/bin/env python3
"""Verifier Lab 27: regex bypass -> 1-click ATO. stdlib only."""

import os
import re
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlparse, parse_qs, urlencode

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

VULN_RE = re.compile(
    r"(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$")
FIXED_RE = re.compile(
    r"(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc\.a\.run\.app)$")


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


def req(method, path, headers=None, body=None):
    c = HTTPConnection(HOST, PORT, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    raw = r.getheaders()
    c.close()
    return r.status, raw, data


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


def login(continue_url):
    body = urlencode({"username": "victim", "password": "x",
                      "continue": continue_url}).encode()
    s, h, _ = req("POST", "/login", body=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    return s, dict(h).get("Location", "")


def parse_contract(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def contract_ok(d):
    if d.get("STATUS") != "302":
        return False, "STATUS=%r" % d.get("STATUS")
    loc = d.get("LOCATION", "")
    u = urlparse(loc)
    if u.path != "/transfer_auth":
        return False, "bukan /transfer_auth"
    host = u.netloc.split(":")[0].lower()
    if not (VULN_RE.search(host) and not FIXED_RE.search(host)):
        return False, "host tidak menunjukkan bypass regex"
    tok = parse_qs(u.query).get("key", [""])[0]
    if not tok or d.get("TOKEN") != tok:
        return False, "TOKEN tidak cocok"
    if d.get("ACCOUNT") != "victim@khan.demo":
        return False, "ACCOUNT=%r" % d.get("ACCOUNT")
    return True, "TOKEN=%s ACCOUNT=victim@khan.demo" % tok


def run_exploit(path):
    p = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    s, _, _ = req("GET", "/")
    check("baseline: GET / -> 200", s == 200, s)
    s, _, data = req("GET", "/login?continue=" + "https://www.khanacademy.org/")
    check("baseline: GET /login -> 200 + form",
          s == 200 and b"<form" in data, s)
    s, loc = login("https://www.khanacademy.org/")
    check("baseline: login continue legitimate -> 302 + token",
          s == 302 and "/transfer_auth?key=tok_" in loc, loc[:60])
    tok = parse_qs(urlparse(loc).query).get("key", [""])[0]
    s, h, _ = req("GET", "/transfer_auth?key=" + tok)
    cookies = [v for k, v in h if k.lower() == "set-cookie"]
    check("baseline: replay token -> 200 + 3 cookie sesi",
          s == 200 and len(cookies) == 3, "%d cookie" % len(cookies))
    s, _, data = req("GET", "/me",
                     headers={"Cookie": "; ".join(v.split(";")[0] for v in cookies)})
    check("baseline: /me -> victim@khan.demo",
          s == 200 and b"victim@khan.demo" in data, s)
    s, _ = login("https://evil.com/")
    check("baseline: continue https://evil.com/ -> 400", s == 400, s)

    print("== [HEALTH] serangan referensi: regex bypass -> token -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/LOCATION/TOKEN/ACCOUNT", ok, got)

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
    check("exploit: STATUS 302", d.get("STATUS") == "302", repr(d.get("STATUS")))
    loc = d.get("LOCATION", "")
    u = urlparse(loc)
    host = u.netloc.split(":")[0].lower()
    check("exploit: LOCATION host lolos regex rentan tapi bukan bentuk legitimate",
          bool(VULN_RE.search(host) and not FIXED_RE.search(host)), host)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: TOKEN cocok & ACCOUNT == victim@khan.demo (ATO)", ok, got)


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
    s, loc = login("https://www.khanacademy.org/")
    check("fungsi normal: login legitimate tetap 302 + token",
          s == 302 and "/transfer_auth?key=tok_" in loc, s)
    s, loc = login("https://sub-6fmjyrz2lq-uc.a.run.app/")
    check("fungsi normal: subdomain bertitik asli tetap lolos",
          s == 302 and "/transfer_auth?key=tok_" in loc, s)
    s, _ = login("https://xfarr-6fmjyrz2lq-uc-a-run.app/")
    check("serangan referensi GAGAL: domain strip -> 400", s == 400, s)
    s, _ = login("https://evil.com/")
    check("serangan referensi GAGAL: evil.com -> 400", s == 400, s)
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
