#!/usr/bin/env python3
"""Verifier Lab 26: Expo OAuth proxy open redirect -> ATO. stdlib only."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlparse, parse_qs, quote

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
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


def req(method, path, headers=None, body=None):
    c = HTTPConnection(HOST, PORT, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    h = dict(r.getheaders())
    c.close()
    return r.status, h, data


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


def parse_contract(out):
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def contract_ok(d):
    """Validasi kontrak exploit: STATUS/LOCATION/TOKEN/ACCOUNT."""
    if d.get("STATUS") != "302":
        return False, "STATUS=%r" % d.get("STATUS")
    loc = d.get("LOCATION", "")
    if "://" not in loc or "#access_token=" not in loc:
        return False, "LOCATION malformed"
    scheme = loc.split("://")[0]
    if not any(c.isupper() for c in scheme):
        return False, "skema tidak campuran-case"
    if urlparse(loc).netloc == "app.demo":
        return False, "masih ke host aplikasi"
    frag_tok = parse_qs(urlparse(loc).fragment).get("access_token", [""])[0]
    if not frag_tok or d.get("TOKEN") != frag_tok:
        return False, "TOKEN tidak cocok fragment"
    if d.get("ACCOUNT") != "victim@demo":
        return False, "ACCOUNT=%r" % d.get("ACCOUNT")
    return True, "TOKEN=%s ACCOUNT=victim@demo" % frag_tok


def run_exploit(path):
    p = subprocess.run([sys.executable, path], capture_output=True,
                       text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def normal_flow_ru(ru):
    """Jalani alur normal dengan returnUrl tertentu; kembalikan (status_cb, location, token)."""
    s, h, _ = req("GET", "/start?returnUrl=" + quote(ru, safe=""))
    cookie = h.get("Set-Cookie", "").split(";")[0]
    s, h, _ = req("POST", "/idp/approve", body=b"")
    cb = h.get("Location", "")
    s, h, _ = req("GET", cb, headers={"Cookie": cookie})
    loc = h.get("Location", "")
    tok = parse_qs(urlparse(loc).fragment).get("access_token", [""])[0]
    return s, loc, tok


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
    s, h, _ = req("GET", "/start?returnUrl=" + quote("https://app.demo/cb", safe=""))
    check("baseline: /start set cookie ru + 302",
          s == 302 and h.get("Set-Cookie", "").startswith("ru=https://app.demo/cb"),
          s)
    s, h, _ = req("POST", "/idp/approve", body=b"")
    check("baseline: approve -> 302 ke /callback",
          s == 302 and h.get("Location", "").startswith("/callback?code="),
          h.get("Location", ""))
    s, loc, tok = normal_flow_ru("https://app.demo/cb")
    check("baseline: alur normal -> 302 + token di fragment",
          s == 302 and loc.startswith("https://app.demo/cb#access_token=tok_"),
          loc[:60])
    s, _, _ = req("GET", "/me?access_token=" + tok)
    check("baseline: token valid di /me", s == 200, s)
    s, _, _ = req("GET", "/callback?code=authcode123",
                  headers={"Cookie": "ru=https://evil.com"})
    check("baseline: https://evil.com -> 400 (allowlist host)", s == 400, s)
    s, _, _ = req("GET", "/callback?code=authcode123",
                  headers={"Cookie": "ru=http://app.demo/cb"})
    check("baseline: http:// -> 400", s == 400, s)

    print("== [HEALTH] serangan referensi: hTTps:// bypass -> token bocor -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d %s" % (rc, err.strip().splitlines()[-1] if err.strip() else ""))
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
    check("exploit: LOCATION skema campuran-case + token",
          "://" in loc and any(c.isupper() for c in loc.split("://")[0])
          and "#access_token=" in loc, loc[:70])
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: TOKEN cocok & ACCOUNT == victim@demo (ATO)", ok, got)


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
    s, loc, tok = normal_flow_ru("https://app.demo/cb")
    check("fungsi normal: alur normal tetap 302 + token",
          s == 302 and loc.startswith("https://app.demo/cb#access_token=tok_"),
          s)
    s, _, _ = req("GET", "/me?access_token=" + tok)
    check("fungsi normal: /me tetap 200", s == 200, s)
    s, _, _ = req("GET", "/callback?code=authcode123",
                  headers={"Cookie": "ru=hTTps://127.0.0.1:9/cb"})
    check("serangan referensi GAGAL: hTTps:// -> 400", s == 400, s)
    s, _, _ = req("GET", "/callback?code=authcode123",
                  headers={"Cookie": "ru=https://evil.com"})
    check("serangan referensi GAGAL: https://evil.com -> 400", s == 400, s)
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
