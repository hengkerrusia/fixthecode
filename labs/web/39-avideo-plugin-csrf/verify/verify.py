#!/usr/bin/env python3
"""Verifier Lab 39: AVideo plugin-config CSRF -> platform takeover (CVE-2026-34394)."""

import os
import secrets
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import urlencode

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
ORIGINAL_EMAIL = "payments@myvideosite.com"
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
            import json as _j
            data = _j.dumps(body).encode()
            h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    raw = r.read()
    try:
        import json as _j
        resp = _j.loads(raw or b"{}")
    except Exception:
        resp = {}
    set_cookie = r.getheader("Set-Cookie", "")
    c.close()
    return r.status, resp, set_cookie, raw


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
            s, _, _, _ = req("GET", "/")
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def login(username, password):
    s, d, raw, _ = req("POST", "/login",
                       {"username": username, "password": password}, form=True)
    if s != 200:
        return "", {}, ""
    return sid_of(raw), d, raw


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


def plugins_of(cookie):
    s, d, _, _ = req("GET", "/admin/plugins", cookie=cookie)
    return s, d.get("plugins", {})


def forged_save(victim_cookie, email, token=None):
    body = {"pluginName": "PayPerView", "paypalReceiverEmail": email}
    if token is not None:
        body["csrf_token"] = token
    return req("POST", "/admin/save.json.php", body,
               cookie=victim_cookie, form=True)


def contract_ok(d, victim_cookie):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    if d.get("PLUGIN") != "PayPerView":
        return False, "PLUGIN=%r" % d.get("PLUGIN")
    email = d.get("PAYPAL_EMAIL", "")
    if not email or "@" not in email:
        return False, "PAYPAL_EMAIL=%r" % d.get("PAYPAL_EMAIL")
    if email == ORIGINAL_EMAIL:
        return False, "nilai tidak berubah (masih asli)"
    s, plugins = plugins_of(victim_cookie)
    got = plugins.get("PayPerView", {}).get("paypalReceiverEmail")
    if got == email:
        return True, "paypalReceiverEmail=%r (takeover terbukti)" % got
    return False, "oracle=%r, kontrak=%r" % (got, email)


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    s, _, _, _ = req("GET", "/")
    check("baseline: GET / panel -> 200", s == 200, s)
    sid, _, _ = login("admin", "salah")
    check("baseline: login password salah -> 401", sid == "", repr(sid))
    victim, info, raw_cookie = login("admin", "admin-pw")
    check("baseline: login admin -> sesi + csrf_token",
          bool(victim) and bool(info.get("csrf_token")),
          "sesi" if victim else "gagal")
    s, _, _, _ = req("GET", "/me", cookie=victim)
    check("baseline: /me -> 200", s == 200, s)
    s, plugins = plugins_of(victim)
    check("baseline: GET /admin/plugins -> 200, 3 plugin",
          s == 200 and set(plugins) == {"PayPerView", "AWS_S3", "LDAP"},
          sorted(plugins) if s == 200 else s)
    c = HTTPConnection(HOST, PORT, timeout=10)
    c.request("GET", "/admin/plugin/edit?name=PayPerView",
              headers={"Cookie": "session=" + victim})
    r = c.getresponse()
    html = r.read().decode()
    c.close()
    check("baseline: form admin resmi memuat csrf_token",
          r.status == 200 and info.get("csrf_token", "") in html, r.status)
    check("baseline: cookie sesi SameSite=None",
          "SameSite=None" in raw_cookie, raw_cookie[:60])
    legit_key = "sk_live_" + secrets.token_hex(4)
    s, d, _, _ = req("POST", "/admin/save.json.php",
                     {"csrf_token": info.get("csrf_token", ""),
                      "pluginName": "PayPerView", "stripeKey": legit_key},
                     cookie=victim, form=True)
    _, plugins = plugins_of(victim)
    check("baseline: save token valid -> 200 + tersimpan",
          s == 200 and plugins.get("PayPerView", {}).get("stripeKey") == legit_key,
          s)

    print("== [HEALTH] serangan referensi: tempaan tanpa token ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d, victim) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/PLUGIN/PAYPAL_EMAIL + oracle", ok, got)

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
    ok, got = contract_ok(d, victim) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: takeover terbukti via oracle (paypalReceiverEmail)", ok, got)


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
    victim, info, _ = login("admin", "admin-pw")
    check("fungsi normal: login -> sesi", bool(victim),
          "sesi" if victim else "gagal")
    evil = "attacker%d@evil.com" % secrets.randbelow(100000)
    s, _, _, _ = forged_save(victim, evil)
    check("serangan GAGAL: tempaan tanpa token -> 4xx",
          400 <= s < 500, s)
    s, _, _, _ = forged_save(victim, evil, token="salah")
    check("serangan GAGAL: tempaan token salah -> 4xx",
          400 <= s < 500, s)
    _, plugins = plugins_of(victim)
    got = plugins.get("PayPerView", {}).get("paypalReceiverEmail")
    check("serangan GAGAL: config tidak berubah", got == ORIGINAL_EMAIL, got)
    legit_key = "sk_live_" + secrets.token_hex(4)
    s, _, _, _ = req("POST", "/admin/save.json.php",
                     {"csrf_token": info.get("csrf_token", ""),
                      "pluginName": "PayPerView", "stripeKey": legit_key},
                     cookie=victim, form=True)
    _, plugins = plugins_of(victim)
    check("fungsi normal: token valid -> 200 + tersimpan",
          s == 200 and plugins.get("PayPerView", {}).get("stripeKey") == legit_key,
          s)
    s, _, _, _ = req("POST", "/admin/save.json.php",
                     {"csrf_token": info.get("csrf_token", ""),
                      "pluginName": "NoSuchPlugin", "x": "1"},
                     cookie=victim, form=True)
    check("fungsi normal: plugin tak dikenal -> 404", s == 404, s)
    print("== FASE 2: menjalankan serangan referensi terhadap fix ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, _ = contract_ok(d, victim)
    check("serangan referensi GAGAL total (tidak ada kontrak valid)",
          rc != 0 or not ok, "rc=%d" % rc)


if __name__ == "__main__":
    fase1()
    fase2()
    print("== HASIL: %d/%d cek lulus ==" % (passed, passed + failed))
    sh(["docker", "compose", "down"])
    sys.exit(0 if failed == 0 else 1)
