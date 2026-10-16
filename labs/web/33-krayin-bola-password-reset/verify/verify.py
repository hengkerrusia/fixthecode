#!/usr/bin/env python3
"""Verifier Lab 33: Krayin CRM BOLA -> password reset -> ATO."""

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

ATTACKER = ("attacker@lab.test", "attacker-pw")
VICTIM = ("victim@lab.test", "victim-pw")
ADMIN = ("admin@lab.test", "admin-pw")
ATTACKER_ID = 100
VICTIM_ID = 1
ADMIN_ID = 2


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
            s, _ = req("POST", "/login", {"email": ATTACKER[0], "password": ATTACKER[1]})
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def login(email, password):
    s, d = req("POST", "/login", {"email": email, "password": password})
    return d.get("token", "") if s == 200 else ""


def put_edit(uid, password, token):
    return req("PUT", "/admin/settings/users/edit/%d" % uid,
               {"password": password}, token=token, form=True)


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


def victim_token_ok(victim_token):
    if not victim_token:
        return False, "token kosong"
    s, d = req("GET", "/me", token=victim_token)
    if s == 200 and d.get("user_id") == VICTIM_ID and d.get("email") == VICTIM[0]:
        return True, "sesi milik victim@lab.test"
    return False, "s=%r me=%r" % (s, d)


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    return victim_token_ok(d.get("VICTIM_TOKEN", ""))


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    tok = login(*ATTACKER)
    check("baseline: login attacker -> token", bool(tok), "token" if tok else "gagal")
    s, d = req("GET", "/me", token=tok)
    check("baseline: /me -> id 100 non-admin",
          s == 200 and d.get("user_id") == ATTACKER_ID and d.get("is_admin") is False,
          d.get("user_id"))
    s, d = put_edit(999, "x", tok)
    check("baseline: id tak dikenal -> 404", s == 404, s)
    s, d = put_edit(VICTIM_ID, "x", None)
    check("baseline: tanpa token -> 401", s == 401, s)
    s, d = put_edit(ADMIN_ID, "x", tok)
    check("baseline: target admin oleh non-admin -> 403", s == 403, s)
    s, d = req("PUT", "/admin/settings/users/edit/%d" % VICTIM_ID,
               {}, token=tok, form=True)
    check("baseline: tanpa field password -> 400", s == 400, s)

    print("== [HEALTH] serangan referensi: reset password victim -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/VICTIM_TOKEN", ok, got)

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
    check("exploit: ATO terbukti via oracle (/me milik victim)", ok, got)


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
    tok = login(*ATTACKER)
    s, d = put_edit(VICTIM_ID, "hacked-by-attacker", tok)
    check("serangan GAGAL: reset password victim -> 403", s == 403, s)
    s, d = req("POST", "/login", {"email": VICTIM[0], "password": VICTIM[1]})
    check("serangan GAGAL: password victim tidak berubah", s == 200, s)
    s, d = put_edit(ATTACKER_ID, "attacker-new-pw", tok)
    ok_self = s == 200
    check("fungsi normal: user ubah password sendiri -> 200", ok_self, s)
    tok2 = login(ATTACKER[0], "attacker-new-pw")
    check("fungsi normal: login dengan password baru sendiri -> 200",
          bool(tok2), "token" if tok2 else "gagal")
    s, d = put_edit(ATTACKER_ID, ATTACKER[1], tok2)
    check("fungsi normal: kembalikan password sendiri -> 200", s == 200, s)
    atok = login(*ADMIN)
    s, d = put_edit(VICTIM_ID, "admin-set-pw", atok)
    check("fungsi normal: admin ubah password user -> 200", s == 200, s)
    s, d = put_edit(VICTIM_ID, VICTIM[1], atok)
    check("fungsi normal: admin kembalikan password victim -> 200", s == 200, s)
    s, d = put_edit(VICTIM_ID, "x", None)
    check("fungsi normal: tanpa token -> 401", s == 401, s)
    s, d = put_edit(999, "x", tok)
    check("fungsi normal: id tak dikenal -> 404", s == 404, s)
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
