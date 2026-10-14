#!/usr/bin/env python3
"""Verifier Lab 30: Stripe email change IDOR -> ATO."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ATTACKER = ("attacker@lab.test", "attacker-pw")
VICTIM = ("victim@lab.test", "victim-pw")
ATTACKER_UID, VICTIM_UID = "user_9001", "user_9002"


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


def req(method, path, body=None, token=None):
    c = HTTPConnection(HOST, PORT, timeout=10)
    h = {}
    if token:
        h["Authorization"] = "Bearer " + token
    c.request(method, path,
              body=json.dumps(body).encode() if body else None, headers=h)
    r = c.getresponse()
    raw = r.read()
    try:
        data = json.loads(raw or b"{}")
    except Exception:
        data = {}
    c.close()
    return r.status, data


def wait_ready(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s, _ = req("GET", "/users")
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def login(email, password):
    s, d = req("POST", "/login", {"email": email, "password": password})
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


def contract_ok(d):
    """Oracle independen: TOKEN harus resolve ke akun victim di server."""
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    if d.get("VICTIM") != VICTIM_UID:
        return False, "VICTIM=%r (harus akun korban)" % d.get("VICTIM")
    email, token = d.get("EMAIL", ""), d.get("TOKEN", "")
    if not email or not token:
        return False, "EMAIL/TOKEN kosong"
    s, m = req("GET", "/me", token=token)
    if s != 200 or m.get("user_id") != VICTIM_UID or m.get("email") != email:
        return False, "TOKEN tidak terbukti milik victim"
    s2, _ = req("POST", "/login", {"email": VICTIM[0], "password": VICTIM[1]})
    if s2 == 200:
        return False, "kredensial lama victim masih bisa login"
    return True, "ATO terbukti: sesi %s" % email


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
    check("baseline: /me -> user_9001", s == 200 and d.get("user_id") == ATTACKER_UID, d.get("user_id"))
    s, d = req("GET", "/users", token=tok)
    check("baseline: direktori user -> 200 + user_9002",
          s == 200 and any(u["user_id"] == VICTIM_UID for u in d.get("users", [])), s)
    s, d = req("POST", "/account/email",
               {"user_id": ATTACKER_UID, "email": "attacker-self@lab.test"}, token=tok)
    s2, m = req("GET", "/me", token=tok)
    ok = s == 200 and s2 == 200 and m.get("email") == "attacker-self@lab.test"
    check("baseline: ganti email sendiri -> 200", ok, s)
    s, d = req("POST", "/account/email",
               {"user_id": ATTACKER_UID, "email": ATTACKER[0]}, token=tok)
    check("baseline: kembalikan email sendiri -> 200", s == 200, s)
    s, d = req("POST", "/account/password-reset", {"email": ATTACKER[0]})
    check("baseline: password-reset email sendiri -> token",
          s == 200 and bool(d.get("reset_token")), s)

    print("== [HEALTH] serangan referensi: IDOR ganti email -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/VICTIM/EMAIL/TOKEN", ok, got)

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
    check("exploit: VICTIM adalah akun korban (bukan milik sendiri)",
          d.get("VICTIM") == VICTIM_UID, repr(d.get("VICTIM")))
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: ATO terbukti via oracle server", ok, got)


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
    s, d = req("POST", "/account/email",
               {"user_id": VICTIM_UID, "email": "evil@lab.test"}, token=tok)
    check("serangan referensi GAGAL: ganti email lintas user -> 403", s == 403, s)
    vtok = login(*VICTIM)
    s, m = req("GET", "/me", token=vtok)
    unchanged = s == 200 and m.get("email") == VICTIM[0]
    check("serangan referensi GAGAL: email victim tidak berubah", unchanged,
          m.get("email") if s == 200 else s)
    s, d = req("POST", "/account/email",
               {"user_id": ATTACKER_UID, "email": "attacker-new@lab.test"}, token=tok)
    check("fix: ganti email sendiri tanpa password -> 403", s == 403, s)
    s, d = req("POST", "/account/email",
               {"user_id": ATTACKER_UID, "email": "attacker-new@lab.test",
                "password": "attacker-pw"}, token=tok)
    s2, m = req("GET", "/me", token=tok)
    ok = s == 200 and s2 == 200 and m.get("email") == "attacker-new@lab.test"
    check("fungsi normal: ganti email sendiri + password -> 200", ok, s)
    s, d = req("POST", "/account/email",
               {"user_id": ATTACKER_UID, "email": ATTACKER[0],
                "password": "attacker-pw"}, token=tok)
    check("fungsi normal: kembalikan email sendiri -> 200", s == 200, s)
    check("fungsi normal: login tetap jalan", bool(login(*ATTACKER)), "token")
    s, d = req("POST", "/account/password-reset", {"email": ATTACKER[0]})
    check("fungsi normal: password-reset email sendiri jalan",
          s == 200 and bool(d.get("reset_token")), s)
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
