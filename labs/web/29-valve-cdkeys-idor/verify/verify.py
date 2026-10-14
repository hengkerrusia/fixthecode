#!/usr/bin/env python3
"""Verifier Lab 29: Valve partner CD keys IDOR."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

ATTACKER = ("dev@pixelquest.dev", "devpw")
VICTIM_USER = ("aaa@galaxyempires.com", "galaxypw")
OWN, TARGET = "game_5001", "game_5002"


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


def victim_keys():
    """Oracle independen: key asli game korban diambil sebagai pemiliknya."""
    tok = login(*VICTIM_USER)
    if not tok:
        return []
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + TARGET, token=tok)
    return d.get("keys", []) if s == 200 else []


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
    if d.get("GAME") != TARGET:
        return False, "GAME=%r (harus game korban)" % d.get("GAME")
    if d.get("KEYS") != "5":
        return False, "KEYS=%r" % d.get("KEYS")
    real = victim_keys()
    if not real or d.get("KEY1") != real[0]:
        return False, "KEY1 tidak cocok key asli"
    return True, "%d key asli %s" % (len(real), TARGET)


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
    s, d = req("GET", "/games", token=tok)
    check("baseline: direktori game -> 200 + game_5002",
          s == 200 and any(g["id"] == TARGET for g in d), s)
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + OWN, token=tok)
    check("baseline: assignkeys game sendiri -> 200 + 5 key",
          s == 200 and len(d.get("keys", [])) == 5, s)
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + TARGET)
    check("baseline: assignkeys tanpa token -> 401", s == 401, s)

    print("== [HEALTH] serangan referensi: IDOR assignkeys lintas partner ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/GAME/KEYS/KEY1", ok, got)

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
    check("exploit: GAME adalah game korban (bukan milik sendiri)",
          d.get("GAME") == TARGET, repr(d.get("GAME")))
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: key asli korban terbukti", ok, got)


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
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + TARGET, token=tok)
    check("serangan referensi GAGAL: lintas partner -> 403", s == 403, s)
    leaked = bool(d.get("keys"))
    check("serangan referensi GAGAL: tidak ada key bocor", not leaked,
          "bersih" if not leaked else "bocor!")
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + OWN, token=tok)
    check("fungsi normal: game sendiri tetap 200 + 5 key",
          s == 200 and len(d.get("keys", [])) == 5, s)
    s, d = req("GET", "/partnercdkeys/assignkeys?game_id=" + TARGET)
    check("fungsi normal: tanpa token tetap 401", s == 401, s)
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
