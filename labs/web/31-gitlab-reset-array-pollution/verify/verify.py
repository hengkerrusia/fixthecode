#!/usr/bin/env python3
"""Verifier Lab 31: GitLab password reset array pollution -> ATO."""

import json
import os
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
passed, failed = 0, 0

VICTIM = ("victim@lab.test", "victim-pw")
VICTIM_UID = "user_3101"
MY_EMAIL = "evil@attacker.lab"


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
            s, _ = req("POST", "/password-reset",
                       {"user": {"email": "probe@lab.test"}})
            if s == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def login(email, password):
    s, d = req("POST", "/login", {"email": email, "password": password})
    return d.get("token", "") if s == 200 else ""


def inbox(email):
    s, d = req("GET", "/inbox/" + email)
    return d.get("messages", []) if s == 200 else None


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
    token = d.get("TOKEN", "")
    if not token:
        return False, "TOKEN kosong"
    s, m = req("GET", "/me", token=token)
    if s != 200 or m.get("user_id") != VICTIM_UID:
        return False, "TOKEN tidak terbukti milik victim"
    if login(*VICTIM):
        return False, "password lama victim masih bisa login"
    return True, "ATO terbukti via oracle server"


def fase1():
    print("== FASE 1: membangun lab PRISTINE (rentan) ==")
    sh(["docker", "compose", "down"])
    sh(["docker", "compose", "up", "--build", "-d"])
    print("menunggu lab siap di 127.0.0.1:8080 ...")
    if not wait_ready():
        check("lab siap", False, "timeout")
        return
    s, d = req("POST", "/password-reset", {"user": {"email": VICTIM[0]}})
    check("baseline: reset string email -> 200", s == 200, s)
    msgs = inbox(MY_EMAIL)
    check("baseline: inbox sendiri kosong (tidak ada fanout)",
          msgs == [], len(msgs) if msgs is not None else "403")
    s, d = req("GET", "/inbox/" + VICTIM[0])
    check("baseline: inbox victim tidak bisa dibaca -> 403", s == 403, s)
    check("baseline: login victim kredensial awal jalan", bool(login(*VICTIM)), "token")

    print("== [HEALTH] serangan referensi: array pollution -> ATO ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/VICTIM/TOKEN", ok, got)

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
    s, d = req("POST", "/password-reset",
               {"user": {"email": [VICTIM[0], MY_EMAIL]}})
    check("serangan referensi GAGAL: array -> 400", s == 400, s)
    msgs = inbox(MY_EMAIL)
    check("serangan referensi GAGAL: tidak ada email terkirim",
          msgs == [], len(msgs) if msgs is not None else "403")
    check("serangan referensi GAGAL: password victim tidak berubah",
          bool(login(*VICTIM)), "masih bisa login")
    s, d = req("POST", "/password-reset", {"user": {"email": VICTIM[0]}})
    check("fungsi normal: reset string email -> 200", s == 200, s)
    s, d = req("POST", "/password-reset", {"user": {"email": "nobody@lab.test"}})
    msgs = inbox(MY_EMAIL)
    check("fungsi normal: email tak dikenal -> 200 tanpa email terkirim",
          s == 200 and msgs == [], s)
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
