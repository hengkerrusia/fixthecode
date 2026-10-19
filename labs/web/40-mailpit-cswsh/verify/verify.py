#!/usr/bin/env python3
"""Verifier Lab 40: Mailpit CSWSH - WebSocket tanpa validasi Origin (CVE-2026-22689)."""

import base64
import json
import os
import secrets
import socket
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


def req(method, path, body=None, cookie=None, form=False):
    c = HTTPConnection(HOST, PORT, timeout=10)
    h = {}
    if cookie:
        h["Cookie"] = "session=" + cookie
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
        return ""
    return sid_of(raw)


def ws_handshake(cookie=None, origin=None):
    s = socket.create_connection((HOST, PORT), timeout=10)
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    lines = ["GET /ws HTTP/1.1",
             "Host: %s:%d" % (HOST, PORT),
             "Upgrade: websocket",
             "Connection: Upgrade",
             "Sec-WebSocket-Key: " + key,
             "Sec-WebSocket-Version: 13"]
    if origin is not None:
        lines.append("Origin: " + origin)
    if cookie:
        lines.append("Cookie: session=" + cookie)
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    f = s.makefile("rb")
    status = f.readline().decode(errors="replace").strip()
    while True:
        line = f.readline().decode(errors="replace").strip()
        if not line:
            break
    return s, f, status


def ws_read_frame(f, timeout=10):
    import select
    r, _, _ = select.select([f], [], [], timeout)
    if not r:
        return None, None
    head = f.read(2)
    if len(head) < 2:
        return None, None
    opcode = head[0] & 0x0F
    ln = head[1] & 0x7F
    if ln == 126:
        ln = int.from_bytes(f.read(2), "big")
    elif ln == 127:
        ln = int.from_bytes(f.read(8), "big")
    payload = f.read(ln) if ln else b""
    return opcode, payload


def ws_close(s):
    try:
        mask = secrets.token_bytes(4)
        s.sendall(bytes([0x88, 0x80]) + mask)
    except Exception:
        pass
    try:
        s.close()
    except Exception:
        pass


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


def events_of(cookie):
    s, d, _ = req("GET", "/api/events", cookie=cookie)
    return d.get("emails", [])


def contract_ok(d, victim):
    if d.get("STATUS") != "101":
        return False, "STATUS=%r" % d.get("STATUS")
    try:
        eid = int(d.get("EVENT_ID", ""))
    except (TypeError, ValueError):
        return False, "EVENT_ID=%r" % d.get("EVENT_ID")
    subj = d.get("EVENT_SUBJECT", "")
    if not subj:
        return False, "EVENT_SUBJECT kosong"
    hit = [e for e in events_of(victim)
           if e["id"] == eid and e["subject"] == subj]
    if hit:
        return True, "event %d %r diterima lintas-origin (bocor terbukti)" % (
            eid, subj)
    return False, "event %d tidak cocok di oracle" % eid


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
    check("baseline: login password salah -> 401", login("dev", "salah") == "", "")
    victim = login("dev", "dev-pw")
    check("baseline: login dev -> sesi", bool(victim), "sesi" if victim else "gagal")
    s, d, _ = req("GET", "/me", cookie=victim)
    check("baseline: /me -> 200", s == 200, s)

    s, f, status = ws_handshake(cookie=None, origin="https://evil.example")
    ws_close(s)
    check("baseline: handshake tanpa sesi -> 401", status.startswith("HTTP/1.1 401"), status)

    s, f, status = ws_handshake(cookie=victim, origin="https://evil.example")
    ws_open = status.startswith("HTTP/1.1 101")
    ws_close(s)
    check("RENTAN: handshake cookie + Origin asing -> 101", ws_open, status)

    s, f, status = ws_handshake(cookie=victim, origin=None)
    ok_no_origin = status.startswith("HTTP/1.1 101")
    ws_close(s)
    check("baseline: handshake tanpa Origin -> 101", ok_no_origin, status)

    print("== [HEALTH] serangan referensi: hijack lintas-origin ==")
    rc, out, err = run_exploit(os.path.join(LAB, "solutions", "exploit.py"))
    d = parse_contract(out)
    ok, got = contract_ok(d, victim) if rc == 0 else (False, "rc=%d" % rc)
    check("serangan referensi: kontrak STATUS/EVENT_ID/EVENT_SUBJECT + oracle", ok, got)

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
    check("exploit: STATUS 101", d.get("STATUS") == "101", repr(d.get("STATUS")))
    ok, got = contract_ok(d, victim) if rc == 0 else (False, "rc=%d" % rc)
    check("exploit: event bocor via socket bajakan (oracle)", ok, got)


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
    victim = login("dev", "dev-pw")
    check("fungsi normal: login -> sesi", bool(victim),
          "sesi" if victim else "gagal")

    s, f, status = ws_handshake(cookie=victim, origin="https://evil.example")
    ws_close(s)
    check("serangan GAGAL: Origin asing -> 403",
          status.startswith("HTTP/1.1 403"), status)

    s, f, status = ws_handshake(cookie=victim, origin=None)
    ok_no_origin = status.startswith("HTTP/1.1 101")
    ws_close(s)
    check("fungsi normal: tanpa Origin -> 101", ok_no_origin, status)

    s, f, status = ws_handshake(cookie=victim,
                                origin="http://%s:%d" % (HOST, PORT))
    ok_same = status.startswith("HTTP/1.1 101")
    if ok_same:
        subj = "rutin-" + secrets.token_hex(3)
        _, d, _ = req("POST", "/api/send-test",
                      {"subject": subj, "from": "a@b.c"}, cookie=victim, form=True)
        eid = d.get("id")
        opcode, payload = ws_read_frame(f)
        try:
            ev = json.loads(payload or b"{}")
        except Exception:
            ev = {}
        ok_same = (opcode == 0x1 and ev.get("id") == eid
                   and ev.get("subject") == subj)
    ws_close(s)
    check("fungsi normal: Origin sah -> 101 + event diterima", ok_same, "")

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
