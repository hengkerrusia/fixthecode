#!/usr/bin/env python3
"""
verify/verify.py — Verifier otomatis 2 fase untuk lab cpdos-error-caching.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /                       -> 200 halaman publik
      - GET /static/app.js                   -> 200 bodi utuh
      - serangan referensi (health)          -> X-Forwarded-Host asing membuat
        origin mengembalikan 403; GET bersih ke URL yang sama menyajikan
        403 dari cache (lab terbukti rentan; kalau ini gagal, yang rusak
        lab-nya, bukan learner)
      - exploit/exploit.py milik learner dijalankan -> mencetak STATUS: 403
        + POISONED_URL, dan GET bersih ke POISONED_URL benar-benar
        mengembalikan 403
  FASE 2 (dengan fix/): bangun ulang cache dari fix/cache, pastikan
      - serangan referensi GAGAL             -> GET bersih setelah serangan
        tetap 200 (error tidak lagi di-cache)
      - request langsung DENGAN header asing -> tetap 403 dari origin
        (validasi host aplikasi tidak dirusak fix)
      - baseline GET /                       -> 200
      - GET /static/app.js 2x                -> 200, fetch kedua X-Cache: HIT
        (fungsi caching normal tidak rusak)

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/cache/cache.py identik byte-per-byte dengan cache/cache.py
    (pristine) -> exit 2.

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
import uuid

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080

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
    Respons kosong (server menutup koneksi tanpa respons) dilaporkan sebagai
    status 0 agar cek gagal dengan jelas, bukan traceback.
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
    try:
        status = int(head_lines[0].split()[1])
    except (IndexError, ValueError):
        return 0, {}, b""
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


def reference_attack():
    """Serangan referensi: picu 403 via host asing di satu URL unik.

    Mengembalikan (poison_url, status_bersih, body_bersih) dari GET *tanpa*
    header asing ke URL yang diserang.
    Saat lab rentan: 403 (error ter-cache).
    """
    tag = uuid.uuid4().hex[:8]
    url = "/?ref=%s" % tag
    evil = "evil-%s.test" % tag
    s1, _, _ = raw_request("GET", url, {"X-Forwarded-Host": evil})
    if s1 != 403:
        return url, s1, b""
    s2, _, body2 = raw_request("GET", url)
    return url, s2, body2


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_url = re.search(r"^POISONED_URL:\s*(\S+)\s*$", out, re.MULTILINE)
    return (m_status.group(1) if m_status else None,
            m_url.group(1) if m_url else None)


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
    s_pub, _, _ = raw_request("GET", "/")
    check("halaman publik / hidup (200)", s_pub == 200, "dapat %d" % s_pub)
    s_js, _, body_js = raw_request("GET", "/static/app.js")
    check("file statis /static/app.js utuh (200 + bodi tidak kosong)",
          s_js == 200 and len(body_js) > 0,
          "dapat %d + len(bodi)=%d" % (s_js, len(body_js)))

    # Health check: lab harus rentan terhadap serangan referensi.
    # Kalau ini gagal, yang rusak adalah lab/setup-nya — bukan learner.
    purl, s_ref, body_ref = reference_attack()
    ref_ok = s_ref == 403
    check("lab dalam kondisi rentan (403 ter-cache untuk publik)",
          ref_ok, "dapat %s" % s_ref)
    if not ref_ok:
        log("\nFase 1 GAGAL: lab tidak dalam kondisi rentan. Periksa setup Docker.")
        sys.exit(1)

    # Artefak learner: exploit/exploit.py harus ada dan sudah diisi.
    # Scaffold me-raise NotImplementedError — itu penanda "belum dikerjakan".
    exploit_py = os.path.join(LAB_DIR, "exploit", "exploit.py")
    if not os.path.exists(exploit_py):
        log("FASE 1: exploit/exploit.py belum ada — kerjakan fase 1 dulu "
            "(tulis exploit-mu di sana; lihat exploit/README.md).")
        sys.exit(3)

    # Jalankan exploit milik learner. Kontrak: skrip mencetak dua baris —
    #   STATUS: <kode>            status GET bersih ke URL racun
    #   POISONED_URL: <path>      URL yang diracuni skrip itu sendiri
    # Verifier lalu memverifikasi sendiri: GET bersih ke POISONED_URL harus
    # 403 (error ter-cache).
    log("menjalankan exploit/exploit.py milik learner ...")
    try:
        p = subprocess.run([sys.executable, exploit_py],
                           capture_output=True, text=True, timeout=60,
                           cwd=LAB_DIR)
    except subprocess.TimeoutExpired:
        log("FASE 1 GAGAL: exploit/exploit.py melebihi 60 detik (hang?).")
        sys.exit(1)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    if "NotImplementedError" in out:
        log("FASE 1: exploit/exploit.py masih scaffold (belum diedit) — "
            "kerjakan fase 1 dulu.")
        sys.exit(3)
    got_status, got_url = parse_exploit_output(out)
    ok1 = False
    detail = ""
    if not (got_status and got_url):
        detail = ("baris kontrak tak lengkap (STATUS=%s, POISONED_URL=%s)"
                  % (got_status, got_url))
    elif not got_url.startswith("/"):
        detail = "POISONED_URL harus berupa path (diawali /)"
    else:
        s_v, _, _ = raw_request("GET", got_url)
        ok1 = (got_status == "403" and s_v == 403)
        detail = ("klaim STATUS=%s, verifikasi ulang: %d"
                  % (got_status, s_v))
    ok1 = check("exploit learner meracuni cache dengan error (GET bersih -> 403)",
                ok1, detail)
    if p.returncode != 0:
        log("  (catatan: script exit code %d)" % p.returncode)
    if not ok1:
        tail = out.strip().splitlines()[-8:]
        if tail:
            log("  output script (maks 8 baris terakhir):")
            for line in tail:
                log("    " + line)
        log("\nFase 1 GAGAL: exploit-mu belum membuktikan cache poisoning. "
            "Lihat exploit/README.md.")
        sys.exit(1)
    log("FASE 1: LULUS — exploit learner reproducible dan berhasil.\n")

    # ---- FASE 2: fix harus ada dan benar ----
    # Scaffold fix = salinan pristine; file yang identik byte-per-byte dengan
    # pristine berarti belum dikerjakan.
    pristine = os.path.join(LAB_DIR, "cache", "cache.py")
    fixed = os.path.join(LAB_DIR, "fix", "cache", "cache.py")
    if not os.path.exists(fixed):
        log("FASE 2: fix/cache/cache.py belum ada — kerjakan fase 2 dulu.")
        sys.exit(2)
    with open(pristine, "rb") as f:
        pristine_bytes = f.read()
    with open(fixed, "rb") as f:
        fixed_bytes = f.read()
    if pristine_bytes == fixed_bytes:
        log("FASE 2: fix/cache/cache.py masih identik dengan pristine (belum diedit) — "
            "kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    # --force-recreate: cache dibuat ulang dalam keadaan kosong. Tanpa ini,
    # container cache dari fase 1 dipakai lagi (racun fase 1 masih di memori).
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "--build", "--force-recreate", "-d"])
    if not wait_up():
        log("lab (fix) tidak merespons — cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 2 --")
    ok = True
    purl, s_x, _ = reference_attack()
    atk_gagal = s_x == 200
    ok &= check("serangan cache poisoning GAGAL (GET bersih tetap 200)",
                atk_gagal, "dapat %s" % s_x)

    # Request langsung DENGAN header asing harus tetap 403 dari origin —
    # validasi host aplikasi tidak boleh dirusak oleh fix.
    dtag = uuid.uuid4().hex[:8]
    s_d, _, _ = raw_request("GET", "/?direct=%s" % dtag,
                            {"X-Forwarded-Host": "evil-%s.test" % dtag})
    ok &= check("validasi host aplikasi tetap jalan (header asing -> 403)",
                s_d == 403, "dapat %s" % s_d)

    s_pub, _, _ = raw_request("GET", "/")
    ok &= check("halaman publik / tetap hidup (200)", s_pub == 200,
                "dapat %d" % s_pub)

    s_j1, h_j1, _ = raw_request("GET", "/static/app.js")
    s_j2, h_j2, _ = raw_request("GET", "/static/app.js")
    cache_ok = (s_j1 == 200 and s_j2 == 200
                and h_j2.get("x-cache") == "HIT")
    ok &= check("file statis tetap ter-cache (fetch kedua X-Cache: HIT)",
                cache_ok,
                "dapat %d/%d, X-Cache=%s/%s"
                % (s_j1, s_j2, h_j1.get("x-cache"), h_j2.get("x-cache")))

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
