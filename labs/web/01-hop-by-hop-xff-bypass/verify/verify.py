#!/usr/bin/env python3
"""
verify/verify.py — Verifier otomatis 2 fase untuk lab hop-by-hop-xff-bypass.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /admin            -> 403
      - serangan referensi (health)    -> 200  (lab terbukti rentan;
        kalau ini gagal, yang rusak lab-nya, bukan learner)
      - exploit/exploit.py milik learner dijalankan -> mencetak STATUS: 200
      - GET /                          -> 200
  FASE 2 (dengan fix/): bangun ulang frontend dari fix/frontend, pastikan
      - serangan hop-by-hop            -> 403  (wajib; serangan harus gagal)
      - baseline GET /admin            -> 403
      - GET /                          -> 200
      - GET /debug/headers             -> 200 dan rantai XFF normal utuh
        (2 IP: IP klien eksternal + IP frontend; bukti proxy tidak rusak)

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
BACKNET = ipaddress.ip_network("10.201.0.0/16")

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


def raw_request(path, headers=None):
    """Kirim raw HTTP/1.1 agar header terkirim persis seperti ditulis.

    Membaca respons sampai EOF, jadi default-nya mengirim `Connection: close`
    (kecuali caller menentukan sendiri, mis. serangan fase 1). Tanpa ini,
    nginx (HTTP/1.1 keep-alive) tidak menutup koneksi dan recv() nyangkut
    sampai socket timeout — wait_up terlihat "stuck" padahal lab hidup.
    """
    lines = ["GET %s HTTP/1.1" % path, "Host: %s:%d" % (HOST, PORT)]
    hdrs = dict(headers or {})
    hdrs.setdefault("Connection", "close")
    for k, v in hdrs.items():
        lines.append("%s: %s" % (k, v))
    req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(req)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
    head, _, body = resp.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, body


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    for _ in range(timeout):
        try:
            status, _ = raw_request("/")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def attack_status():
    """Serangan fase 1: daftarkan X-Forwarded-For sebagai hop-by-hop."""
    status, _ = raw_request("/admin", {"Connection": "close, X-Forwarded-For"})
    return status


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
    s_base, _ = raw_request("/admin")
    check("baseline /admin ditolak (403)", s_base == 403, "dapat %d" % s_base)
    s_hit, _ = raw_request("/")
    check("halaman publik / hidup (200)", s_hit == 200, "dapat %d" % s_hit)

    # Health check: lab harus rentan terhadap serangan referensi.
    # Kalau ini gagal, yang rusak adalah lab/setup-nya — bukan learner.
    s_ref = attack_status()
    check("lab dalam kondisi rentan (serangan referensi -> 200)",
          s_ref == 200, "dapat %d" % s_ref)
    if s_ref != 200:
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
    # "STATUS: <kode>" berisi status HTTP GET /admin hasil serangannya.
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
    ok1 = check("exploit learner menembus /admin (STATUS: 200)", got == "200",
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
        log("\nFase 1 GAGAL: exploit-mu belum mencapai 200 di /admin. "
            "Lihat exploit/README.md.")
        sys.exit(1)
    log("FASE 1: LULUS — exploit learner reproducible dan berhasil.\n")

    # ---- FASE 2: fix harus ada dan benar ----
    pristine = os.path.join(LAB_DIR, "frontend", "nginx.conf")
    fixed = os.path.join(LAB_DIR, "fix", "frontend", "nginx.conf")
    if not os.path.exists(fixed):
        log("FASE 2: fix/frontend/nginx.conf belum ada — kerjakan fase 2 dulu.")
        sys.exit(2)
    with open(pristine) as f:
        pristine_txt = f.read()
    with open(fixed) as f:
        fixed_txt = f.read()
    if "TODO (fase 2)" in fixed_txt:
        log("FASE 2: fix/frontend/nginx.conf masih scaffold (belum diedit) — "
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
    s_x = attack_status()
    ok &= check("serangan hop-by-hop DITOLAK (403)", s_x == 403, "dapat %d" % s_x)
    s_base, _ = raw_request("/admin")
    ok &= check("baseline /admin tetap ditolak (403)", s_base == 403, "dapat %d" % s_base)
    s_hit, _ = raw_request("/")
    ok &= check("halaman publik / tetap hidup (200)", s_hit == 200, "dapat %d" % s_hit)

    s_dbg, body = raw_request("/debug/headers")
    chain_ok = False
    chain_detail = "dapat %d" % s_dbg
    if s_dbg == 200:
        try:
            data = json.loads(body.decode("utf-8"))
            xff = data.get("X-Forwarded-For", "")
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            # Rantai normal: [IP klien eksternal, IP frontend/backnet].
            # IP pertama WAJIB di luar BACKNET — ini invariant yang menjaga
            # baseline selalu 403 (regresi: gateway NAT Docker pernah bocor
            # masuk rantai sebagai $remote_addr di sebagian mesin).
            chain_ok = (len(parts) == 2
                        and ipaddress.ip_address(parts[0]) not in BACKNET
                        and ipaddress.ip_address(parts[1]) in BACKNET)
            chain_detail = "XFF=%s" % xff
        except Exception as e:
            chain_detail = "gagal parse: %s" % e
    ok &= check("/debug/headers hidup & rantai XFF normal utuh", chain_ok, chain_detail)

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
