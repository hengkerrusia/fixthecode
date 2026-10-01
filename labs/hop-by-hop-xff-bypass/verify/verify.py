#!/usr/bin/env python3
"""
verify/verify.py — Verifier otomatis 2 fase untuk lab hop-by-hop-xff-bypass.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /admin            -> 403
      - serangan hop-by-hop            -> 200  (lab terbukti rentan)
      - GET /                          -> 200
  FASE 2 (dengan fix/): bangun ulang frontend dari fix/frontend, pastikan
      - serangan hop-by-hop            -> 403  (wajib; serangan harus gagal)
      - baseline GET /admin            -> 403
      - GET /                          -> 200
      - GET /debug/headers             -> 200 dan rantai XFF normal utuh
        (2 IP: IP klien + IP frontend; bukti proxy tidak rusak)

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan.
"""
import ipaddress
import json
import os
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
    """Kirim raw HTTP/1.1 agar header terkirim persis seperti ditulis."""
    lines = ["GET %s HTTP/1.1" % path, "Host: %s:%d" % (HOST, PORT)]
    for k, v in (headers or {}).items():
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
    s_x = attack_status()
    check("serangan hop-by-hop menembus /admin (200)", s_x == 200, "dapat %d" % s_x)

    if s_x != 200:
        log("\nFase 1 GAGAL: lab tidak dalam kondisi rentan. Periksa setup Docker.")
        sys.exit(1)
    log("FASE 1: LULUS — lab terbukti rentan dan exploit bekerja.\n")

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
            # Rantai normal: [IP klien/frontnet, IP frontend/backnet]
            chain_ok = (len(parts) == 2
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
