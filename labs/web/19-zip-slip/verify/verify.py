#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 19.

Rantai: POST /upload menerima byte mentah sebuah arsip .zip -> tiap nama
entry arsip (input tak tepercaya) digabung ke direktori target
(/data/uploads) tanpa validasi -> entry "../PWNED.txt" menulis file ke
/data/PWNED.txt, di luar direktori target: Zip Slip, ala Snyk Research
2018 dan CVE-2018-1002203 (unzipper npm <0.8.13, fixed di 0.8.13).

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / -> 200; upload zip normal -> 200;
        GET /files/<nama> mengembalikan isi yang sama
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 200, ESCAPED_PATH: /data/PWNED.txt, MARKER: <marker>;
        file /data/PWNED.txt berisi marker teramati di dalam container
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200, ESCAPED_PATH: /data/PWNED.txt, MARKER: <marker>;
        verifier membaca /data/PWNED.txt di dalam container dan
        memastikan isinya sama dengan marker learner
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - serangan referensi GAGAL: /data/PWNED.txt tidak tercipta
        (fix boleh menolak upload dengan 400 atau melewati entry
        yang lolos — yang dinilai: tidak ada tulisan ke luar
        direktori target)
      - fungsi normal utuh: upload zip normal + baca kembali

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/* identik byte-per-byte dengan app/* -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import io
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from http.client import HTTPConnection

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
ESCAPED_PATH = "/data/PWNED.txt"
FIX_FILES = ["Dockerfile", "package.json", "server.js"]
PASS, FAIL = "LULUS", "GAGAL"
results = []


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    log("  [%s] %s%s" % (PASS if ok else FAIL, name,
                         " -- " + detail if detail else ""))
    return ok


def run(cmd):
    p = subprocess.run(cmd, cwd=LAB_DIR, capture_output=True,
                       text=True, timeout=600)
    if p.returncode != 0:
        log("perintah gagal: %s\n%s" % (" ".join(cmd), p.stderr[-2000:]))
        sys.exit(1)
    return p


def compose_base():
    return ["docker", "compose"]


def compose_fix():
    return ["docker", "compose", "-f", "docker-compose.yml",
            "-f", "docker-compose.fix.yml"]


def compose_down():
    run(compose_fix() + ["down", "--remove-orphans"])
    run(compose_base() + ["down", "--remove-orphans"])


def exec_app(base, *args):
    p = subprocess.run(base + ["exec", "-T", "app"] + list(args),
                       cwd=LAB_DIR, capture_output=True, text=True,
                       timeout=60)
    return p.returncode, (p.stdout or "").strip()


def escaped_exists(base):
    rc, _ = exec_app(base, "test", "-f", ESCAPED_PATH)
    return rc == 0


def escaped_content(base):
    rc, out = exec_app(base, "cat", ESCAPED_PATH)
    return out if rc == 0 else None


def clean_escaped(base):
    exec_app(base, "rm", "-f", ESCAPED_PATH)


def get(path, timeout=10):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def post_upload(data, timeout=15):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("POST", "/upload", body=data,
                  headers={"Content-Type": "application/zip"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def craft_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def reference_attack(marker):
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp, marker], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_path = re.search(r"^ESCAPED_PATH:\s*(\S+)\s*$", out, re.MULTILINE)
    m_marker = re.search(r"^MARKER:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_path.group(1) if m_path else None),
            (m_marker.group(1) if m_marker else None))


def valid_marker(m):
    return bool(m) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", m)


def health_marker():
    return "health-%s" % uuid.uuid4().hex[:8]


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, _ = get("/")
            if st == 200:
                return True
        except OSError:
            pass
        time.sleep(2)
    return False


def baseline_checks(base, tag):
    st, _ = get("/")
    check("%s: GET / -> 200" % tag, st == 200, "dapat %s" % st)
    data = craft_zip([("hello.txt", "hello world")])
    st, _ = post_upload(data)
    check("%s: upload zip normal -> 200" % tag, st == 200, "dapat %s" % st)
    st, body = get("/files/hello.txt")
    check("%s: baca kembali file hasil ekstrak" % tag,
          st == 200 and body == b"hello world",
          "dapat %s %r" % (st, body[:20]))


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    log("== bersih-bersih container lama ==")
    compose_down()

    # ---------------- FASE 1 ----------------
    base = compose_base()
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run(base + ["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    baseline_checks(base, "baseline")
    clean_escaped(base)
    check("pracetak: belum ada file lolos", not escaped_exists(base))

    log("== [HEALTH] serangan referensi: entry ../PWNED.txt -> tulis ke luar target ==")
    marker = health_marker()
    rc, out, err = reference_attack(marker)
    status, epath, m = parse_exploit_output(out)
    content = escaped_content(base)
    ok_ref = (rc == 0 and status == "200" and epath == ESCAPED_PATH
              and m == marker and content == marker)
    check("serangan referensi: STATUS 200 + /data/PWNED.txt berisi marker",
          ok_ref, "dapat rc=%s status=%r marker=%r isi=%r"
          % (rc, status, m, (content or "")[:20]))
    if not ok_ref:
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stderr: %s" % (err[-1500:] if err else "-"))
        compose_down()
        sys.exit(1)

    log("== FASE 1: menjalankan exploit/exploit.py milik learner ==")
    clean_escaped(base)
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    try:
        p = subprocess.run([sys.executable, exp], capture_output=True,
                           text=True, timeout=120,
                           cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 120 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    status, epath, m = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak ESCAPED_PATH: /data/PWNED.txt",
          epath == ESCAPED_PATH, "dapat %r" % epath)
    check("exploit mencetak MARKER (alfanumerik)", valid_marker(m),
          "dapat %r" % m)
    content = escaped_content(base)
    check("MARKER terbukti: /data/PWNED.txt berisi marker learner",
          valid_marker(m) and content == m,
          "dapat isi=%r" % ((content or "")[:20]))

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine_same = True
    for fn in FIX_FILES:
        a = os.path.join(LAB_DIR, "app", fn)
        b = os.path.join(LAB_DIR, "fix", "app", fn)
        with open(a, "rb") as f1, open(b, "rb") as f2:
            if f1.read() != f2.read():
                pristine_same = False
                break
    if pristine_same:
        log("fix/app/* masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    fix = compose_fix()
    log("== FASE 2: membangun lab dengan FIX ==")
    run(fix + ["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    clean_escaped(fix)
    log("== FASE 2: serangan referensi harus GAGAL ==")
    marker2 = health_marker()
    rc, out, _ = reference_attack(marker2)
    check("serangan referensi GAGAL: tidak ada /data/PWNED.txt",
          not escaped_exists(fix),
          "dapat ada=%s" % escaped_exists(fix))

    baseline_checks(fix, "fungsi normal")

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed),
                                         len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
