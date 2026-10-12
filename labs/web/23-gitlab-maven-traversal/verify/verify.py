#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 23 (H1 #733072, GitLab Maven traversal).

Rantai: PUT /api/v4/projects/<id>/packages/maven/<path>/<file_name>
dengan body. Server menggabungkan <path>/<file_name> ke direktori
penyimpanan tanpa validasi, sehingga file_name yang mengandung
traversal ter-encode ("%2e%2e%2f") menulis di luar direktori —
primitif *write* via traversal. Di kasus aslinya, attacker menimpa
authorized_keys lalu masuk via SSH (RCE). Pelajaran inti: traversal
pada operasi tulis sama berbahayanya — bahkan lebih — dari pada
operasi baca.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - PUT/GET artefak normal -> 200 (fungsi registry utuh).
      - serangan referensi (health): solutions/exploit.py mencetak
        STATUS: 200 dan MARKER: GITLAB-TRAVERSAL-WRITE-OK;
        gagal di sini = lab rusak, bukan learner gagal.
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 dan MARKER: GITLAB-TRAVERSAL-WRITE-OK.
  FASE 2 (dengan fix/): bangun ulang dengan fix/server.py, pastikan
      - serangan referensi GAGAL fail-closed: marker tidak muncul
        (fix menolak path di luar direktori penyimpanan).
      - fungsi normal utuh: PUT/GET artefak normal tetap 200.

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/server.py identik byte-per-byte dengan
    app/server.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
MARKER = "GITLAB-TRAVERSAL-WRITE-OK"
FIX_FILES = ["server.py"]
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


def wait_port(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = HTTPConnection(HOST, PORT, timeout=3)
            c.request("GET", "/api/v4/projects/1/packages/maven/a/b/c.jar")
            r = c.getresponse()
            r.read()
            c.close()
            return True
        except OSError:
            time.sleep(2)
    return False


def put(path, body, timeout=30):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("PUT", path, body=body)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def get(path, timeout=30):
    c = HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def reference_attack():
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def learner_exploit():
    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_marker = re.search(r"^MARKER:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_status.group(1) if m_status else None),
            (m_marker.group(1) if m_marker else None))


def baseline_checks(label):
    ok = True
    p = "/api/v4/projects/1/packages/maven/com/example/1.0/lib.jar"
    s, _ = put(p, b"fake-jar-bytes")
    ok &= check("%s: PUT artefak normal -> 200" % label, s == 200,
                "status=%s" % s)
    s, body = get(p)
    ok &= check("%s: GET artefak normal -> 200" % label,
                s == 200 and body == b"fake-jar-bytes",
                "status=%s" % s)
    s, _ = get("/api/v4/projects/1/packages/maven/nope/missing.jar")
    ok &= check("%s: artefak tidak ada -> 404" % label, s == 404,
                "status=%s" % s)
    return ok


def main():
    if shutil.which("docker") is None:
        log("docker tidak ditemukan di PATH. Install Docker dulu lalu jalankan lagi.")
        sys.exit(1)

    exp = os.path.join(LAB_DIR, "exploit", "exploit.py")
    if not os.path.isfile(exp):
        log("exploit/exploit.py belum ada.")
        sys.exit(3)
    rc, _, err = learner_exploit()
    if "NotImplementedError" in err:
        log("Fase 1 belum dikerjakan (exploit.py masih scaffold).")
        sys.exit(3)

    untouched = True
    for rel in FIX_FILES:
        a = os.path.join(LAB_DIR, "app", rel)
        b = os.path.join(LAB_DIR, "fix", rel)
        if not (os.path.isfile(a) and os.path.isfile(b)):
            untouched = False
            break
        with open(a, "rb") as fa, open(b, "rb") as fb:
            if fa.read() != fb.read():
                untouched = False
                break
    if untouched:
        log("Fase 2 belum dikerjakan (fix/* identik dengan app/*).")
        sys.exit(2)

    compose_down()

    # ---------- FASE 1: pristine ----------
    log("== FASE 1: rakitan rentan (pristine) ==")
    run(compose_base() + ["up", "--build", "-d"])
    try:
        if not wait_port():
            check("lab menyala", False, "port tidak merespons")
            sys.exit(1)
        ok = baseline_checks("baseline")

        log("[HEALTH] serangan referensi builder...")
        rc, out, err = reference_attack()
        st, mk = parse_exploit_output(out)
        ok &= check("[HEALTH] serangan referensi berhasil",
                    st == "200" and mk == MARKER,
                    "rc=%s out=%r" % (rc, out.strip()[:120]))

        log("menjalankan exploit/exploit.py milik learner...")
        rc, out, err = learner_exploit()
        st, mk = parse_exploit_output(out)
        ok &= check("exploit: STATUS 200", st == "200",
                    "out=%r" % out.strip()[:120])
        ok &= check("exploit: MARKER cocok", mk == MARKER,
                    "marker=%r" % mk)
    finally:
        compose_down()

    # ---------- FASE 2: dengan fix ----------
    log("== FASE 2: rakitan dengan fix/ ==")
    run(compose_fix() + ["up", "--build", "-d"])
    try:
        if not wait_port():
            check("lab (fix) menyala", False, "port tidak merespons")
            sys.exit(1)
        ok2 = baseline_checks("baseline+fix")

        log("[HEALTH] serangan referensi terhadap rakitan fix...")
        rc, out, err = reference_attack()
        st, mk = parse_exploit_output(out)
        attack_blocked = (mk != MARKER)
        ok2 &= check("serangan referensi digagalkan fix", attack_blocked,
                     "STATUS=%s MARKER=%r" % (st, mk))
    finally:
        compose_down()

    total = len(results)
    passed = sum(1 for _, ok_ in results if ok_)
    log("== ringkasan: %s %d/%d ==" % (PASS if passed == total else FAIL,
                                       passed, total))
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
