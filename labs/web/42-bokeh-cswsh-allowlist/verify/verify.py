#!/usr/bin/env python3
"""Verifier Lab 42 — Bokeh CSWSH allowlist prefix-match (GHSA-793v-589g-574v).

Fase 1 (mode rentan): app harus bisa dipakai normal, dan handshake WebSocket
dari Origin domain look-alike (host yang diizinkan sebagai awalan) harus
diterima (101) memakai sesi korban — sementara Origin asing biasa ditolak.
Fase 2 (mode fix): handshake dari Origin asing maupun look-alike ditolak
(403), sementara fungsi normal (login, handshake dari Origin yang diizinkan,
handshake tanpa Origin, kirim event) tetap jalan.

Jalankan dari root lab:
    python3 verify/verify.py [--phase1-only|--phase2-only] [--keep]
"""
from __future__ import annotations

import base64
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:8080"
USER, PASSWORD = "dev", "dev-pw"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def http_req(method, path, data=None, cookie=None, headers=None):
    url = BASE + path
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if cookie:
        req.add_header("Cookie", cookie)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")


def login_cookie(user=USER, password=PASSWORD):
    status, headers, _ = http_req("POST", "/login", {"username": user, "password": password})
    raw = headers.get("Set-Cookie", "")
    if status != 200 or "session=" not in raw:
        return None
    return raw.split(";", 1)[0]


def ws_handshake(cookie=None, origin=None, path="/api/events"):
    """Handshake WebSocket mentah; kembalikan status HTTP-nya."""
    host = urllib.parse.urlparse(BASE).netloc
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket",
             "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
             "Sec-WebSocket-Version: 13"]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    lines += ["", ""]
    with socket.create_connection((urllib.parse.urlparse(BASE).hostname, 8080), timeout=10) as s:
        s.sendall("\r\n".join(lines).encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    first = resp.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    try:
        return int(first.split()[1])
    except (IndexError, ValueError):
        return -1


def ws_handshake_keep(cookie=None, origin=None, path="/api/events"):
    """Handshake yang koneksinya dipertahankan; kembalikan (status, sock, file)."""
    host = urllib.parse.urlparse(BASE).netloc
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket",
             "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
             "Sec-WebSocket-Version: 13"]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookie:
        lines.append(f"Cookie: {cookie}")
    lines += ["", ""]
    s = socket.create_connection((urllib.parse.urlparse(BASE).hostname, 8080), timeout=10)
    s.settimeout(15)
    s.sendall("\r\n".join(lines).encode())
    f = s.makefile("rb")
    status_line = f.readline().decode("utf-8", "replace")
    while True:
        line = f.readline()
        if line in (b"\r\n", b""):
            break
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        status = -1
    return status, s, f


def read_text_frame(f, timeout=10):
    """Baca satu frame WebSocket dari server; kembalikan payload teks."""
    def read_exact(n):
        buf = b""
        while len(buf) < n:
            chunk = f.read(n - len(buf))
            if not chunk:
                raise ConnectionError("koneksi tertutup")
            buf += chunk
        return buf

    while True:
        b1, b2 = read_exact(2)
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            length = int.from_bytes(read_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(read_exact(8), "big")
        payload = read_exact(length) if length else b""
        if opcode == 0x1:
            return payload.decode("utf-8", "replace")
        if opcode == 0x8:
            raise ConnectionError("frame close")


def run_script(path: Path, timeout=60):
    env = dict(os.environ)
    env["BASE_URL"] = BASE
    proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=str(LAB))
    return proc.returncode, proc.stdout, proc.stderr


def oracle_events(cookie):
    status, _, body = http_req("GET", "/api/events", cookie=cookie)
    return body if status == 200 else ""


def poll_oracle(cookie, subject, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if subject in oracle_events(cookie):
            return True
        time.sleep(0.5)
    return False


def script_proves(stdout: str) -> bool:
    status_ok = any(l.strip() == "STATUS: 101" for l in stdout.splitlines())
    subject = None
    for l in stdout.splitlines():
        if l.startswith("EVENT_SUBJECT:"):
            subject = l.split(":", 1)[1].strip()
    return status_ok and bool(subject)


def compose(compose_args, *args, check_rc=True):
    cmd = ["docker", "compose", *compose_args, *args]
    proc = subprocess.run(cmd, cwd=str(LAB), capture_output=True, text=True, timeout=600)
    if check_rc and proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"perintah gagal: {' '.join(cmd)}")
    return proc


def wait_ready(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _, _ = http_req("GET", "/")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(1.5)
    return False


PHASE1_COMPOSE = ["-f", "docker-compose.yml"]
PHASE2_COMPOSE = ["-p", "lab42fix", "-f", "docker-compose.yml", "-f", "docker-compose.fix.yml"]


def phase1():
    print("\n=== FASE 1 — mode rentan ===")
    compose(PHASE1_COMPOSE, "down", "-v", check_rc=False)
    compose(PHASE1_COMPOSE, "up", "-d", "--build")
    if not check("app start (mode rentan)", wait_ready()):
        return

    status, _, body = http_req("GET", "/")
    check("panel login tampil", status == 200 and "<form" in body, f"status={status}")

    status, _, _ = http_req("POST", "/login", {"username": USER, "password": "salah"})
    check("login password salah ditolak", status == 401, f"status={status}")

    cookie = login_cookie()
    if not check("login benar menghasilkan sesi", cookie is not None):
        return

    status, _, body = http_req("GET", "/me", cookie=cookie)
    check("/me mengenali sesi", status == 200 and USER in body, f"status={status}")

    status = ws_handshake(origin="http://portal.corp")
    check("handshake tanpa sesi ditolak 401", status == 401, f"status={status}")

    status = ws_handshake(cookie, "https://evil.example")
    check("[PROTEKSI] Origin asing ditolak 403 (allowlist tampak aktif)",
          status == 403, f"status={status}")

    status = ws_handshake(cookie, "http://portal.corp.evil.example")
    check("[RENTAN] Origin look-alike diterima 101", status == 101, f"status={status}")

    status = ws_handshake(cookie, None)
    check("handshake tanpa Origin diterima 101", status == 101, f"status={status}")

    status = ws_handshake(cookie, "http://corp.evil.example")
    check("Origin bukan-awalan ditolak 403", status == 403, f"status={status}")

    try:
        rc, out, err = run_script(LAB / "solutions" / "exploit.py")
        check("[HEALTH] exploit referensi membuktikan CSWSH",
              script_proves(out), f"rc={rc} out={out.strip()[:120]} err={err.strip()[:120]}")
    except Exception as e:
        check("[HEALTH] exploit referensi membuktikan CSWSH", False, str(e))

    learner = LAB / "exploit" / "exploit.py"
    try:
        rc, out, err = run_script(learner)
        if "NotImplementedError" in err:
            print("[SKIP] exploit peserta belum dikerjakan")
        else:
            check("exploit peserta membuktikan CSWSH", script_proves(out),
                  f"rc={rc} out={out.strip()[:120]} err={err.strip()[:120]}")
    except Exception as e:
        check("exploit peserta membuktikan CSWSH", False, str(e))


def phase2():
    print("\n=== FASE 2 — mode fix ===")
    fixed = (LAB / "fix" / "app" / "app.py").read_bytes()
    pristine = (LAB / "app" / "app.py").read_bytes()
    if not check("fix sudah ditulis (berbeda dari app rentan)", fixed != pristine):
        print("[SKIP] sisa fase 2 dilewati — fix masih identik dengan app rentan")
        return
    compose(PHASE2_COMPOSE, "down", "-v", check_rc=False)
    compose(PHASE1_COMPOSE, "down", "-v", check_rc=False)
    compose(PHASE2_COMPOSE, "up", "-d", "--build")
    if not check("app start (mode fix)", wait_ready()):
        return

    cookie = login_cookie()
    if not check("login tetap berfungsi setelah fix", cookie is not None):
        return

    status = ws_handshake(cookie, "https://evil.example")
    check("[FIX] Origin asing ditolak 403", status == 403, f"status={status}")

    status = ws_handshake(cookie, "http://portal.corp.evil.example")
    check("[FIX] Origin look-alike ditolak 403", status == 403, f"status={status}")

    status = ws_handshake(cookie, None)
    check("handshake tanpa Origin tetap diterima 101", status == 101, f"status={status}")

    subject = "uji-fix-" + secrets.token_hex(3)
    status, s, f = ws_handshake_keep(cookie, "http://portal.corp")
    ok = status == 101
    detail = f"status={status}"
    if ok:
        http_req("POST", "/api/send-test", {"subject": subject}, cookie=cookie)
        try:
            got = ""
            deadline = time.time() + 10
            while time.time() < deadline and subject not in got:
                got += read_text_frame(f, timeout=10)
            ok = subject in got
            detail += f" event={'diterima' if ok else 'tidak diterima'}"
        except Exception as e:
            ok = False
            detail += f" err={e}"
    s.close()
    check("handshake dari Origin yang diizinkan tetap menerima event", ok, detail)

    status = ws_handshake(cookie, "http://127.0.0.1:8080")
    check("handshake Origin alamat server sendiri diterima 101", status == 101,
          f"status={status}")

    try:
        rc, out, err = run_script(LAB / "solutions" / "exploit.py")
        check("exploit referensi GAGAL setelah fix", not script_proves(out),
              f"rc={rc} out={out.strip()[:120]}")
    except Exception as e:
        check("exploit referensi GAGAL setelah fix", False, str(e))


def main():
    args = sys.argv[1:]
    keep = "--keep" in args
    try:
        if "--phase2-only" not in args:
            phase1()
        if "--phase1-only" not in args:
            phase2()
    finally:
        if not keep:
            compose(PHASE1_COMPOSE, "down", "-v", check_rc=False)
            compose(PHASE2_COMPOSE, "down", "-v", check_rc=False)
    failed = [r for r in results if not r[1]]
    print(f"\n=== RINGKASAN: {len(results) - len(failed)}/{len(results)} lulus ===")
    for name, _, detail in failed:
        print(f"GAGAL: {name} — {detail}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
