# Lab 37 — Argo CD CSRF: SameSite itu batas site, bukan origin → cluster takeover

Sumber: [vendor advisory Argo CD GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg)
(CVE-2024-22424, dilaporkan oleh An Trinh / Upwind).
Terdampak Argo CD **< 2.10-rc2, < 2.9.4, < 2.8.8, < 2.7.16**; diperbaiki di
rilis tersebut (breaking change: API menolak non-GET tanpa
`Content-Type: application/json`). Ini lab ketiga seri CSRF — yang "advanced":
token/sesi tidak relevan, yang di-bypass adalah semantik cookie browser itu
sendiri.

## Skenario

Mock API Argo CD (satu admin: `admin` / `admin-pw`). Server mengandalkan
cookie `argocd.token` ber-atribut `SameSite=Lax` sebagai pertahanan CSRF —
tanpa token anti-CSRF lain.

- `GET /` → panel (HTML generik)
- `POST /api/v1/session` (JSON/form: `username`, `password`) → 200 + cookie
  `argocd.token` (`Domain=lab.local; HttpOnly; SameSite=Lax`)
- `GET /api/v1/applications` (cookie) → daftar aplikasi (oracle lab)
- `POST /api/v1/applications` (cookie; body `{"name": ..., "spec": ...}`)
  → 201, aplikasi tercipta
- `OPTIONS *` → 204 tanpa header CORS

Tidak ada browser di lab ini: `exploit.py`-mu memainkan peran browser korban
*dan* halaman penyerang. Header `Host`/`Origin` yang kamu kirim adalah cara
bercerita "request ini datang dari halaman X menuju host Y" — server tidak
memvalidasinya; aturan cookie + CORS ditegakkan oleh model browser yang kamu
tulis.

Rantai serangan (setia pada advisory + riset Upwind): penyerang menaruh HTML
di **sibling subdomain** (`evil.lab.local`, satu site dengan
`argo.lab.local`) → korban yang sedang login membukanya → request tempaan ke
API membuat Application menunjuk repo penyerang → deploy kode jahat.

## Akar Masalah

**Dua asumsi yang salah, satu serangan:**

1. **`SameSite=Lax` disangka batas origin — padahal batas site.**
   Site = eTLD+1. `test.internal.example.com` dan
   `argo-cd.internal.example.com` adalah *satu site*: browser tetap mengirim
   cookie Lax pada subrequest antar keduanya. Perusahaan yang menaruh Argo CD
   di subdomain internal dan memberi tim lain subdomain tetangga memberi
   penyerang "origin" yang sah menurut cookie.
2. **Preflight CORS disangka pengaman server — padahal pengaman browser yang
   bisa dihindari.** Browser hanya mengirim preflight untuk content type
   "sensitif" (`application/json`). Dengan `text/plain` (cukup untuk
   "simple request"), tidak ada preflight — dan server yang tidak memvalidasi
   Content-Type tetap mem-parse body sebagai JSON lalu mengeksekusinya.

Gabungannya: request lintas-origin dari sibling subdomain tiba dengan cookie
utuh, tanpa preflight, dan diproses sebagai perintah API yang sah.

Bentuk amannya (persis patch upstream):

1. **Server memvalidasi Content-Type sendiri** — jangan delegasikan ke
   preflight browser. Non-GET tanpa `application/json` → 4xx (fail-closed).
   Dengan ini, request lintas-origin *terpaksa* memakai `application/json` →
   *terpaksa* memicu preflight → *terpaksa* diblokir browser bila server
   tidak mengizinkan CORS.
2. Token anti-CSRF per-request sebagai pertahanan lapis kedua (bukan
   satu-satunya).
3. `SameSite=Lax` tetap dipasang — ia menutup kasus domain eksternal murni,
   hanya saja bukan garis pertahanan terakhir.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login → amati `Set-Cookie` (atribut apa saja?). Buat aplikasi
   via `POST /api/v1/applications` dengan cookie → 201. Autentikasi bekerja.
2. **Probe**: ulangi pembuatan aplikasi dengan `Content-Type: text/plain`
   (body tetap JSON). Apakah server keberatan? `OPTIONS` dengan
   `Origin: http://evil.com` → apakah ada `Access-Control-Allow-Origin`?
3. **Diferensial**: modelkan dua halaman penyerang — `evil.com` (cross-site)
   vs `evil.lab.local` (sibling, same-site). Untuk tiap halaman, terapkan
   aturan SameSite=Lax dan preflight: mana yang cookie-nya terkirim, mana
   yang request-nya lolos?
4. **Eksploitasi**: dari halaman sibling subdomain, kirim `POST
   /api/v1/applications` berversi `text/plain` berisi spec aplikasi jahat
   (`spec.source.repoURL` milikmu) → 201 → buktikan di oracle.

### Deliverable

`exploit/exploit.py` dijalankan verifier dan **wajib** mencetak tepat dua baris:

```text
STATUS: 200
APP: <nama aplikasi>
```

`APP` adalah nama aplikasi yang kamu buat lewat serangan — verifier login
sebagai admin dan memastikan nama itu muncul di `GET /api/v1/applications`.

## Fase 2 — Review & Fix

Baca `app/app.py`, temukan titiknya: `POST /api/v1/applications` mem-parse
body sebagai JSON tanpa memeriksa Content-Type. Tulis perbaikan di
`fix/app/app.py`:

- Request non-GET ke API wajib `Content-Type: application/json`
  (toleransi `; charset=...`); selain itu → 4xx fail-closed.
- Fungsi normal tetap utuh: login → 200 + cookie; create dengan JSON → 201;
  list → benar.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix/ milikmu
./lab.sh stop     # hentikan lab
```

## Referensi

- https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg (vendor advisory)
- https://nvd.nist.gov/vuln/detail/CVE-2024-22424 (NVD)
- https://www.upwind.io/feed/upwind-takes-over-argocd-and-an-eks-cluster-using-only-a-simple-csrf-vulnerability (riset asli + PoC end-to-end)
- OWASP Cross-Site Request Forgery Prevention Cheat Sheet
