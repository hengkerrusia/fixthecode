# fixthecode

Lab keamanan web berbasis Docker. **Bukan CTF, bukan kejar flag.**

Setiap lab diselesaikan dalam **2 fase**:

1. **Fase 1 — Hacking.** Eksploitasi kerentanannya sampai berhasil. Pahami *bagaimana* serangan bekerja.
2. **Fase 2 — Fixing.** Review code/config, tulis perbaikan. Pahami *mengapa* itu rentan dan bagaimana menutupnya dengan benar.

Lab dinyatakan **sukses** hanya jika kedua fase lolos verifikasi otomatis (`verify/`).

## Aturan main

- **Restart = kembali rentan.** Image dibangun dari file *pristine* (definisi rentan) di tiap lab.
  Fix-mu tinggal di direktori `fix/` dan hanya dipakai saat verifikasi — tidak pernah menimpa
  definisi rentan. `docker compose down` + `up --build` selalu menghasilkan lab yang rentan lagi,
  walau sesi sebelumnya kamu sudah fixing.
- **Image seringan mungkin.** Prinsip: base image sekecil mungkin (`nginx:alpine`,
  `python:alpine`), tanpa dependency yang tidak perlu, tanpa build tool di image final.
- **Satu lab = satu kerentanan nyata**, dikurasi dari write-up / riset / CVE yang tepercaya
  (bukan artikel asal-asalan).

## Anatomi sebuah lab

```
labs/<kategori>/<nn>-<nama-lab>/
  README.md               # skenario, arsitektur, objektif 2 fase, referensi
  docker-compose.yml      # definisi PRISTINE (rentan) — jangan diedit untuk fixing
  docker-compose.fix.yml  # overlay compose: pakai config dari fix/
  lab.sh                  # start | stop | verify | fix-up
  frontend/  mid/  app/   # service lab (Dockerfile + config, tanpa volume mount)
  fix/                    # <-- hasil kerja fase 2 tinggal di sini
  verify/verify.py        # verifier otomatis 2 fase (Python stdlib only)
  exploit/                # panduan fase 1 + exploit.py milikmu (dieksekusi & dinilai verifier)
  solutions/              # solusi referensi — buka hanya kalau mentok
```

Kategori top-level dibuat lebar dan stabil (`web`, `api`, `network`, `crypto`, `mobile`,
`cloud`); satu lab masuk satu kategori utama (kategori sekunder dicatat di README lab).

## Daftar lab

| # | Lab | Kategori | Entry Point | Kelas kerentanan | Sumber |
|---|---|----------|-------------|------------------|--------|
| 1 | [`web/01-hop-by-hop-xff-bypass`](labs/web/01-hop-by-hop-xff-bypass/) | Hop-by-Hop Abuse | HTTP headers | Hop-by-hop header abuse → X-Forwarded-For stripping → admin bypass | Nathan Davison, "Abusing HTTP hop-by-hop request headers" |
| 2 | [`web/02-web-cache-deception`](labs/web/02-web-cache-deception/) | Cache Poisoning | URL path | Web cache deception → halaman privat ter-cache publik | Omer Gil, "Web Cache Deception Attack" (PayPal, $3.000) |
| 3 | [`web/03-unkeyed-input-xfh`](labs/web/03-unkeyed-input-xfh/) | Cache Poisoning | HTTP headers | Unkeyed input → X-Forwarded-Host cache poisoning | HackerOne #977851 (Shopify, $1.300 → $6.300) |
| 4 | [`web/04-method-override`](labs/web/04-method-override/) | Cache Poisoning | HTTP headers | Method override → X-HTTP-Method-Override cache poisoning DoS | HackerOne #1160407 (GitLab, $2.500) |
| 5 | [`web/05-cpdos-error-caching`](labs/web/05-cpdos-error-caching/) | Cache Poisoning | HTTP headers | CPDoS → error caching (403) → denial of service | "Your Cache Has Fallen" (CCS 2019); 403-caching $2.500 |
| 6 | [`web/06-h2c-smuggling`](labs/web/06-h2c-smuggling/) | Request Smuggling | Proxy | H2C smuggling → terowongan upgrade HTTP/2 cleartext → bypass proteksi /admin | Bishop Fox, h2csmuggler |
| 7 | [`web/07-ats-chunked-smuggling`](labs/web/07-ats-chunked-smuggling/) | Request Smuggling | Proxy | Chunked desync → parser chunked basi (stale CR flag) → request selundupan lolos ke origin | CVE-2025-65114 (ATS, CWE-444) |
| 8 | [`web/08-paypal-clte-cache-poison`](labs/web/08-paypal-clte-cache-poison/) | Request Smuggling | Proxy | CL.TE request smuggling → cache poisoning → stored XSS di /signin | HackerOne #488147 (PayPal, $18.900) |
| 9 | [`web/09-h2-downgrade-desync`](labs/web/09-h2-downgrade-desync/) | Request Smuggling | Proxy | H2.CL downgrade desync → frontend HTTP/2 vs backend HTTP/1 | James Kettle, "HTTP/2: The Sequel is Always Worse" (PortSwigger Research 2021) |
| 10 | [`web/10-0cl-expect-desync`](labs/web/10-0cl-expect-desync/) | Request Smuggling | Proxy | 0.CL desync via Expect: 100-continue | James Kettle, "HTTP/1.1 Must Die: The Desync Endgame" (PortSwigger Research 2025) |
| 11 | [`web/11-cspt-csrf`](labs/web/11-cspt-csrf/) | CSPT | URL parameter | CSPT → CSRF | Doyensec, "CSPT2CSRF" (Maxence Schmitt, 2024) |
| 12 | [`web/12-cspt-cache-deception`](labs/web/12-cspt-cache-deception/) | CSPT | URL parameter | CSPT → web cache deception → account takeover | zere.es, "Cache Deception + CSPT" (2025) |
| 13 | [`web/13-cspt-stylesheet-injection`](labs/web/13-cspt-stylesheet-injection/) | CSPT | Reflected input | CSPT via stylesheet loader → open redirect → CSS injection | HackerOne #1245165 (Medi/Acronis, 2022) |
| 14 | [`web/14-cspt-plugin-xss-ssrf`](labs/web/14-cspt-plugin-xss-ssrf/) | CSPT | Reflected input | CSPT via plugin loader → open redirect → XSS → SSRF | Grafana CVE-2025-4123 ("The Grafana Ghost") |
| 15 | [`web/15-crlf-response-splitting`](labs/web/15-crlf-response-splitting/) | CRLF Injection | Reflected input | CRLF injection -> response splitting -> session fixation | Pi-hole CVE-2025-59151 (GHSA-5v79-p56f-x7c4) |
| 16 | [`web/16-crlf-desync`](labs/web/16-crlf-desync/) | CRLF Injection | Proxy | CRLF-powered desync -> request splitting -> response queue poisoning | PortSwigger Research, "CRLF-Powered Desync Attacks" (2026) |
| 17 | [`web/17-formdata-crlf`](labs/web/17-formdata-crlf/) | CRLF Injection | File upload | CRLF via multipart filename -> header part injection | form-data CVE-2026-12143 (GHSA-hmw2-7cc7-3qxx) |
| 18 | [`web/18-morgan-log-forging`](labs/web/18-morgan-log-forging/) | CRLF Injection | HTTP headers | CRLF di Basic-auth username -> log forging | morgan CVE-2026-5078 (GHSA-4vj7-5mj6-jm8m) |
| 19 | [`web/19-zip-slip`](labs/web/19-zip-slip/) | File Inclusion | File upload | Zip Slip -> arbitrary file write via nama entry archive | Snyk Research Team, "Zip Slip" (CVE-2018-1002203) |
| 20 | [`web/20-php-filter-chain`](labs/web/20-php-filter-chain/) | File Inclusion | URL parameter | PHP filter chains -> LFI to RCE tanpa upload | Synacktiv, "PHP filter chains" (2022) |
| 21 | [`web/21-wp-file-inclusion`](labs/web/21-wp-file-inclusion/) | File Inclusion | URL parameter | WordPress file inclusion -> canonicalization tanpa containment | CVE-2026-87902 (Robert Ressl) |
| 22 | [`web/22-canto-rfi`](labs/web/22-canto-rfi/) | File Inclusion | URL parameter | Canto RFI -> require_once() -> RCE via data:// | CVE-2023-3452 (Wordfence, CVSS 9.8) |
| 23 | [`web/23-gitlab-maven-traversal`](labs/web/23-gitlab-maven-traversal/) | Path Traversal | API | GitLab Maven traversal -> tulis authorized_keys -> RCE | HackerOne #733072 |
| 24 | [`web/24-apache-249-traversal`](labs/web/24-apache-249-traversal/) | Path Traversal | URL path | Apache 2.4.49 path traversal -> file read via Alias | CVE-2021-41773 (HackerOne #1394916) |
| 25 | [`web/25-mopub-openredirect-xss`](labs/web/25-mopub-openredirect-xss/) | Open Redirect | Login form | Login open redirect -> XSS via javascript: URI | HackerOne #683298 (MoPub, jackb898) |
| 26 | [`web/26-expo-oauth-openredirect`](labs/web/26-expo-oauth-openredirect/) | Open Redirect | OAuth flow | OAuth proxy returnUrl -> token di fragment -> ATO via hTTps:// bypass | CVE-2023-28131 (Salt Labs, CVSS 9.6) |
| 27 | [`web/27-khan-academy-regex-bypass`](labs/web/27-khan-academy-regex-bypass/) | Open Redirect | Login form | Regex allowlist lupa escape titik -> 1-click ATO via transfer token | HackerOne #3723458 (Khan Academy) |
| 28 | [`web/28-paypal-idor-privesc`](labs/web/28-paypal-idor-privesc/) | IDOR | API | PayPal IDOR tambah-user lintas merchant → privilege escalation | HackerOne #415081 (born2hack, High 7.1, $10.500) |
| 29 | [`web/29-valve-cdkeys-idor`](labs/web/29-valve-cdkeys-idor/) | IDOR | API | Valve partner CD keys IDOR -> sedot key game milik partner lain | HackerOne #391217 (moskowsky, Critical, $20.000) |
| 30 | [`web/30-stripe-email-idor-ato`](labs/web/30-stripe-email-idor-ato/) | IDOR | API | Stripe email change IDOR -> ganti email korban -> password-reset -> ATO | HackerOne #1250037 (dk82hg, Critical) |
| 31 | [`web/31-gitlab-reset-array-pollution`](labs/web/31-gitlab-reset-array-pollution/) | Parameter Pollution | API | GitLab password reset array pollution -> reset link ke email attacker -> ATO | HackerOne #2293343 (asterion04, Critical, $35.000) |
| 32 | [`web/32-indico-principals-bola`](labs/web/32-indico-principals-bola/) | IDOR | API | Indico BOLA /api/principals -> enumerasi user ID -> PII exposure | CVE-2025-53640 (rafaelcorvino1, CWE-639) |
| 33 | [`web/33-krayin-bola-password-reset`](labs/web/33-krayin-bola-password-reset/) | IDOR | Web | Krayin CRM BOLA /admin/settings/users/edit/{id} -> password reset -> ATO | CVE-2026-38529 (trexnegro, CWE-269/639) |
| 34 | [`web/34-confluence-setup-bfla`](labs/web/34-confluence-setup-bfla/) | BFLA | Web | Confluence BFLA setup re-run -> flip setupComplete -> buat admin baru -> ATO | CVE-2023-22515 (Atlassian, CVSS 10.0) |
| 35 | [`web/35-opensourcepos-classic-csrf`](labs/web/35-opensourcepos-classic-csrf/) | CSRF | Web | OpenSourcePOS classic CSRF POST /users tanpa token -> rogue admin -> ATO | CVE-2025-68434 (GHSA-wjm4-hfwg-5w5r, CVSS 8.8) |

Kolom **Kategori** adalah taksonomi seri serangan — dipakai sebagai acuan monitoring
otomatis (vuln-watch) untuk mencari write-up/riset terbaru per kategori.

Kolom **Entry Point** menunjukkan di mana kelas kerentanan ini diuji di dunia nyata
(mengacu pada [metodologi HackTricks](https://hacktricks.wiki/en/pentesting-web/web-vulnerabilities-methodology.html)) —
berguna saat hunting: dari entry point yang ditemui, petakan ke kelas serangan yang relevan.

## Mulai cepat

```bash
cd labs/web/01-hop-by-hop-xff-bypass
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh stop     # hentikan & bersihkan container
```

Baca `README.md` di tiap lab sebelum mulai — di sana ada skenario, arsitektur,
dan kriteria suksesnya.
