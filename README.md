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

| # | Lab | Kategori | Kelas kerentanan | Sumber |
|---|-----|----------|------------------|--------|
| 1 | [`web/01-hop-by-hop-xff-bypass`](labs/web/01-hop-by-hop-xff-bypass/) | Hop-by-Hop Abuse | Hop-by-hop header abuse → X-Forwarded-For stripping → admin bypass | Nathan Davison, "Abusing HTTP hop-by-hop request headers" |
| 2 | [`web/02-web-cache-deception`](labs/web/02-web-cache-deception/) | Cache Poisoning | Web cache deception → halaman privat ter-cache publik | Omer Gil, "Web Cache Deception Attack" (PayPal, $3.000) |
| 3 | [`web/03-unkeyed-input-xfh`](labs/web/03-unkeyed-input-xfh/) | Cache Poisoning | Unkeyed input → X-Forwarded-Host cache poisoning | HackerOne #977851 (Shopify, $1.300 → $6.300) |
| 4 | [`web/04-method-override`](labs/web/04-method-override/) | Cache Poisoning | Method override → X-HTTP-Method-Override cache poisoning DoS | HackerOne #1160407 (GitLab, $2.500) |
| 5 | [`web/05-cpdos-error-caching`](labs/web/05-cpdos-error-caching/) | Cache Poisoning | CPDoS → error caching (403) → denial of service | "Your Cache Has Fallen" (CCS 2019); 403-caching $2.500 |
| 6 | [`web/06-h2c-smuggling`](labs/web/06-h2c-smuggling/) | Request Smuggling | H2C smuggling → terowongan upgrade HTTP/2 cleartext → bypass proteksi /admin | Bishop Fox, h2csmuggler |
| 7 | [`web/07-ats-chunked-smuggling`](labs/web/07-ats-chunked-smuggling/) | Request Smuggling | Chunked desync → parser chunked basi (stale CR flag) → request selundupan lolos ke origin | CVE-2025-65114 (ATS, CWE-444) |
| 8 | [`web/08-paypal-clte-cache-poison`](labs/web/08-paypal-clte-cache-poison/) | Request Smuggling | CL.TE request smuggling → cache poisoning → stored XSS di /signin | HackerOne #488147 (PayPal, $18.900) |
| 9 | [`web/09-h2-downgrade-desync`](labs/web/09-h2-downgrade-desync/) | Request Smuggling | H2.CL downgrade desync → frontend HTTP/2 vs backend HTTP/1 | James Kettle, "HTTP/2: The Sequel is Always Worse" (PortSwigger Research 2021) |
| 10 | [`web/10-0cl-expect-desync`](labs/web/10-0cl-expect-desync/) | Request Smuggling | 0.CL desync via Expect: 100-continue | James Kettle, "HTTP/1.1 Must Die: The Desync Endgame" (PortSwigger Research 2025) |
| 11 | [`web/11-cspt-csrf`](labs/web/11-cspt-csrf/) | CSPT | CSPT → CSRF | Doyensec, "CSPT2CSRF" (Maxence Schmitt, 2024) |
| 12 | [`web/12-cspt-cache-deception`](labs/web/12-cspt-cache-deception/) | CSPT | CSPT → web cache deception → account takeover | zere.es, "Cache Deception + CSPT" (2025) |
| 13 | [`web/13-cspt-stylesheet-injection`](labs/web/13-cspt-stylesheet-injection/) | CSPT | CSPT via stylesheet loader → open redirect → CSS injection | HackerOne #1245165 (Medi/Acronis, 2022) |
| 14 | [`web/14-cspt-plugin-xss-ssrf`](labs/web/14-cspt-plugin-xss-ssrf/) | CSPT | CSPT via plugin loader → open redirect → XSS → SSRF | Grafana CVE-2025-4123 ("The Grafana Ghost") |
| 15 | [`web/15-crlf-response-splitting`](labs/web/15-crlf-response-splitting/) | CRLF Injection | CRLF injection -> response splitting -> session fixation | Pi-hole CVE-2025-59151 (GHSA-5v79-p56f-x7c4) |
| 16 | [`web/16-crlf-desync`](labs/web/16-crlf-desync/) | CRLF Injection | CRLF-powered desync -> request splitting -> response queue poisoning | PortSwigger Research, "CRLF-Powered Desync Attacks" (2026) |
| 17 | [`web/17-formdata-crlf`](labs/web/17-formdata-crlf/) | CRLF Injection | CRLF via multipart filename -> header part injection | form-data CVE-2026-12143 (GHSA-hmw2-7cc7-3qxx) |
| 18 | [`web/18-morgan-log-forging`](labs/web/18-morgan-log-forging/) | CRLF Injection | CRLF di Basic-auth username -> log forging | morgan CVE-2026-5078 (GHSA-4vj7-5mj6-jm8m) |
| 19 | [`web/19-zip-slip`](labs/web/19-zip-slip/) | File Inclusion | Zip Slip -> arbitrary file write via nama entry archive | Snyk Research Team, "Zip Slip" (CVE-2018-1002203) |
| 20 | [`web/20-php-filter-chain`](labs/web/20-php-filter-chain/) | File Inclusion | PHP filter chains -> LFI to RCE tanpa upload | Synacktiv, "PHP filter chains" (2022) |
| 21 | [`web/21-wp-file-inclusion`](labs/web/21-wp-file-inclusion/) | File Inclusion | WordPress file inclusion -> canonicalization tanpa containment | CVE-2026-87902 (Robert Ressl) |
| 22 | [`web/22-canto-rfi`](labs/web/22-canto-rfi/) | File Inclusion | Canto RFI -> require_once() -> RCE via data:// | CVE-2023-3452 (Wordfence, CVSS 9.8) |
| 23 | [`web/23-gitlab-maven-traversal`](labs/web/23-gitlab-maven-traversal/) | Path Traversal | GitLab Maven traversal -> tulis authorized_keys -> RCE | HackerOne #733072 |
| 24 | [`web/24-apache-249-traversal`](labs/web/24-apache-249-traversal/) | Path Traversal | Apache 2.4.49 path traversal -> file read via Alias | CVE-2021-41773 (HackerOne #1394916) |
| 25 | [`web/25-mopub-openredirect-xss`](labs/web/25-mopub-openredirect-xss/) | Open Redirect | Login open redirect -> XSS via javascript: URI | HackerOne #683298 (MoPub, jackb898) |
| 26 | [`web/26-expo-oauth-openredirect`](labs/web/26-expo-oauth-openredirect/) | Open Redirect | OAuth proxy returnUrl -> token di fragment -> ATO via hTTps:// bypass | CVE-2023-28131 (Salt Labs, CVSS 9.6) |

Kolom **Kategori** adalah taksonomi seri serangan — dipakai sebagai acuan monitoring
otomatis (vuln-watch) untuk mencari write-up/riset terbaru per kategori.

## Mulai cepat

```bash
cd labs/web/01-hop-by-hop-xff-bypass
./lab.sh start    # jalankan lab (kondisi rentan) di http://localhost:8080
./lab.sh verify   # verifikasi fase 1 + fase 2
./lab.sh stop     # hentikan & bersihkan container
```

Baca `README.md` di tiap lab sebelum mulai — di sana ada skenario, arsitektur,
dan kriteria suksesnya.
