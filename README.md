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

| # | Lab | Kategori | Entry Point | Kelas kerentanan | Akar masalah | Sumber |
|---|---|----------|-------------|------------------|--------------|--------|
| 1 | [`web/01-hop-by-hop-xff-bypass`](labs/web/01-hop-by-hop-xff-bypass/) | Hop-by-Hop Abuse | HTTP headers | Hop-by-hop header abuse → X-Forwarded-For stripping → admin bypass | header Connection tak dikonsumsi di batas proxy | Nathan Davison, "Abusing HTTP hop-by-hop request headers" |
| 2 | [`web/02-web-cache-deception`](labs/web/02-web-cache-deception/) | Cache Poisoning | URL path | Web cache deception → halaman privat ter-cache publik | respons privat dikirim dengan Cache-Control: public | Omer Gil, "Web Cache Deception Attack" (PayPal, $3.000) |
| 3 | [`web/03-unkeyed-input-xfh`](labs/web/03-unkeyed-input-xfh/) | Cache Poisoning | HTTP headers | Unkeyed input → X-Forwarded-Host cache poisoning | X-Forwarded-Host tak masuk cache key | HackerOne #977851 (Shopify, $1.300 → $6.300) |
| 4 | [`web/04-method-override`](labs/web/04-method-override/) | Cache Poisoning | HTTP headers | Method override → X-HTTP-Method-Override cache poisoning DoS | header method-override dari klien dipercaya | HackerOne #1160407 (GitLab, $2.500) |
| 5 | [`web/05-cpdos-error-caching`](labs/web/05-cpdos-error-caching/) | Cache Poisoning | HTTP headers | CPDoS → error caching (403) → denial of service | respons error 403 ikut ter-cache | "Your Cache Has Fallen" (CCS 2019); 403-caching $2.500 |
| 6 | [`web/06-h2c-smuggling`](labs/web/06-h2c-smuggling/) | Request Smuggling | Proxy | H2C smuggling → terowongan upgrade HTTP/2 cleartext → bypass proteksi /admin | frontend teruskan permintaan upgrade h2c ke backend | Bishop Fox, h2csmuggler |
| 7 | [`web/07-ats-chunked-smuggling`](labs/web/07-ats-chunked-smuggling/) | Request Smuggling | Proxy | Chunked desync → parser chunked basi (stale CR flag) → request selundupan lolos ke origin | parser chunked andalkan flag CR yang basi | CVE-2025-65114 (ATS, CWE-444) |
| 8 | [`web/08-paypal-clte-cache-poison`](labs/web/08-paypal-clte-cache-poison/) | Request Smuggling | Proxy | CL.TE request smuggling → cache poisoning → stored XSS di /signin | frontend & backend beda hitung panjang body (CL.TE) | HackerOne #488147 (PayPal, $18.900) |
| 9 | [`web/09-h2-downgrade-desync`](labs/web/09-h2-downgrade-desync/) | Request Smuggling | Proxy | H2.CL downgrade desync → frontend HTTP/2 vs backend HTTP/1 | translasi H2→H1 teruskan header CL/TE apa adanya | James Kettle, "HTTP/2: The Sequel is Always Worse" (PortSwigger Research 2021) |
| 10 | [`web/10-0cl-expect-desync`](labs/web/10-0cl-expect-desync/) | Request Smuggling | Proxy | 0.CL desync via Expect: 100-continue | proxy salah kelola alur Expect: 100-continue | James Kettle, "HTTP/1.1 Must Die: The Desync Endgame" (PortSwigger Research 2025) |
| 11 | [`web/11-cspt-csrf`](labs/web/11-cspt-csrf/) | CSPT | URL parameter | CSPT → CSRF | path request dibangun dari input tanpa validasi | Doyensec, "CSPT2CSRF" (Maxence Schmitt, 2024) |
| 12 | [`web/12-cspt-cache-deception`](labs/web/12-cspt-cache-deception/) | CSPT | URL parameter | CSPT → web cache deception → account takeover | CSPT + respons terautentikasi ter-cache publik | zere.es, "Cache Deception + CSPT" (2025) |
| 13 | [`web/13-cspt-stylesheet-injection`](labs/web/13-cspt-stylesheet-injection/) | CSPT | Reflected input | CSPT via stylesheet loader → open redirect → CSS injection | stylesheet loader muat URL dari input tak tervalidasi | HackerOne #1245165 (Medi/Acronis, 2022) |
| 14 | [`web/14-cspt-plugin-xss-ssrf`](labs/web/14-cspt-plugin-xss-ssrf/) | CSPT | Reflected input | CSPT via plugin loader → open redirect → XSS → SSRF | plugin loader muat script dari URL tak tervalidasi | Grafana CVE-2025-4123 ("The Grafana Ghost") |
| 15 | [`web/15-crlf-response-splitting`](labs/web/15-crlf-response-splitting/) | CRLF Injection | Reflected input | CRLF injection -> response splitting -> session fixation | input user masuk header respons tanpa netralisasi CRLF | Pi-hole CVE-2025-59151 (GHSA-5v79-p56f-x7c4) |
| 16 | [`web/16-crlf-desync`](labs/web/16-crlf-desync/) | CRLF Injection | Proxy | CRLF-powered desync -> request splitting -> response queue poisoning | gateway & backend beda hitung batas request | PortSwigger Research, "CRLF-Powered Desync Attacks" (2026) |
| 17 | [`web/17-formdata-crlf`](labs/web/17-formdata-crlf/) | CRLF Injection | File upload | CRLF via multipart filename -> header part injection | library multipart interpolasi filename tanpa sanitasi | form-data CVE-2026-12143 (GHSA-hmw2-7cc7-3qxx) |
| 18 | [`web/18-morgan-log-forging`](labs/web/18-morgan-log-forging/) | CRLF Injection | HTTP headers | CRLF di Basic-auth username -> log forging | input tak tepercaya ditulis ke log baris tanpa netralisasi | morgan CVE-2026-5078 (GHSA-4vj7-5mj6-jm8m) |
| 19 | [`web/19-zip-slip`](labs/web/19-zip-slip/) | File Inclusion | File upload | Zip Slip -> arbitrary file write via nama entry archive | nama entry arsip digabung ke path tanpa containment | Snyk Research Team, "Zip Slip" (CVE-2018-1002203) |
| 20 | [`web/20-php-filter-chain`](labs/web/20-php-filter-chain/) | File Inclusion | URL parameter | PHP filter chains -> LFI to RCE tanpa upload | include() terima input user; wrapper php://filter aktif | Synacktiv, "PHP filter chains" (2022) |
| 21 | [`web/21-wp-file-inclusion`](labs/web/21-wp-file-inclusion/) | File Inclusion | URL parameter | WordPress file inclusion -> canonicalization tanpa containment | realpath dicek tapi tak dibuktikan di dalam direktori | CVE-2026-87902 (Robert Ressl) |
| 22 | [`web/22-canto-rfi`](labs/web/22-canto-rfi/) | File Inclusion | URL parameter | Canto RFI -> require_once() -> RCE via data:// | require_once() terima URL; allow_url_include aktif | CVE-2023-3452 (Wordfence, CVSS 9.8) |
| 23 | [`web/23-gitlab-maven-traversal`](labs/web/23-gitlab-maven-traversal/) | Path Traversal | API | GitLab Maven traversal -> tulis authorized_keys -> RCE | path tulis file dibangun dari input tanpa containment | HackerOne #733072 |
| 24 | [`web/24-apache-249-traversal`](labs/web/24-apache-249-traversal/) | Path Traversal | URL path | Apache 2.4.49 path traversal -> file read via Alias | validasi `..` jalan sebelum URL-decode | CVE-2021-41773 (HackerOne #1394916) |
| 25 | [`web/25-mopub-openredirect-xss`](labs/web/25-mopub-openredirect-xss/) | Open Redirect | Login form | Login open redirect -> XSS via javascript: URI | parameter next tak tervalidasi; redirect via JS | HackerOne #683298 (MoPub, jackb898) |
| 26 | [`web/26-expo-oauth-openredirect`](labs/web/26-expo-oauth-openredirect/) | Open Redirect | OAuth flow | OAuth proxy returnUrl -> token di fragment -> ATO via hTTps:// bypass | returnUrl pasca-auth bawa token; validasi fail-open | CVE-2023-28131 (Salt Labs, CVSS 9.6) |
| 27 | [`web/27-khan-academy-regex-bypass`](labs/web/27-khan-academy-regex-bypass/) | Open Redirect | Login form | Regex allowlist lupa escape titik -> 1-click ATO via transfer token | titik tak di-escape di regex allowlist domain | HackerOne #3723458 (Khan Academy) |
| 28 | [`web/28-paypal-idor-privesc`](labs/web/28-paypal-idor-privesc/) | IDOR | API | PayPal IDOR tambah-user lintas merchant → privilege escalation | tambah-user lintas merchant tanpa cek relasi | HackerOne #415081 (born2hack, High 7.1, $10.500) |
| 29 | [`web/29-valve-cdkeys-idor`](labs/web/29-valve-cdkeys-idor/) | IDOR | API | Valve partner CD keys IDOR -> sedot key game milik partner lain | game_id lintas partner tanpa cek kepemilikan | HackerOne #391217 (moskowsky, Critical, $20.000) |
| 30 | [`web/30-stripe-email-idor-ato`](labs/web/30-stripe-email-idor-ato/) | IDOR | API | Stripe email change IDOR -> ganti email korban -> password-reset -> ATO | user_id mutasi diambil dari body, bukan sesi | HackerOne #1250037 (dk82hg, Critical) |
| 31 | [`web/31-gitlab-reset-array-pollution`](labs/web/31-gitlab-reset-array-pollution/) | Parameter Pollution | API | GitLab password reset array pollution -> reset link ke email attacker -> ATO | input array diterima di posisi string; mailer kirim ke semua | HackerOne #2293343 (asterion04, Critical, $35.000) |
| 32 | [`web/32-indico-principals-bola`](labs/web/32-indico-principals-bola/) | IDOR | API | Indico BOLA /api/principals -> enumerasi user ID -> PII exposure | endpoint utilitas tanpa otorisasi; ID sequential | CVE-2025-53640 (rafaelcorvino1, CWE-639) |
| 33 | [`web/33-krayin-bola-password-reset`](labs/web/33-krayin-bola-password-reset/) | IDOR | Web | Krayin CRM BOLA /admin/settings/users/edit/{id} -> password reset -> ATO | gate otorisasi cek peran, bukan kepemilikan objek | CVE-2026-38529 (trexnegro, CWE-269/639) |
| 34 | [`web/34-confluence-setup-bfla`](labs/web/34-confluence-setup-bfla/) | BFLA | Web | Confluence BFLA setup re-run -> flip setupComplete -> buat admin baru -> ATO | setup bisa di-re-run; parameter binding ubah setupComplete | CVE-2023-22515 (Atlassian, CVSS 10.0) |
| 35 | [`web/35-opensourcepos-classic-csrf`](labs/web/35-opensourcepos-classic-csrf/) | CSRF | Web | OpenSourcePOS classic CSRF POST /users -> rogue admin -> ATO | tanpa token CSRF sama sekali | CVE-2025-68434 (GHSA-wjm4-hfwg-5w5r, CVSS 8.8) |
| 36 | [`web/36-fastapiusers-login-csrf`](labs/web/36-fastapiusers-login-csrf/) | CSRF | Web | fastapi-users login CSRF -> SSO identity penyerang ter-link ke akun korban -> ATO | state token stateless, tak terikat sesi | CVE-2025-68481 (GHSA-5j53-63w8-8625) |
| 37 | [`web/37-argocd-samesite-csrf`](labs/web/37-argocd-samesite-csrf/) | CSRF | Web | Argo CD CSRF lintas-subdomain -> forged Application | Lax = batas site; tanpa validasi content-type | CVE-2024-22424 (GHSA-92mw-q256-5vwg) |
| 38 | [`web/38-admidio-imported-csrf`](labs/web/38-admidio-imported-csrf/) | CSRF | Web | Admidio imported=1 → skip CSRF + validasi → tulis inventory | penegakan CSRF kondisional pada input penyerang | CVE-2026-34383 (GHSA-4rwm-c5mj-wh7x, CVSS 4.3) |
| 39 | [`web/39-avideo-plugin-csrf`](labs/web/39-avideo-plugin-csrf/) | CSRF | Web | AVideo CSRF tempaan -> tulis config plugin -> takeover platform | token CSRF absen di endpoint konfigurasi plugin | CVE-2026-34394 (GHSA-4wwr-7h7c-chqr, CVSS 8.1) |
| 40 | [`web/40-mailpit-cswsh`](labs/web/40-mailpit-cswsh/) | CSWSH | WebSocket handshake | CSWSH Mailpit -> socket korban dibajak -> email bocor | handshake WebSocket tanpa validasi Origin | CVE-2026-22689 (GHSA-524m-q5m7-79mm, CVSS 6.5) |
| 41 | [`web/41-mailpit-cswsh-bypass`](labs/web/41-mailpit-cswsh-bypass/) | CSWSH | URL path | CSWSH Mailpit -> cek Origin terlewati via path percent-encoded -> socket dibajak -> email bocor | gate Origin uji URI mentah, router path ter-decode | CVE-2026-67448 (GHSA-8r62-w5wh-fc5m) |
| 42 | [`web/42-bokeh-cswsh-allowlist`](labs/web/42-bokeh-cswsh-allowlist/) | CSWSH | WebSocket handshake | CSWSH Bokeh -> allowlist Origin lolos via domain look-alike -> socket dibajak -> event bocor | pencocokan allowlist berhenti di awalan label | CVE-2026-21883 (GHSA-793v-589g-574v, CVSS 5.4) |

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
