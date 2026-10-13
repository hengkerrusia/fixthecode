# Lab 25 — MoPub login open redirect → XSS via `javascript:` URI (H1 #683298)

Sumber: HackerOne report #683298 (jackb898) — `app.mopub.com/login?next=` menerima
tujuan arbitrer termasuk skema `javascript:`, sehingga setelah login korban,
XSS terefleksi dieksekusi di sesi korban.

## Skenario

Publisher Portal — portal login untuk penerbit iklan. Alur login:

1. Korban membuka `/login?next=<tujuan>`.
2. Korban mengisi username + password, form dikirim ke `POST /login`
   (membawa parameter `next`).
3. Kredensial valid → server membalas halaman yang me-redirect ke `next`
   **via JavaScript**: `<script>window.location.href = "<next>";</script>`.
4. Kredensial salah → `401`.

### Topologi

```
[learner / korban] --HTTP--> [app:80 publisher portal]
[learner exploit]  --HTTP--> [browser:8081 render shim]
                                     |
                              headless Chromium
```

Service `browser` adalah infrastruktur lab: headless Chromium + shim `POST /render`
yang menerima `{"html": "..."}` dan mengembalikan `{"dom": "..."}` — DOM setelah
JavaScript dieksekusi. Exploit-mu (stdlib-only) memakai service ini untuk
*membuktikan eksekusi JS*; tidak ada dependency tambahan di host.

Kredensial demo: `demo` / `demo123`.

## Akar Masalah

Dua lapis yang saling mengunci:

1. **Open redirect tak tervalidasi.** Parameter `next` diterima apa adanya —
   URL absolut, protocol-relative (`//evil.com`), bahkan skema non-HTTP.
   Open redirect sendirian sering dianggap low severity.
2. **Sink redirect berbasis JavaScript.** Navigasi pasca-login dilakukan via
   `window.location.href = next`, bukan redirect HTTP 302. Browser mengeksekusi
   URI `javascript:` yang di-assign ke `window.location` — sehingga open
   redirect naik kelas menjadi **XSS terefleksi di sesi korban**.

Bentuk umum polanya: *setiap parameter "kembali ke" / "lanjut ke" yang mengalir
ke sink navigasi client-side (`window.location`, `location.href`, meta refresh)
tanpa validasi skema = XSS potensial*, bukan sekadar open redirect.

Bentuk aman dari pola yang sama:

- Validasi `next` secara allowlist: hanya path relatif (`/dashboard`),
  tolak yang diawali `//`, tolak yang mengandung skema (`:` sebelum `/`
  pertama), tolak backslash. Selain itu → `400` (fail-closed).
- Atau: abaikan `next` dari user dan redirect selalu ke halaman default.

## Fase 1 — Hacking

### Metodologi

1. **Baseline** — petakan aplikasi: `GET /`, `GET /login`, `POST /login`
   (kredensial benar & salah), `GET /dashboard`. Catat status & perilaku normal.
2. **Probe** — amati parameter `next`: ke mana ia mengalir? Coba `next=/dashboard`
   vs `next=https://example.com`. Perhatikan *bagaimana* redirect dilakukan
   (baca HTML responsnya, bukan cuma statusnya).
3. **Diferensial** — apa yang terjadi bila `next` diisi skema non-HTTP?
   Coba `javascript:...`. Di mana ia mendarat di respons? Konteks apa
   (atribut HTML? string JavaScript?)? Karakter apa yang harus dihindari agar
   sintaks tidak rusak?
4. **Eksploitasi** — rangkai payload `javascript:` yang mengeksekusi JavaScript
   di halaman korban. Buktikan eksekusi via service `browser`: post HTML
   respons login ke `POST http://127.0.0.1:8081/render`, periksa marker di
   `dom` yang dikembalikan.

### Deliverable

`exploit/exploit.py` (stdlib-only, selesai < 60 detik) mencetak ke stdout,
baris persis seperti ini:

```text
STATUS: <kode status HTTP login, 3 digit>
NEXT: <payload next yang dipakai>
RENDERED: true
MARKER: MOPUB-XSS-OK
```

- `STATUS`: 200 bila login berhasil dan halaman redirect diterima.
- `NEXT`: payload `next` yang dipakai (harus skema `javascript:`).
- `RENDERED`: `true` bila shim browser mengembalikan DOM.
- `MARKER`: cetak **hanya bila** string `MOPUB-XSS-OK` ditemukan di DOM hasil
  render — bukti JavaScript-mu benar-benar dieksekusi browser, bukan sekadar
  terefleksi di HTML.

## Fase 2 — Review & Fix

Baca `app/app.py`. Temukan di mana parameter `next` mengalir ke sink tanpa
validasi. Tulis perbaikan di `fix/app/app.py`:

- `next` yang tidak lolos validasi → `400` (jangan di-sanitize diam-diam
  menjadi halaman default — request ambigu harus ditolak).
- Redirect normal (`next=/dashboard`) harus tetap bekerja; login salah tetap
  `401`; halaman lain tidak berubah.

## Perintah

```sh
./lab.sh start    # jalankan rakitan rentan
./lab.sh verify   # verifikasi 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan dengan fix/ (tanpa verifikasi)
./lab.sh stop     # hentikan
```

## Referensi

- HackerOne #683298 — MoPub login open redirect → XSS via `javascript:` URI.
- CWE-601 (URL Redirection to Untrusted Site), CWE-79 (XSS).
- Catatan: `Location: javascript:...` pada redirect HTTP 302 **tidak** dieksekusi
  browser modern — rantai ini bekerja justru karena sink-nya client-side
  (`window.location.href`).
