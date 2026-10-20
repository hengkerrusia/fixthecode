# Lab 41 — Bypass cek Origin WebSocket via path percent-encoded (Mailpit CVE-2026-67448)

Sumber: [GHSA-8r62-w5wh-fc5m](https://github.com/advisories/GHSA-8r62-w5wh-fc5m)
(CVE-2026-67448, CWE-1385) — "WebSocket origin check bypass via
percent-encoded path". Ini **regresi** dari CVE-2026-22689 (Lab 40).
Terdampak: axllent/mailpit 1.29.0 – 1.30.5; diperbaiki di 1.30.6.

Kode rentan: perbaikan Lab 40 diimplementasikan ulang sebagai middleware
Origin di `server/server.go`, tetapi gate-nya menguji **URI mentah**:
`strings.HasPrefix(r.RequestURI, "/api/")`. Router Go (`http.ServeMux`)
justru me-route berdasarkan path yang **sudah di-percent-decode**. Sementara
itu `server/websockets/client.go` tetap memasang
`CheckOrigin: func(r *http.Request) bool { return true }` dengan komentar
"origin is checked via server.go's CORS settings". Akibatnya request ke
`/%61pi/events` melewatkan satu-satunya cek Origin (URI mentah tidak diawali
`/api/`), lalu ter-route ke handler `/api/events` yang menerima semua
origin. Perbaikan 1.30.6: gate memakai `r.URL.Path` (sudah ter-decode) **dan**
upgrader memvalidasi Origin sendiri secara fail-closed.

## Skenario

Kelanjutan Lab 40: tool testing email ala Mailpit, satu developer bawaan
(`dev` / `dev-pw`). WebSocket event sekarang tinggal di `GET /api/events`
(path yang sama menyajikan daftar email JSON untuk request non-upgrade).
Kali ini aplikasi **sudah punya** middleware Origin: handshake lintas-origin
ke `/api/events` ditolak 403. Sepintas aplikasi ini sudah diperbaiki.

Catatan: sama seperti Lab 40, Mailpit asli tidak memakai autentikasi —
lab ini memakai sesi login agar model CSWSH klasik (penyerang menunggangi
browser korban) terlihat jelas.

## Akar Masalah

Pola umumnya: **validasi membaca representasi yang berbeda dari yang
dikonsumsi router**. Pemeriksa menguji representasi mentah (URI apa adanya),
router bekerja pada representasi ternormalisasi (path hasil decode). Setiap
pasangan cek-lalu-route yang normalisasinya tidak sinkron adalah celah:
penyerang cukup menemukan representasi yang *lolos dari pemeriksa* tetapi
*setara bagi router*.

Bentuk aman dari pola yang sama:

- Normalisasi dulu, validasi kemudian — pada representasi kanonis yang sama
  persis dengan yang dipakai routing (`r.URL.Path`, bukan `r.RequestURI`).
- Validasi di titik konsumsi, bukan hanya di gerbang hulu: upgrader
  WebSocket memvalidasi `Origin` sendiri.
- Fail-closed: bila fungsi pemeriksa tidak terpasang/terlewati, tolak —
  jangan pernah "percaya gerbang depan sudah mengecek".

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai dev, petakan endpoint (`/me`, `/api/events`,
   `/api/send-test`). Coba handshake WebSocket lintas-origin
   (`Origin: https://evil.example` + cookie sesi) ke `/api/events`:
   hasilnya 403 — proteksi tampak aktif. Coba juga tanpa `Origin` (101)
   dan tanpa cookie (401).
2. **Probe**: variasikan *representasi* path yang sama — percent-encoding
   pada karakter/segmen berbeda, termasuk double-encoding sebagai kontrol
   negatif — dan cari representasi yang melewati gate Origin tetapi tetap
   ter-route ke handler WebSocket. Bandingkan status tiap varian:
   403 (gate menangkap), 404 (router tidak kenal), 101 (bypass).
3. **Eksploitasi**: pertahankan socket dari representasi yang lolos,
   picu email baru lewat `/api/send-test`, dan baca frame yang di-push
   server. Buktikan lewat `GET /api/events`.

### Deliverable

`exploit/exploit.py` (stdlib-only) mencetak kontrak:

```text
STATUS: 101
EVENT_ID: <id>
EVENT_SUBJECT: <subjek>
```

`EVENT_ID`/`EVENT_SUBJECT` adalah email yang bocor ke socket bajakanmu.
Verifier mencocokkannya dengan `GET /api/events`. Lihat `exploit/README.md`
untuk langkah yang disarankan.

## Fase 2 — Review & Fix

Baca `app/app.py`: temukan gate Origin di `do_GET`/`do_POST` — perhatikan
string apa yang diuji prefix-nya — lalu bandingkan dengan path yang dipakai
routing di bawahnya. Perhatikan juga bahwa `_handle_ws` sendiri tidak pernah
memvalidasi `Origin`.

Tulis perbaikan di `fix/app/app.py` (mirror path). Syarat: handshake menolak
`Origin` yang host-nya tidak cocok dengan `Host` (→ 403) pada **semua
representasi path**; tanpa `Origin` tetap diterima (klien non-browser).
Lihat `fix/README.md` untuk daftar fungsi normal yang harus tetap jalan.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifier 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix
./lab.sh stop     # hentikan
```

## Referensi

- Advisory: https://github.com/advisories/GHSA-8r62-w5wh-fc5m
- Advisory regresi (Lab 40): https://github.com/advisories/GHSA-524m-q5m7-79mm
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-67448
- PortSwigger Academy: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
