# Lab 40 — Cross-Site WebSocket Hijacking tanpa validasi Origin (Mailpit CVE-2026-22689)

Sumber: [GHSA-524m-q5m7-79mm](https://github.com/advisories/GHSA-524m-q5m7-79mm)
(CVE-2026-22689, CVSS 6.5, CWE-1385) — "Cross-Site WebSocket Hijacking (CSWSH)
allowing unauthenticated access to message data". Terdampak: axllent/mailpit
< 1.28.2; diperbaiki di 1.28.2. Kode rentan: `server/websockets/client.go` —
`CheckOrigin: func(r *http.Request) bool { return true } // allow multi-domain`.
Perbaikan anjuran advisory: hapus `CheckOrigin` agar gorilla/websocket memakai
perilaku default yang aman (Origin harus cocok dengan Host).

## Skenario

Tool testing email ala Mailpit. Satu developer bawaan (`dev` / `dev-pw`).
Aplikasi menyiarkan event email baru lewat WebSocket di `GET /ws` — setiap ada
email masuk, semua klien socket yang terhubung menerima JSON berisi
pengirim, subjek, dan cuplikan isi. Endpoint `POST /api/send-test` memicu
email uji (mensimulasikan aktivitas normal).

Catatan: Mailpit asli bahkan tidak memakai autentikasi sama sekali — halaman
asing mana pun bisa connect. Lab ini memakai sesi login agar model CSWSH
klasik terlihat jelas: penyerang menunggangi cookie korban.

## Akar Masalah

Pola umumnya: **handshake WebSocket adalah request HTTP Upgrade** — browser
menempelkan cookie sesi korban seperti request biasa. Tanpa validasi header
`Origin` di handshake, halaman milik penyerang bisa membuka socket yang
terautentikasi sebagai korban: membaca semua pesan yang di-push server dan
mengirim pesan sebagai korban. Tidak seperti CSRF buta, penyerang mendapat
**saluran dua arah**.

Bentuk aman dari pola yang sama:

- Validasi `Origin` di setiap handshake: host-nya harus cocok dengan `Host`
  (perilaku default gorilla/websocket) atau ada di allowlist eksplisit.
- Tambahkan nilai tak-terduga (token CSRF) ke request handshake.
- Cookie `SameSite=Lax/Strict` sebagai pertahanan berlapis.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai dev, petakan endpoint (`/me`, `/api/events`,
   `/api/send-test`, `/ws`). Coba handshake WebSocket: apa yang terjadi tanpa
   cookie sesi? (Handshake WebSocket = HTTP biasa — kamu bisa melakukannya
   dengan socket mentah + header `Upgrade: websocket`.)
2. **Probe**: kirim handshake **dengan cookie sesi korban tetapi header
   `Origin: https://evil.example`** — mensimulasikan halaman jebakan.
   Bandingkan dengan handshake tanpa `Origin` (klien non-browser).
3. **Eksploitasi**: pertahankan socket bajakanmu tetap terbuka, picu email
   baru lewat `/api/send-test`, dan baca frame yang di-push server.
   Buktikan lewat `GET /api/events`.

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

Baca `app/app.py`: temukan fungsi handshake (`_handle_ws`) dan perhatikan apa
yang diperiksa sebelum `101 Switching Protocols` dikirim — dan apa yang
*tidak* diperiksa.

Tulis perbaikan di `fix/app/app.py` (mirror path). Syarat: handshake menolak
`Origin` yang host-nya tidak cocok dengan `Host` (→ 403); tanpa `Origin`
tetap diterima (klien non-browser). Lihat `fix/README.md` untuk daftar fungsi
normal yang harus tetap jalan.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifier 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix
./lab.sh stop     # hentikan
```

## Referensi

- Advisory: https://github.com/advisories/GHSA-524m-q5m7-79mm
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-22689
- PortSwigger Academy: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- Christian Schneider, "Cross-Site WebSocket Hijacking" (2013): https://christian-schneider.net/blog/cross-site-websocket-hijacking/
