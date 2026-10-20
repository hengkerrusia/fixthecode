# Lab 42 — Bokeh: CSWSH via Allowlist Prefix-Match

**Sumber:** GitHub Advisory GHSA-793v-589g-574v — "Bokeh server applications
have Incomplete Origin Validation in WebSockets" (CVE-2026-21883,
CWE-1385, CVSS 3.1: 5.4). Terdampak: Bokeh < 3.8.2; diperbaiki di 3.8.2
(commit `cedd113b0e271b439dce768671685cf5f861812e`). Lab ini memodelkan
mekanisme validasi Origin-nya secara setia dengan Python stdlib.

Dua lab sebelumnya (40, 41) soal WebSocket tanpa pemeriksaan Origin yang
benar. Lab ini beda: pemeriksaannya **ada** dan **tampak bekerja** — Origin
asing ditolak. Yang rusak adalah logika pencocokan polanya.

## Skenario

Sebuah server visualisasi data ala Bokeh menyajikan dashboard lewat
WebSocket. Dashboard itu dirancang untuk di-embed di portal internal
perusahaan, jadi server dikonfigurasi dengan allowlist Origin:

```
ALLOWLIST = ["portal.corp", "127.0.0.1:8080"]
```

Artinya hanya halaman dari `portal.corp` (dan alamat server sendiri) yang
boleh membuka koneksi WebSocket. Sesi pengguna ditandai cookie `session`,
dan lewat WebSocket yang sama pengguna menerima event dashboard secara
real-time.

Persoalannya: fungsi pencocok pola host di server membandingkan host dan
pola **per label** (pecahan titik) memakai `zip()`. Karena `zip()` berhenti
di urutan terpendek, dan kode hanya menolak bila pola **lebih panjang**
dari host, pola cocok sebagai **awalan**: host `portal.corp.evil.example`
dianggap cocok dengan pola `portal.corp`. Halaman jahat di domain
look-alike itu pun lolos pemeriksaan Origin — Cross-Site WebSocket
Hijacking (CSWSH), padahal allowlist-nya aktif.

## Akar Masalah

Pencocokan identitas keamanan tidak boleh memakai semantik prefix:
kecocokan sebagian **bukan** kecocokan. Pola `portal.corp` adalah nama host
yang utuh, bukan awalan — ia hanya boleh cocok dengan host yang persis
sama, label demi label, sampai habis. Semantik awalan pada identitas
(host, Origin, path, token) hampir selalu berubah menjadi bypass, karena
penyerang bebas menempelkan label/segmen tambahan di belakang identitas
yang sah.

Bentuk aman dari pola yang sama:

- Pola non-wildcard hanya cocok bila jumlah label **persis sama** dan
  seluruh label cocok — persis perbaikan upstream Bokeh 3.8.2: tambahan
  pemeriksaan `len(pattern_parts) != len(host_parts)` → tidak cocok.
- Kecocokan subdomain harus **disengaja** lewat wildcard eksplisit
  (`*.portal.corp`), bukan muncul sebagai efek samping implementasi.
- Dan jangan lupa contoh negatif saat menguji: proteksi yang hanya diuji
  dengan Origin asing biasa akan terlihat berfungsi, padahal varian
  look-alike lolos.

## Fase 1 — Hacking

### Metodologi

- **Baseline.** Login sebagai `dev` / `dev-pw` dari panel di `/`. Sesi
  tersimpan di cookie `session`. Buka `GET /api/events` untuk melihat
  daftar event (oracle), dan `POST /api/send-test` untuk memicu event.
- **Probe.** Lakukan handshake WebSocket mentah ke `GET /api/events`
  (header `Upgrade: websocket` + `Sec-WebSocket-Key`) memakai cookie
  korban, dari beberapa varian Origin. Catat: tanpa Origin → 101; Origin
  asing (`https://evil.example`) → 403 (proteksi tampak aktif); Origin
  look-alike berupa host yang diizinkan ditambah label di belakangnya
  (`http://portal.corp.evil.example`) → 101; Origin yang bukan awalan
  (`http://corp.evil.example`) → 403.
- **Diferensial.** Hanya varian look-alike yang lolos dari seluruh Origin
  cross-site. Itulah buktinya: pemeriksaan Origin berjalan, tetapi
  pencocokan polanya berhenti di awalan.
- **Eksploitasi.** Dari halaman "penyerang" (disimulasikan skripmu),
  handshake WebSocket dengan Origin look-alike + cookie korban akan
  diterima (101). Pemicu event dengan subjek acak lewat sesi korban, baca
  event yang tiba di koneksi WebSocket itu, dan konfirmasi subjeknya
  muncul di `GET /api/events`. Browser asli akan mengirim cookie korban
  pada handshake cross-origin persis seperti skripmu mengirimkannya —
  WebSocket tidak tunduk pada same-origin policy.

### Deliverable

`exploit/exploit.py` — skrip Python 3 (stdlib saja; handshake WebSocket
dibangun manual lewat socket) yang membaca `BASE_URL` dari env (default
`http://127.0.0.1:8080`), login sebagai korban, melakukan serangan di
atas, lalu mencetak:

```
STATUS: 101
EVENT_ID: <id event yang diterima>
EVENT_SUBJECT: <subjek event yang diterima>
```

Verifier menjalankan skrip ini terhadap app rentan (harus berhasil) dan
terhadap app hasil fix-mu (harus gagal).

## Fase 2 — Review & Fix

Baca `app/app.py`, khususnya fungsi `match_host()` dan
`check_allowlist()`: perhatikan bagaimana `zip()` atas label host dan
label pola membuat pola yang lebih pendek selalu cocok sebagai awalan,
dan tidak ada pemeriksaan kesetaraan jumlah label.

Tulis perbaikanmu di `fix/app/app.py` mengikuti pola upstream (3.8.2):
pola cocok hanya bila jumlah label host dan pola sama (di luar wildcard
eksplisit `*`). Setelah fix, verifier memeriksa:

- Handshake dengan Origin asing → 403, dan dengan Origin look-alike → 403.
- Login tetap berfungsi.
- Handshake dari `http://portal.corp` → 101 dan tetap menerima event.
- Handshake dengan Origin alamat server sendiri → 101.
- Handshake tanpa Origin → 101 (klien non-browser tidak punya Origin;
  memblokirnya merusak fungsi yang sah dan bukan itu akar masalahnya).

## Perintah

```bash
./lab.sh up        # mode rentan (docker compose up -d --build)
./lab.sh verify    # jalankan verifier dua fase
./lab.sh down      # matikan & bersihkan
```

Atau langsung: `python3 verify/verify.py` dari folder lab ini
(`--phase1-only` / `--phase2-only` untuk satu fase).

## Referensi

- Advisory: https://github.com/advisories/GHSA-793v-589g-574v
- Perbaikan upstream (Bokeh 3.8.1 → 3.8.2, `src/bokeh/server/util.py`):
  commit `cedd113b0e271b439dce768671685cf5f861812e`
- CWE-1385: Missing Origin Validation in WebSockets
