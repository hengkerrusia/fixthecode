# Lab 38 — CSRF & Validation Bypass via Attacker-Controlled Flag (Admidio CVE-2026-34383)

Sumber: [GHSA-4rwm-c5mj-wh7x](https://github.com/advisories/GHSA-4rwm-c5mj-wh7x)
(CVE-2026-34383, CVSS 4.3) — "Admidio has CSRF and Form Validation Bypass in
Inventory Item Save via `imported` Parameter". Terdampak: admidio/admidio
≤ 5.0.7; diperbaiki di 5.0.8 (commit `00494b9`). Pelapor: @offset.

## Skenario

Aplikasi inventory web (ala modul inventory Admidio). Satu manager bawaan
(`manager` / `manager-pw`) mengelola daftar barang lewat panel web. Setiap
form state-changing dilindungi token CSRF per sesi, dan server memvalidasi
tiap field sebelum menyimpan.

Endpoint `POST /inventory/item_save` menerima satu parameter tambahan,
`imported`, yang semula dimaksudkan untuk jalur impor data. Masalahnya:
nilai parameter ini **dibaca langsung dari request penyerang**. Ketika
`imported=1`, server melewati *seluruh* pemeriksaan token CSRF **dan**
seluruh validasi form — lalu menyimpan mentah nilai POST ke database.

## Akar Masalah

Pola umumnya: **penegakan keamanan yang bersifat kondisional terhadap input
penyerang**. Aplikasinya *punya* token CSRF dan *punya* validasi server-side —
keduanya benar secara individual. Tetapi sebuah flag (`imported`) yang
nilainya dikontrol penyerang memutuskan apakah kedua pemeriksaan itu
dijalankan. Akibatnya proteksi yang terlihat kokoh dari luar bisa dimatikan
penuh lewat satu parameter.

Bentuk aman dari pola yang sama:

- Security check (validasi token CSRF, validasi input) berjalan **tanpa
  syarat** di setiap request state-changing — fail-closed. Flag request
  tidak boleh mengendalikan *apakah* check dijalankan.
- Kalau sebuah alur (mis. impor) memang butuh perilaku khusus, tandai alur
  itu lewat **state server-side** (mis. variabel sesi yang diset selama
  proses impor), bukan lewat parameter yang bisa ditulis penyerang di
  request buatannya sendiri.
- Aturan praktis: parameter request boleh mengatur *alur fitur*, tidak boleh
  mengatur *penegakan keamanan*.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai manager, petakan endpoint (`/me`,
   `/inventory`, `/inventory/new`, `/inventory/item_save`). Catat bagaimana
   token CSRF diterbitkan dan dipakai; catat aturan validasi field (coba
   nilai benar vs salah).
2. **Probe**: kirim request tempaan ala CSRF — hanya cookie sesi, tanpa token
   valid. Amati mana yang ditolak (403) dan mana yang lolos.
3. **Diferensial**: uji parameter-parameter boolean pada endpoint
   `item_save`. Bandingkan perilaku validasi (apakah 400 untuk quantity
   invalid?) dengan dan tanpa parameter tersebut. Satu parameter mengubah
   *dua* perilaku sekaligus — itu sinyalnya.
4. **Eksploitasi**: dalam satu request tempaan (tanpa token valid), buat item
   dengan nilai yang pasti ditolak validasi normal. Buktikan lewat
   `GET /inventory`.

### Deliverable

`exploit/exploit.py` (stdlib-only) mencetak kontrak:

```text
STATUS: 200
ITEM_ID: <id>
```

`ITEM_ID` menunjuk item yang kamu tempa. Verifier mengambilnya dari
`GET /inventory` dan memastikan quantity-nya **invalid** (negatif atau bukan
integer) — sesuatu yang mustahil lolos validasi normal. Lihat
`exploit/README.md` untuk langkah yang disarankan.

## Fase 2 — Review & Fix

Baca `app/app.py`: temukan di mana nilai `imported` dibaca, dan apa yang
terjadi di cabang `imported=1` vs cabang normal. Perhatikan dua hal yang
dilewati sekaligus.

Tulis perbaikan di `fix/app/app.py` (mirror path). Syarat: token CSRF selalu
divalidasi tanpa kecuali; validasi form selalu berjalan; flag request tidak
mengendalikan penegakan keamanan. Lihat `fix/README.md` untuk daftar fungsi
normal yang harus tetap jalan.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifier 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix
./lab.sh stop     # hentikan
```

## Referensi

- Advisory: https://github.com/advisories/GHSA-4rwm-c5mj-wh7x
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-34383
- Fix commit: https://github.com/Admidio/admidio/commit/00494b95dfe847af8b938e4397e5d909d8f36839
- Seri CSRF fixthecode: Lab 35 (classic), Lab 36 (login CSRF + OAuth),
  Lab 37 (SameSite bypass)
