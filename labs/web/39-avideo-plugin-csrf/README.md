# Lab 39 — CSRF on Admin Plugin Config → Platform Takeover (AVideo CVE-2026-34394)

Sumber: [GHSA-4wwr-7h7c-chqr](https://github.com/advisories/GHSA-4wwr-7h7c-chqr)
(CVE-2026-34394, CVSS 8.1) — "CSRF on Admin Plugin Configuration Enables
Payment Credential Hijacking". Terdampak: WWBN/AVideo ≤ 26.0. Perbaikan yang
dianjurkan advisory: panggil `isGlobalTokenValid()` di `admin/save.json.php:10`,
tepat setelah pemeriksaan admin. Pelapor: aisafe.io.

## Skenario

Platform video ala AVideo. Satu administrator bawaan (`admin` / `admin-pw`)
mengelola konfigurasi plugin lewat panel admin: `PayPerView` (email penerima
PayPal, kunci Stripe), `AWS_S3` (bucket, kredensial), `LDAP` (server direktori).

Endpoint `POST /admin/save.json.php` menerima `pluginName` plus field-field
konfigurasi, lalu menulisnya langsung ke konfigurasi plugin tersebut dan
mengembalikan `{"success": true}`.

## Akar Masalah

Pola umumnya: **endpoint state-changing paling berkuasa tanpa validasi token
CSRF**. Aplikasi ini *punya* infrastruktur token CSRF (form resmi di
`/admin/plugin/edit` menyertakan `csrf_token` per sesi) — tetapi endpoint
`save.json.php` tidak pernah memanggilnya. Dua faktor memperparah:

- Cookie sesi dipasang dengan `SameSite=None`, sehingga cookie ikut terkirim
  di request lintas-origin — serangan CSRF menjadi trivial.
- Tidak ada allowlist key: semua field POST (selain `pluginName`) ditulis
  mentah ke konfigurasi plugin.

Bentuk aman dari pola yang sama:

- Setiap request state-changing memvalidasi token CSRF **tanpa kecuali** —
  fail-closed. Token hilang/tidak cocok → tolak, dalam kondisi apa pun.
- Cookie sesi pakai `SameSite=Lax` (atau `Strict`) kecuali ada alasan kuat.
- Field yang boleh ditulis dibatasi allowlist eksplisit per plugin.

Catatan seri: Lab 35 juga "tanpa token CSRF", tetapi rantai serangannya
berbeda — di sana request tempaan *membuat akun admin baru* (privesc langsung).
Di sini tidak ada akun yang disentuh: takeover terjadi lewat **penulisan ulang
konfigurasi** — satu request tempaan mengubah email penerima pembayaran,
kredensial storage, atau penyedia identitas. Takeover lewat konfigurasi,
bukan lewat akun.

## Fase 1 — Hacking

### Metodologi

1. **Baseline**: login sebagai admin, petakan endpoint (`/me`,
   `/admin/plugins`, `/admin/plugin/edit`, `/admin/save.json.php`). Catat
   bagaimana token CSRF diterbitkan dan di mana ia dipakai.
2. **Probe**: kirim request tempaan ala CSRF ke `save.json.php` — hanya cookie
   sesi, tanpa token. Amati mana yang ditolak dan mana yang lolos.
3. **Diferensial**: bandingkan perilaku endpoint ini dengan form resmi
   (`/admin/plugin/edit`): form resmi menyertakan token — endpoint-nya
   memeriksanya atau tidak?
4. **Eksploitasi**: dalam satu request tempaan (tanpa token valid), ubah
   `paypalReceiverEmail` plugin `PayPerView` menjadi alamat penyerang.
   Buktikan lewat `GET /admin/plugins`.

### Deliverable

`exploit/exploit.py` (stdlib-only) mencetak kontrak:

```text
STATUS: 200
PLUGIN: PayPerView
PAYPAL_EMAIL: <email-penyerang>
```

`PAYPAL_EMAIL` adalah alamat yang kamu tulis. Verifier mengambilnya dari
`GET /admin/plugins` dan memastikan nilainya benar-benar berubah dari bawaan.
Lihat `exploit/README.md` untuk langkah yang disarankan.

## Fase 2 — Review & Fix

Baca `app/app.py`: temukan handler `POST /admin/save.json.php` dan perhatikan
apa yang diperiksa sebelum data ditulis — dan apa yang *tidak* diperiksa.

Tulis perbaikan di `fix/app/app.py` (mirror path). Syarat: token CSRF selalu
divalidasi tanpa kecuali di endpoint ini; token hilang/tidak cocok → 403.
Lihat `fix/README.md` untuk daftar fungsi normal yang harus tetap jalan.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifier 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix
./lab.sh stop     # hentikan
```

## Referensi

- Advisory: https://github.com/advisories/GHSA-4wwr-7h7c-chqr
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-34394
- Seri CSRF fixthecode: Lab 35 (classic), Lab 36 (login CSRF + OAuth),
  Lab 37 (SameSite bypass), Lab 38 (penegakan kondisional)
