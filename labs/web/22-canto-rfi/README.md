# Lab 22 — Canto Remote File Inclusion (CVE-2023-3452)

Sumber: Wordfence Threat Intelligence, peneliti Marco Wotschka (2023-08-09).
Plugin Canto untuk WordPress ≤ 3.0.4 rentan terhadap *remote file inclusion*
tanpa autentikasi melalui parameter `wp_abspath` — CVSS 9.8.

## Skenario

Target adalah simulasi endpoint plugin galeri media ("Canto") yang ditulis
dengan PHP dan dijalankan di atas server bawaan PHP. Endpoint
`/includes/lib/get.php` menerima parameter `subdomain` dan `wp_abspath`,
lalu me-*render* halaman media library.

Di suatu tempat di dalam alur itu, aplikasi menyusun path sebuah file
yang akan di-*include* dengan menempelkan input pengguna. Konfigurasi PHP
di lab ini secara eksplisit mengaktifkan `allow_url_include=On` — sebuah
*misconfiguration* (nilai default PHP modern adalah `Off`).

Tugasmu: dari luar, tanpa kredensial apa pun, buktikan kamu bisa
mengeksekusi kode di server dalam satu request.

## Akar Masalah

Pola umumnya: **membangun path `include`/`require` dari input pengguna
yang tidak divalidasi.**

```php
require_once($_GET['wp_abspath'] . '/wp-admin/admin.php');
```

Bila `allow_url_include` aktif, argumen `include`/`require` tidak harus
berupa path lokal — ia bisa berupa URL (`http://...`) atau *wrapper*
seperti `data://`. Artinya input pengguna tidak lagi sekadar memilih
*file mana*, melainkan *kode apa* yang dijalankan. Inilah bedanya LFI
dengan RFI: pada RFI, attacker membawa kodenya sendiri.

Bentuk aman dari pola yang sama:

- Jangan pernah menyusun path include dari input pengguna. Pakai path
  yang di-*hardcode* atau peta allowlist (`$templates[$name]`).
- Pastikan `allow_url_include=Off` (default). Opsi ini hampir tidak pernah
  dibutuhkan aplikasi modern.
- Bila sebuah parameter hanya dipakai untuk konfigurasi path, validasi
  ketat terhadap daftar nilai yang dikenal — bukan sekadar menolak pola
  yang terlihat jahat.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Buka `/` dan `/includes/lib/get.php`. Catat respons
   normal: status, isi halaman, dan parameter apa saja yang diterima.
2. **Probe.** Uji parameter `wp_abspath`: apa yang terjadi bila nilainya
   diubah? Respons mana yang menunjukkan nilaimu ikut dipakai?
3. **Diferensial.** Setelah yakin parameter itu mengalir ke operasi
   *include*, uji dua hal: (a) apakah path lokal bisa dibaca (LFI), dan
   (b) apakah wrapper URL dieksekusi (RFI). Perbedaan responsnya adalah
   petunjuk konfigurasi server.
4. **Eksploitasi.** Dengan `allow_url_include=On`, wrapper `data://`
   memungkinkan kamu menanam kode PHP langsung di dalam URL — tanpa
   perlu meng-host file di server lain. Perhatikan: aplikasi menempelkan
   sufiks `/wp-admin/admin.php` di belakang nilaimu. Pikirkan bagaimana
   membuat sufiks itu tidak merusak kodemu (misalnya dengan menutup tag
   PHP lebih dulu, sehingga sisanya hanya menjadi teks biasa).
   Buktikan eksekusi kode dengan membaca `/flag.txt` di server.

### Deliverable

Skrip `exploit/exploit.py` kamu dieksekusi verifier tanpa argumen dan
wajib mencetak tepat dua baris:

```
STATUS: 200
MARKER: CANTO-RFI-RCE-OK
```

Baris `MARKER:` hanya boleh dicetak bila string `CANTO-RFI-RCE-OK`
benar-benar muncul di body respons HTTP yang diterima skripmu —
yakni hasil perintah yang kamu eksekusi di server membaca `/flag.txt`.

## Fase 2 — Review & Fix

1. Baca kode aplikasi di `app/`. Temukan di mana input pengguna mengalir
   ke operasi *include*, dan mengapa itu berbahaya.
2. Tulis perbaikan di `fix/` (mirror path `app/`). Perbaikan yang benar
   bersifat *fail-closed*: input yang tidak tepercaya tidak boleh lagi
   menentukan file apa yang di-*include*.
3. Verifier me-rebuild lab dengan fix-mu: serangan referensi harus gagal
   (marker tidak muncul), dan fungsi normal (`/`, halaman media library)
   harus tetap utuh.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh stop     # hentikan
./lab.sh verify   # verifikasi 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan dengan fix/ milikmu
```

## Referensi

- Wordfence Threat Intelligence — Canto ≤ 3.0.4 Unauthenticated Remote
  File Inclusion (Marco Wotschka, 2023-08-09):
  https://www.wordfence.com/threat-intel/vulnerabilities/id/a76077c6-700a-4d21-a930-b0d6455d959c
- NVD — CVE-2023-3452: https://nvd.nist.gov/vuln/detail/CVE-2023-3452
- PHP Manual — `allow_url_include`:
  https://www.php.net/manual/en/filesystem.configuration.php
- PHP Manual — wrapper `data://`:
  https://www.php.net/manual/en/wrappers.data.php
