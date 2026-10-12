# Lab 21 — WordPress file inclusion (Robert Ressl, 2026)

CVE-2026-87902: local PHP file inclusion tanpa autentikasi di WordPress
4.7.0–7.1.1 (CVSS 4.0 9.2, Critical). Kombinasi `pagename` yang
di-encode dua kali dan `page_id` numerik membuat resolusi template
halaman meng-include file `.php` lokal di luar direktori tema. Pada
kondisi server tertentu (PEAR + `register_argc_argv=On`) inclusion ini
bisa diangkat menjadi RCE — di lab ini scope dibatasi ke primitif
file-read.

## Skenario

Target adalah mini-CMS yang meniru alur resolusi template halaman
WordPress: satu service Python di `localhost:8080`.

- `GET /` — halaman depan.
- `POST /page/` (atau `GET`) dengan parameter `pagename` dan `page_id`
  — me-render sebuah halaman. `page_id` numerik yang valid memilih
  halaman yang sudah terbit dan bisa diakses anonim; `pagename`
  dipakai untuk menentukan file template mana yang di-include.
- Di luar direktori tema ada file `.php` yang bisa dibaca berisi
  kredensial (simulasi `db-backup.php`), dengan baris marker
  `integrity marker: WP87902-FILE-READ-OK`.

Tidak ada akun, cookie, sesi, atau nonce yang dibutuhkan — serangan
penuh anonim, seperti temuan aslinya.

## Akar Masalah

**Penyebab umum — canonicalization is not containment.** Pola umumnya:
aplikasi membangun path file dari input user, menormalisasinya dengan
`realpath()`, lalu memeriksa hasil normalisasi (file ada? ekstensi
benar? bisa dibaca?) — tetapi tidak pernah *membuktikan* bahwa path
hasil normalisasi tetap berada di dalam direktori yang dimaksud.
`realpath()` menjawab "path ini menunjuk ke mana", bukan "apakah
tujuan ini termasuk direktori yang saya percayai". Dua pertanyaan itu
berbeda, dan hanya yang kedua yang menjadi batas keamanan.

Di kasus ini ada lapisan kedua yang membuat input berbahaya lolos:
**decode berlapis.** Nilai `pagename` di-decode satu kali saat request
di-parsing (pada titik ini karakter yang masih ter-encode tidak
dianggap sebagai separator path), lalu di-decode *sekali lagi* oleh
fungsi resolusi template — dan barulah separator hasil decode menjadi
sintaks path aktif. Tiap tahap menerima nilai yang terlihat aman bagi
tahap itu, tetapi berbahaya bagi tahap berikutnya. Ditambah keanehan
pemilihan halaman: `page_id` yang valid memilih halaman asli,
sementara `pagename` yang jahat tetap tersimpan dan dipakai untuk
penamaan template — dua keputusan yang *divergen* dari dua parameter
yang datang bersamaan.

**Bentuk aman dari pola yang sama:**

1. Setelah canonicalization, lakukan *containment check*: buktikan
   path hasil resolve berada di dalam direktori yang diizinkan
   (mis. bandingkan `commonpath` atau prefix direktori + separator),
   dan tolak secara fail-closed bila tidak.
2. Decode tepat satu kali di boundary input; jangan pernah decode
   ulang nilai yang sudah melewati validasi.
3. Untuk penamaan template, lebih aman memakai allowlist nama
   template yang dikenal daripada membangun path dari string bebas.

## Fase 1 — Hacking (black-box)

Hanya berbekal README ini, tanpa membaca code.

### Metodologi

1. **Baseline** — pahami perilaku normal: `GET /`, `POST /page/`
   dengan `pagename=hello-world&page_id=1` (halaman ter-render dari
   template bawaan tema), dan `page_id` yang tidak valid (404).
2. **Probe** — kirim varian `pagename`: nama biasa, path absolut,
   traversal `../` polos, traversal yang di-encode satu kali, dua
   kali. Catat kapan respons tetap template bawaan dan kapan berubah.
   Perhatikan berapa kali encoding-mu "terkupas" sepanjang jalan.
3. **Diferensial** — temukan bentuk `pagename` yang membuat server
   me-render konten yang *bukan* dari direktori tema.
4. **Eksploitasi** — rangkai menjadi serangan penuh: dengan
   `page_id` valid + `pagename` yang tepat, baca file `.php` di luar
   direktori tema dan ekstrak marker-nya.

Petunjuk: kirim request mentah (tanpa auto-encoding dari library
HTTP) supaya kamu memegang kendali penuh atas encoding tiap karakter.

### Deliverable

`exploit/exploit.py` dieksekusi dan harus mencetak:

```text
STATUS: 200
MARKER: WP87902-FILE-READ-OK
```

Verifier menilai: baris `STATUS` harus `200`, dan `MARKER` harus persis
sama dengan marker di dalam file target. Sebelum menilaimu, verifier
menjalankan serangan referensi milik builder sebagai health check —
gagal di sana berarti lab-nya yang rusak, bukan kamu.

## Fase 2 — Review & Fix

Alur: baca code aplikasi (`app/server.py`) → temukan letak & akar
kerentanan → tulis perbaikan di `fix/app/server.py`.

Kriteria fix yang benar: serangan referensi digagalkan secara
fail-closed (respons 400, marker tidak bocor), dan fungsi normal tetap
utuh (`GET /`, halaman normal, 404 untuk `page_id` invalid).

Catatan stretch goal (opsional, tidak dinilai): di WordPress asli,
primitif inclusion ini bisa diangkat menjadi eksekusi kode via
`pearcmd.php` bila PEAR terinstal dan `register_argc_argv=On` —
dengan request pertama menulis file PHP terkontrol, request kedua
meng-include-nya. Lab ini tidak mereproduksi rantai RCE tersebut
(tidak ada runtime PHP/PEAR di image); scope yang dinilai adalah
file-read + fix containment.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi 2 fase
./lab.sh fix-up   # jalankan dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan
```

## Referensi

- Robert Ressl, "CVE-2026-87902: Critical WordPress file inclusion and conditional RCE" (2026-09-22) — https://ressl.ch/blog/cve-2026-87902-wordpress/
- WordPress security advisory GHSA-7hp8-65ch-5whp — versi terdampak 4.7.0–7.1.1, diperbaiki di 7.1.2 / 7.0.6 (backport sampai 4.7)
