# Lab 24 — Apache 2.4.49 Path Traversal (CVE-2021-41773)

**Sumber:** Apache HTTP Server Project (advisory), NVD, disclosed HackerOne
report #1394916 (Internet Bug Bounty).

## Skenario

Sebuah server web **Apache HTTP Server 2.4.49** melayani aplikasi internal.
Konfigurasinya standar untuk zamannya:

- `DocumentRoot` melayani halaman utama (`/`).
- `ScriptAlias /cgi-bin/` dengan `mod_cgi` aktif melayani skrip CGI.

Versi 2.4.49 membawa perubahan pada fungsi normalisasi path
(`ap_normalize_path`) — dan perubahan itulah yang cacat. Targetmu:
membaca file di luar direktori web (bukti kanonis: `/etc/passwd`).

## Akar Masalah

**Pola umum: validasi sebelum canonicalization (check-then-decode).**

Alurnya yang rusak:

1. Server menerima segmen path seperti `.%2e` (dot + dot ter-encode).
2. Pemeriksaan `..` berjalan pada representasi **mentah** — `.%2e`
   tidak dikenali sebagai `..`, jadi lolos.
3. **Setelah** pemeriksaan, `%2e` didecode menjadi `.` — segmen berubah
   menjadi `..` dan berfungsi sebagai traversal sungguhan.

Check dan use melihat dua representasi berbeda dari input yang sama.
Ini keluarga besar bug yang sama: filter bekerja pada bentuk A,
eksekusi memakai bentuk B. Varian lainnya: double-encoding (`%252e`),
normalisasi Unicode, dan perbedaan decode antara dua lapisan
(mis. reverse-proxy vs backend).

**Bentuk aman dari pola yang sama:**

1. **Canonicalize dulu, validasi kemudian.** Decode penuh + normalisasi
   path sampai tidak ada lagi yang bisa berubah, BARU periksa hasilnya.
2. **Containment check, bukan blocklist.** Setelah canonical, buktikan
   path hasil resolve tetap di dalam direktori yang diizinkan. Jangan
   mengandalkan daftar encoding terlarang — selalu ada encoding lain.
3. **Deny-by-default.** `Require all denied` pada filesystem root, grant
   hanya direktori yang dibutuhkan. Bypass validasi pun gagal fail-closed.
4. **Upgrade.** Fix definitif upstream = 2.4.51. (2.4.50 sempat dirilis
   sebagai fix, ternyata tidak lengkap → CVE-2021-42013. Pelajaran
   tambahan: menambal pola encoding satu per satu kalah melawan
   canonicalization yang benar.)

Catatan sejarah: bug ini **hanya ada di 2.4.49** — versi sebelumnya tidak
punya perubahan normalisasi yang cacat itu. Perubahan "perbaikan" pada
kode parsing/normalisasi adalah sumber bypass klasik; setiap kali
normalizer disentuh, seluruh asumsi validasi di atasnya harus diuji ulang.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Petakan fungsi normal: `GET /` (halaman utama),
   `GET /cgi-bin/hello.sh` (CGI berjalan). Catat header `Server`
   untuk fingerprint versi.
2. **Probe.** Uji bagaimana server menangani segmen path yang tidak
   biasa pada path di bawah direktori yang di-alias (`ScriptAlias`) —
   khususnya dot yang ditulis dalam bentuk ter-encode.
3. **Diferensial.** Bandingkan respons path normal vs path dengan segmen
   ter-encode. Cari penanda bahwa respons berasal dari file di luar
   `DocumentRoot` (isi `/etc/passwd` selalu diawali `root:`).
4. **Eksploitasi.** Susun request yang memetakan URL ke file di luar
   direktori web, baca isinya, dan penuhi kontrak deliverable.

### Deliverable

Kontrak dengan verifier (`verify/verify.py`):

- `exploit.py` dieksekusi sebagai `python3 exploit/exploit.py` (tanpa argumen).
- Wajib mencetak ke stdout:
  - `STATUS: 200` — kode status HTTP dari respons serangan.
  - `MARKER: APACHE-TRAVERSAL-READ-OK` — **hanya** bila string `root:`
    benar-benar terlihat di body respons (bukti `/etc/passwd` terbaca).

## Fase 2 — Review & Fix

1. **Review** `apache/httpd.conf`. Temukan letak masalahnya: tidak ada
   proteksi default-deny pada filesystem root — file di luar direktori
   web tidak dilindungi `require all denied`, persis kondisi yang
   disebut advisory ("If files outside of these directories are not
   protected by 'require all denied', these requests can succeed").
2. **Fix** di `fix/apache/httpd.conf` (mirror path `apache/`):
   tambahkan `<Directory />` dengan `Require all denied`, dan pastikan
   direktori yang memang dibutuhkan (halaman utama, `cgi-bin`) tetap
   di-grant secukupnya.
3. Verifier me-rebuild dengan fix-mu: serangan referensi harus **gagal
   fail-closed** (bukan 200, marker hilang), sementara fungsi normal —
   halaman utama dan skrip CGI — tetap 200.
4. Catatan jujur: fix definitif di dunia nyata adalah upgrade ke
   ≥ 2.4.51. Di lab ini fix diwujudkan sebagai hardening config sesuai
   mitigasi resmi di advisory, karena itulah yang bisa diverifikasi
   otomatis (serangan → 403, fungsi normal utuh).

**Eskalasi nyata (tidak dicakup lab):** dengan `mod_cgi` aktif, celah
yang sama bisa dipakai untuk eksekusi perintah jarak jauh (RCE) —
itulah yang membuat CVE ini berstatus kritis. Primitif traversal-nya
tetap satu: path traversal.

## Perintah

```sh
./lab.sh start    # jalankan rakitan rentan di http://127.0.0.1:8080
./lab.sh stop     # hentikan
./lab.sh verify   # verifikasi 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan dengan fix/ learner (tanpa verifikasi)
```

## Referensi

- Apache HTTP Server Project — vulnerabilities 2.4:
  https://httpd.apache.org/security/vulnerabilities_24.html
- NVD — CVE-2021-41773:
  https://nvd.nist.gov/vuln/detail/CVE-2021-41773
- HackerOne report #1394916 (Internet Bug Bounty, disclosed):
  https://hackerone.com/reports/1394916
