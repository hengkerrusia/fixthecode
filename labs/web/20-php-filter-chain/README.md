# Lab 20 — PHP Filter Chain: LFI menjadi RCE (Synacktiv, 2022)

Aplikasi PHP me-render halaman dengan me-`include` parameter `page`
apa adanya — dan `include` mengeksekusi kode PHP apa pun yang ada di
stream yang di-include. Dengan merangkai filter `php://filter`,
LFI ini berubah menjadi RCE tanpa mengunggah satu file pun.

## Skenario

`halamanku`: aplikasi PHP kecil dengan satu endpoint
`GET /?page=<nilai>` yang me-include file halaman. Perilaku normalnya
wajar: `GET /` menampilkan halaman utama,
`?page=templates/about.php` menampilkan halaman tentang.

Bug-nya: nilai `page` diteruskan mentah ke `include`. Di PHP,
`include` bukan sekadar "baca file" — ia mengeksekusi setiap kode
PHP di dalam stream yang diberikan. Dan skema wrapper `php://filter`
memungkinkan penyerang mengubah isi stream *sebelum* `include`
melihatnya — termasuk menempa byte arbitrer dari resource kosong
(`php://temp`).

Konteks dunia nyata: teknik "PHP filter chain" dipublikasikan tim
riset Synacktiv (2022): LFI menjadi RCE tanpa upload file, tanpa
meracuni log — murni penyalahgunaan wrapper. Pola dasarnya
(`include` atas input user, CWE-98) adalah klasik yang tak pernah
mati di aplikasi PHP.

### Topologi

    learner → app (HTTP :8080, satu service; PHP built-in server)

## Akar Masalah

1. **Penyebab umum** — tiga lapis yang saling mengunci: (a) input
   yang sepenuhnya dikendalikan penyerang dioper langsung ke
   `include`/`require` → Local File Inclusion: penyerang memilih
   file apa yang dibaca/dieksekusi; (b) PHP memproses stream wrapper
   (`php://...`) di argumen `include`, sehingga
   `php://filter/<filter>/resource=<x>` menerapkan filter ke isi
   `<x>` sebelum hasilnya dieksekusi; (c) filter
   `convert.iconv.<dari>.<ke>` mengubah byte secara deterministik —
   dirangkai dengan tepat, rantai filter menempa byte arbitrer dari
   ketiadaan, dan karena `convert.base64-decode` mengabaikan karakter
   di luar alfabet base64, "sampah" hasil konversi hilang pada decode
   terakhir, menyisakan payload yang ditempa. Hasilnya: kode PHP
   pilihan penyerang tereksekusi tanpa satu file pun diunggah.
   Catatan: ini bukan RFI — `allow_url_include` tidak relevan,
   karena `php://filter` adalah wrapper lokal.
2. **Bentuk aman dari pola yang sama** — jangan pernah mengoper input
   mentah ke `include`/`require`. Petakan input ke allowlist nama
   halaman yang dikenal, tolak sisanya secara fail-closed (mis.
   respons 400). Allowlist menutup seluruh kelas LFI; sekadar
   memblokir skema wrapper (`://`) hanyalah tambalan yang lebih
   lemah.

## Fase 1 — Hacking (black-box)

Hanya berbekal README ini, tanpa membaca code.

### Metodologi

1. **Baseline** — `GET /` menampilkan halaman utama; catat juga
   perilaku `GET /?page=templates/about.php`. Pahami siklus normal:
   nilai `page` → halaman ter-render.
2. **Probe** — ke mana perginya nilai `page`? Coba isi dengan path
   absolut seperti `/etc/passwd`. Ingat: `include` mencetak isi
   file yang bukan PHP apa adanya — jadi file-read adalah probe
   termurah untuk membuktikan input-mu mencapai `include`.
3. **Diferensial** — bila file-read berhasil, uji apakah PHP juga
   memproses wrapper di parameter itu: coba
   `page=php://filter/convert.base64-encode/resource=templates/home.php`.
   Bila responsnya adalah base64 dari isi file, wrapper hidup — dan
   `include` akan mengeksekusi apa pun yang keluar dari filter.
4. **Eksploitasi** — rangkai filter chain yang hasil akhirnya adalah
   kode PHP pilihanmu (helper `exploit/fchain.py` merangkaikannya;
   tugasmu memilih payload dan mengantarkannya). Kirim lewat `page`
   — jangan lupa URL-encode, chain-nya panjang dan penuh karakter
   khusus. Buat payload-mu menulis marker ke `/tmp/PWNED.txt`,
   lalu buktikan lewat
   `docker compose exec app cat /tmp/PWNED.txt`.

### Deliverable

> `exploit/exploit.py` dieksekusi dan harus mencetak:
>
>     STATUS: 200
>     PWNED_PATH: /tmp/PWNED.txt
>     MARKER: <marker alfanumerik pilihanmu>
>
> Verifier menilai: (1) `STATUS` 200; (2) `PWNED_PATH` persis
> `/tmp/PWNED.txt`; (3) `MARKER` cocok pola `[A-Za-z0-9_-]`
> (maks 64 karakter); (4) isi `/tmp/PWNED.txt` di dalam container
> persis sama dengan `MARKER` — bukti kodemu benar-benar
> tereksekusi di server.

## Fase 2 — Review & Fix

Alur: baca code aplikasi → temukan letak & akar kerentanan → tulis
perbaikan di `fix/`.

File yang boleh diubah: `fix/app/index.php` (mirror dari
`app/index.php`; `Dockerfile` dan `templates/` juga ada di `fix/`
bila perbaikanmu menyentuhnya). Kriteria fix yang benar: serangan
referensi tidak lagi mengeksekusi kode (fail-closed — mis. 400, dan
tidak ada file yang tertulis), dan fungsi normal tetap utuh —
`GET /` dan `GET /?page=templates/about.php` tetap me-render
seperti semula.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi 2 fase
./lab.sh fix-up   # jalankan dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan
```

## Referensi

- Synacktiv — php_filter_chain_generator (2022): https://github.com/synacktiv/php_filter_chain_generator
- HackTricks — "LFI2RCE via php filters": https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters
