# Lab 19 — Zip Slip (Snyk Research 2018, CVE-2018-1002203)

Layanan upload-and-extract mengekstrak arsip `.zip` ke direktori target —
tapi nama entry di dalam arsip tidak divalidasi, sehingga entry `../`
menulis file ke luar direktori target (arbitrary file write).

## Skenario

`arsipku`: layanan kecil untuk mengunggah arsip dan mengekstraknya.
`POST /upload` menerima byte mentah sebuah `.zip` lalu mengekstrak tiap
entry-nya ke `/data/uploads`; `GET /files/<nama>` mengembalikan file yang
sudah diekstrak. Bug-nya ada di kode ekstraksi: nama entry arsip
digabung ke direktori target tanpa pemeriksaan.

Konteks dunia nyata: Snyk (2018) menemukan pola ini di banyak ekosistem
— JavaScript, Ruby, .NET, Go, dan terutama Java. Instance konkretnya:
`unzipper` (npm) sebelum 0.8.13 menulis entry arsip ke luar direktori
tujuan (CVE-2018-1002203, CVSS 9.4 Critical; fixed di 0.8.13).

### Topologi

    learner → app (HTTP :8080, satu service)

## Akar Masalah

1. **Penyebab umum** — kode ekstraksi arsip menggabungkan nama entry
   (input yang sepenuhnya dikendalikan penyerang) ke direktori target
   tanpa memvalidasi bahwa hasil akhirnya tetap berada di dalam
   direktori tersebut. Format arsip mengizinkan nama entry arbitrer —
   `../../x`, path absolut, nama aneh — dan aplikasi arsip normal
   memang tidak pernah membuatnya, tapi penyerang bebas membuatnya.
   `../` di nama entry "membawa" file keluar dari direktori target
   saat digabung dengan `path.join` (atau konkatenasi string).
   Ini bukan bug pada format zip-nya; bug-nya ada pada kode yang
   menaruh entry ke disk tanpa containment check.
2. **Bentuk aman dari pola yang sama** — untuk setiap entry: resolve
   path hasil penggabungan terhadap direktori target, lalu pastikan
   hasilnya masih berada di dalam direktori target (containment
   check). Entry yang lolos harus ditolak secara fail-closed
   (tolak seluruh upload, atau lewati entry tersebut) — jangan
   pernah menulisnya. Catatan hardening: pola yang sama berlaku
   untuk symlink di dalam arsip; perlakukan entry symlink dengan
   curiga.

## Fase 1 — Hacking (black-box)

Hanya berbekal README ini, tanpa membaca code.

### Metodologi

1. **Baseline** — `GET /` menampilkan form; buat zip normal berisi
   satu file (`hello.txt`), `POST` ke `/upload`, pastikan `200`,
   lalu baca kembali via `GET /files/hello.txt`. Pahami siklus
   normal: upload → ekstrak → baca.
2. **Probe** — apa yang terjadi bila nama entry bukan nama biasa?
   Coba entry bernama `../PWNED.txt`, atau `a/../../PWNED.txt`,
   atau path absolut. Ke mana file-nya "pergi"?
3. **Diferensial** — bandingkan dengan baseline: file normal mendarat
   di `/data/uploads/`, sedangkan entry `../` mendarat di luar itu.
   Buktikan dengan membaca filesystem container:
   `docker compose exec app cat /data/PWNED.txt`.
4. **Eksploitasi** — rangkai menjadi serangan penuh: satu zip, satu
   entry `../PWNED.txt` berisi marker pilihanmu, satu request.
   File harus tertulis di `/data/PWNED.txt` dengan isi persis
   marker-mu.

### Deliverable

> `exploit/exploit.py` dieksekusi dan harus mencetak:
>
>     STATUS: 200
>     ESCAPED_PATH: /data/PWNED.txt
>     MARKER: <marker alfanumerik pilihanmu>
>
> Verifier menilai: (1) `STATUS` 200; (2) `ESCAPED_PATH` persis
> `/data/PWNED.txt`; (3) `MARKER` alfanumerik; (4) isi file
> `/data/PWNED.txt` di dalam container persis sama dengan `MARKER`
> — bukti tulisanmu benar-benar lolos ke luar direktori target.

## Fase 2 — Review & Fix

Alur: baca code aplikasi → temukan letak & akar kerentanan → tulis
perbaikan di `fix/`.

File yang boleh diubah: `fix/app/server.js` (mirror dari
`app/server.js`; `Dockerfile` dan `package.json` juga ada di `fix/`
bila perbaikanmu menyentuhnya). Kriteria fix yang benar: zip berisi
entry `../PWNED.txt` tidak boleh menulis apa pun ke luar direktori
target (fail-closed), dan fungsi normal tetap utuh — zip biasa tetap
terekstrak dan bisa dibaca kembali.

## Perintah

```bash
./lab.sh start    # jalankan lab (rentan)
./lab.sh verify   # verifikasi 2 fase
./lab.sh fix-up   # jalankan dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan
```

## Referensi

- Snyk — "Zip Slip Vulnerability" (2018): https://security.snyk.io/research/zip-slip-vulnerability
- CVE-2018-1002203 — Arbitrary File Write via Archive Extraction in `unzipper`: https://security.snyk.io/vuln/npm:unzipper:20180415
