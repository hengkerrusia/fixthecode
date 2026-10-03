# Lab 7 — Chunked Smuggling ala CVE-2025-65114 (ATS)

## Latar belakang

CVE-2025-65114 adalah kerentanan *request smuggling* di **Apache Traffic
Server** (ATS), dilaporkan oleh Katsutoshi Ikenoya, dipublikasikan
2 April 2026. Deskripsi resminya satu baris: *"Apache Traffic Server
allows request smuggling if chunked messages are malformed."*
(CWE-444: Inconsistent Interpretation of HTTP Requests.)

Versi terdampak: ATS 9.0.0–9.2.12 dan 10.0.0–10.1.1. Diperbaiki di
9.2.13 / 10.1.2 lewat commit *"Fix prev_is_cr flag handling in chunked
encoding parser"* di `proxy/http/HttpTunnel.cc`.

Akar masalahnya ada di `ChunkedHandler::read_size()`, fungsi yang
mengurai baris ukuran chunk (`5\r\n`, `0\r\n`, ...). Fungsi ini memakai
flag `prev_is_cr` untuk mengingat "apakah karakter sebelumnya adalah
CR" -- dipakai untuk memvalidasi bahwa setiap baris benar-benar
diakhiri CRLF, bukan LF telanjang. Bug-nya: flag itu di-*assign* di
dalam ekspresi kondisional (`if ((prev_is_cr = is_cr(c)) == true)`),
sehingga **tidak selalu diupdate** -- ia menjadi basi (*stale*) antar
iterasi parsing. Patch-nya sederhana: update flag di *setiap* akhir
iterasi loop agar selalu mencerminkan karakter terakhir yang dibaca.

Akibat bug: ATS **menerima** chunked body yang malformed -- yang
seharusnya ditolak (koneksi diputus) -- sehingga batas-batas request
ditafsir berbeda dari semestinya dan request selundupan lolos ke
origin.

Trigger yang dipakai regression test ATS sendiri:

```text
Transfer-Encoding: chunked

1\r\n\r\n0\r\n\r\n
```

dibaca: chunk-size `1`, tapi **nol byte** chunk-data (langsung `\r\n`),
lalu chunk terakhir `0\r\n\r\n`. Parser yang benar menolak ini
("LF tanpa CR yang mendahului"); parser ATS yang buggy menerimanya
diam-diam.

Lab ini mengemulasi logika parser tersebut (disederhanakan) di
`proxy/chunked.py`. Emulasinya setia pada mekanisme bug -- flag
`prev_is_cr` yang basi -- bukan salinan baris-per-baris kode C++ ATS.

## Topologi

```text
klien --TCP--> proxy:8080 --TCP--> backend:8000
```

- **proxy** (python, `proxy/proxy.py` + `proxy/chunked.py`): reverse
  proxy. Untuk request `Transfer-Encoding: chunked`, ia mengurai body
  dengan parser di `chunked.py`. Jika parsing gagal -> **400** dan
  koneksi diputus (inilah gerbang keamanannya). Jika lolos, body
  di-*dechunk* lalu diteruskan ke backend sebagai `Content-Length`
  biasa. Mendukung pipelining: request berikutnya di koneksi yang sama
  ikut diteruskan.
- **backend** (python, `backend/app.py`): origin biasa. `GET /` dan
  `POST /submit` -> 200; `GET /admin` -> 200 + `ADMIN-SECRET`
  (endpoint internal, tanpa proteksi sendiri).

## Fase 1 — Hacking (black-box)

Tujuan: selundupkan request kedua ke backend **melewati gerbang
validasi proxy**. Proxy yang benar akan menjawab 400 dan memutus
koneksi saat melihat chunked body yang malformed -- request keduamu
tidak akan pernah sampai ke backend.

Langkah yang disarankan:

1. **Baseline.** Kirim `POST /submit` dengan `Transfer-Encoding:
   chunked` dan body yang well-formed (`5\r\nhello\r\n0\r\n\r\n`).
   Harus 200. Ini memastikan kamu bisa ngomong chunked ke proxy.
2. **Petakan validasinya.** Coba body yang jelas rusak (mis. ukuran
   chunk `z`, bukan hex). Proxy menjawab 400 -- validasi jalan.
3. **Uji ketegasan parser.** Parser yang "ketat di kata, longgar di
   perbuatan" biasanya punya celah di kasus tepi: chunk-size tanpa
   chunk-data, LF telanjang di posisi yang tak terduga, dan
   sejenisnya. Cari satu framing malformed yang **diterima** (200),
   bukan ditolak.
4. **Selundupkan.** Setelah framing malformed yang diterima ketemu,
   pipeline request kedua (`GET /admin`) tepat setelah body itu dalam
   **satu koneksi**. Kalau gerbangnya jebol, proxy meneruskan
   keduanya; kalau tidak, koneksi diputus di request pertama.
5. **Buktikan.** Baca DUA respons dari koneksimu: respons pertama
   (untuk POST) dan respons kedua (untuk request selundupan).
   Klaim `STATUS` dari respons **kedua**, bukan yang pertama.

Deliverable: `exploit/exploit.py` mencetak `STATUS` + `SMUGGLED_PATH`
(lihat `exploit/README.md`). Verifier melakukan serangan ulang sendiri
dan hanya lulus jika backend benar-benar mengeksekusi request kedua.

## Fase 2 — Review & Fix

Baca `proxy/chunked.py`. Cari di mana flag pelacak CR diupdate -- dan
di mana ia **lupa** diupdate. Perbaikannya meniru patch upstream:
pastikan flag selalu mencerminkan karakter terakhir di setiap langkah
parsing, sehingga framing malformed ditolak alih-alih diterima.

Tulis perbaikanmu di `fix/proxy/chunked.py`, lalu `./lab.sh verify`.
Fase 2 lulus jika serangan referensi gagal total (request malformed ->
400, koneksi diputus, request kedua tak dieksekusi) sementara
`POST /submit` chunked yang well-formed dan `GET /` tetap 200.

## Referensi

- CVE-2025-65114 — "Malformed chunked message body allows request
  smuggling", ATS 9.0.0–9.2.12 / 10.0.0–10.1.1, fixed 9.2.13 / 10.1.2.
- Patch: apache/trafficserver, "Fix prev_is_cr flag handling in
  chunked encoding parser" (`proxy/http/HttpTunnel.cc`).
- Regression test upstream memakai body `1\r\n\r\n0\r\n\r\n`
  ("chunk-size is set to 1, but no chunk-data is present").
