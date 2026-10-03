# Lab 8 — CL.TE Request Smuggling → Cache Poisoning → Stored XSS (PayPal)

## Latar belakang

HackerOne [#488147](https://hackerone.com/reports/488147) — *"Stored XSS
on https://paypal.com/signin via cache poisoning"*, dilaporkan oleh
albinowax (James Kettle), 2019, bounty **$18.900**. Ringkasan dari
PayPal sendiri: penyerang *"use request smuggling to convert a page
request into a cached redirect"* — request smuggling dipakai untuk
mengubah request halaman biasa menjadi sesuatu yang ter-cache,
sehingga konten penyerang tersaji sebagai halaman sign-in paypal.com:
stored XSS.

Ini rantai tiga tahap: **(1)** request smuggling (desync CL.TE) →
**(2)** cache poisoning → **(3)** stored XSS. Target aslinya proprietary,
jadi lab ini mengemulasi rantai yang sama dengan stack open-source:
caching reverse proxy (python) + origin (python).

## Akar masalah (wajib paham)

Request smuggling terjadi ketika **front-end dan back-end beda tafsir
tentang di mana satu request berakhir dan request berikutnya mulai**.
Varian **CL.TE**: front-end membingkai request pakai `Content-Length`,
back-end membingkai pakai `Transfer-Encoding`.

Penyebab umumnya:

- **Rantai parser ganda.** Dua implementasi HTTP berbeda di satu jalur
  (mis. CDN/proxy di depan, origin di belakang) dengan kebijakan
  framing berbeda. Masing-masing benar sendiri-sendiri; kombinasinya
  yang ambigu.
- **Request ambigu diteruskan apa adanya.** Request yang membawa
  `Content-Length` *dan* `Transfer-Encoding` sekaligus seharusnya
  ditolak atau dinormalisasi di front-end. Kalau diteruskan mentah,
  back-end bebas menafsir ulang batas-batasnya.
- **Koneksi keep-alive dipakai ulang.** Front-end dan back-end
  berbagi koneksi persisten. Request selundupan ikut dieksekusi
  back-end, responsnya tertinggal di antrean ("nyangkut"), lalu
  disajikan sebagai respons untuk request *berikutnya* yang lewat
  front-end — *response queue poisoning*.
- **Cache mengunci racun di kunci korban.** Front-end mengira respons
  antrean itu adalah jawaban untuk request normal (mis. `GET /signin`)
  yang cacheable, lalu menyimpannya di bawah kunci URL korban. Semua
  pengunjung halaman itu kemudian menerima konten penyerang — dampak
  setara stored XSS.

Pola serangannya: kirim **satu** request ambigu. Front-end melihat satu
request (bingkai `Content-Length`, body diteruskan mentah). Back-end
melihat **dua** request (bingkai chunked: body berakhir di chunk `0`,
sisanya diurai sebagai request kedua). Request kedua inilah yang kamu
kendalikan — targetkan ke halaman korban dengan muatanmu.

## Topologi

```text
klien --TCP--> proxy:8080 --TCP--> backend:8000
```

- **proxy** (`proxy/proxy.py`): caching reverse proxy. Meneruskan
  request ke backend lewat satu koneksi keep-alive bersama.
  Meng-cache respons `GET` 200 dengan kunci `(method, target)` —
  query string termasuk dalam kunci. Header `X-Cache: HIT/MISS`
  menunjukkan perilaku cache (perilaku CDN standar). Request dengan
  `Cache-Control: no-cache` diteruskan ke origin (melewati cache baca)
  dan respons segarnya disimpan — cara standar untuk memastikan
  origin yang ditanya.
- **backend** (`backend/app.py`): origin biasa. `GET /` → 200;
  `POST /` → 200; `GET /signin` → 200 halaman masuk. Parameter `msg`
  di `/signin` direfleksikan ke halaman — ini kendaraan dampaknya,
  bukan fokus labnya (fokusnya tetap desync di proxy).

## Fase 1 — Hacking (black-box)

Tujuan: **racuni cache untuk `GET /signin`** sehingga pengunjung
`/signin` menerima halaman berisi skripmu — stored XSS via cache
poisoning — dengan request smuggling sebagai kendaraannya.

Langkah yang disarankan:

1. **Baseline.** `GET /` → 200; `GET /signin` → 200 bersih. Perhatikan
   `X-Cache`: request pertama MISS, kedua HIT. Pahami dulu perilaku
   normalnya.
2. **Petakan kunci cache.** Coba `GET /signin?msg=<b>hai</b>` — apa
   yang terjadi, dan apakah `/signin` (tanpa query) ikut berubah?
   Kunci cache mencakup query string: refleksi langsung **tidak**
   meracuni `/signin`. Di sinilah kamu butuh smuggling.
3. **Uji ambiguitas.** Kirim request dengan `Content-Length` **dan**
   `Transfer-Encoding` sekaligus. Bagaimana front-end membingkainya?
   (Seharusnya ditolak. Kenyataannya?)
4. **Selundupkan.** Sembunyikan request kedua **di dalam** body
   `Content-Length`: front-end meneruskan byte mentahnya, back-end
   mengurai body sebagai chunked dan menemukan request keduamu tepat
   setelah chunk `0`. Request selundupanmu: `GET /signin?msg=<skrip>`
   — ingat, jangan minta koneksi ditutup di request selundupan.
5. **Racuni.** Respons untuk request selundupan tertinggal di antrean
   backend. Untuk mengambilnya, kirim `GET /signin` dengan header
   `Cache-Control: no-cache`: front-end meneruskan request ke origin
   (melewati cache) dan menyimpan respons segarnya — karena yang
   dikembalikan origin adalah respons antrean (racunmu), cache kini
   menyimpan racun di bawah kunci `/signin`.
6. **Buktikan.** `GET /signin` biasa → 200, `X-Cache: HIT`, dan
   skripmu ada di body. Klaim `STATUS` dari request pembuktian ini.

Catatan: antrean respons backend itu stateful. Kalau kamu menjalankan
serangan dua kali tanpa reset, hasilnya bisa aneh (sisa run
sebelumnya masih di antrean). Selalu uji dari keadaan segar
(`./lab.sh down` lalu `./lab.sh up`).

Deliverable: `exploit/exploit.py` mencetak `STATUS` + `POISONED_URL`
(lihat `exploit/README.md`). Verifier memeriksa independen bahwa
`GET /signin` memang keracuni setelah skripmu jalan.

## Fase 2 — Review & Fix

Baca `proxy/proxy.py`. Temukan kebijakan framing-nya: apa yang ia
lakukan saat request membawa `Content-Length` dan
`Transfer-Encoding` sekaligus? Perbaikan mengikuti mitigasi kanonis
(dari riset Kettle 2019 dan ringkasan PayPal): **tolak request ambigu**
di front-end — 400, jangan diteruskan.

Tulis perbaikanmu di `fix/proxy/proxy.py`, lalu `./lab.sh verify`.
Fase 2 lulus bila serangan referensi gagal total (400, tidak ada yang
diteruskan ke backend, cache bersih) sementara fungsi normal utuh:
`GET /`, `GET /signin`, `POST /` (pakai Content-Length saja maupun
chunked saja) tetap 200.

## Referensi

- HackerOne #488147 — "Stored XSS on https://paypal.com/signin via
  cache poisoning" (albinowax, 2019), bounty $18.900 —
  https://hackerone.com/reports/488147
- James Kettle / PortSwigger Research — "HTTP Desync Attacks: Request
  Smuggling Reborn" (2019), taksonomi CL.TE / TE.CL / TE.TE —
  https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
