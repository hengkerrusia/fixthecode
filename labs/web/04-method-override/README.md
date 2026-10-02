# Lab 4: Method Override → Cache Poisoning DoS via X-HTTP-Method-Override

**Sumber:** HackerOne [#1160407](https://hackerone.com/reports/1160407)
(GitLab, 2021). Satu request `GET /assets/webpack/*.js` dengan header
`X-HTTP-Method-Override: HEAD` membuat backend mengembalikan bodi kosong —
dan CDN meng-cache-nya sebagai respons GET yang sah. Akibatnya file JS
tersebut tersaji kosong ke semua orang: *denial of service* via cache.
Bounty **$2.500**. (Angka bounty dari blog peneliti; tidak tampil di halaman
publik HackerOne.)

## Skenario

Sebuah aplikasi menuruti header `X-HTTP-Method-Override` — awalnya fitur
untuk form HTML yang cuma bisa GET/POST. Di depannya ada cache edge yang
menyimpan respons berdasarkan *method + path*, memakai method yang terlihat
di request line:

```
                    +------------------+
                    |  kamu (penyerang) |
                    +--------+---------+
                             | http://localhost:8080
                    +--------v---------+
                    | cache (python)   |
                    | - key: method    |
                    |   + path         |
                    | - header X-Cache |
                    +--------+---------+
                             |
                    +--------v---------+
                    | app (python)     |
                    | /static/app.js   |
                    | nurut override   |
                    +------------------+
```

Ini saudara kandung Lab 3 (*unkeyed input*): method efektif yang dipakai
origin (`HEAD` via header override) **tidak masuk cache key** — cache cuma
melihat `GET` di request line. Satu request penyerang menimpa entri cache
`GET /static/app.js` dengan respons 200 berbodi kosong, dan semua orang
mendapat file kosong sampai cache diisi ulang.

## Fase 1 — Hacking

**Objektif:** tanpa header override, dapatkan `HTTP 200` dengan **bodi kosong**
dari URL yang sudah kamu racuni (baseline normal: `200` + bodi utuh).

### Metodologi

Black-box dulu, seperti di write-up:

1. **Baseline.** Fetch file statis dan catat isinya:
   ```bash
   curl -i "http://localhost:8080/static/app.js?cb=1"
   ```
2. **Kenali cache.** Fetch dua kali, perhatikan `X-Cache`: `MISS` lalu `HIT`.
3. **Uji hipotesis.** Apa yang terjadi kalau kamu kirim
   `X-HTTP-Method-Override: HEAD` pada request GET? Apakah bodinya berubah?
   Kalau ya: apakah method override itu masuk cache key? (Racuni URL
   ber-query unik dengan header itu, lalu fetch ulang *tanpa* header —
   apakah bodi kosongnya bertahan?)
   ```bash
   curl -s -D- -H "X-HTTP-Method-Override: HEAD" "http://localhost:8080/static/app.js?cb=2" | head -8
   curl -s "http://localhost:8080/static/app.js?cb=2" | wc -c
   ```
4. **Eksploitasi.** Racuni satu URL unik, lalu buktikan URL itu menyajikan
   bodi kosong *tanpa* header override. Ulangi sampai konsisten.

### Deliverable

Tulis seranganmu sebagai script di `exploit/exploit.py` (scaffold: kode +
`raise NotImplementedError`). Menyerang manual via curl boleh untuk eksplorasi,
tapi kelulusan butuh script yang reproducible. Kontrak dengan verifier
(`./lab.sh verify`):

- Dijalankan sebagai `python3 exploit/exploit.py` saat lab hidup di `127.0.0.1:8080`.
- Hanya Python stdlib, selesai < 60 detik.
- Wajib mencetak tepat dua baris:
  ```
  STATUS: <kode>            status HTTP dari GET *bersih* (tanpa header
                            override) ke URL yang kamu racuni. Contoh: 200
  POISONED_URL: <path>      URL yang kamu racuni
                            (mis. /static/app.js?x=<acak>)
  ```
- Verifier **tidak percaya begitu saja**: ia melakukan GET bersih sendiri ke
  `POISONED_URL`. Fase 1 lulus hanya jika responsnya `200` **dan** bodinya
  kosong.
- Pakai URL racun yang unik tiap eksekusi (query `?x=<acak>`) supaya tidak
  tercampur dengan percobaan lain — termasuk percobaan manualmu sendiri.
- Kalau skripmu membaca respons sampai EOF, pastikan request-mu mengandung
  `Connection: close` — kalau tidak, koneksi tidak ditutup dan skripmu hang.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `app/app.py`. Di mana tepatnya aplikasi memutuskan untuk menuruti
   `X-HTTP-Method-Override`? Method apa saja yang "didukung" header itu, dan
   siapa yang bisa mengirimnya?
2. Tulis perbaikanmu di `fix/app/app.py` (salinan pristine tanpa komentar —
   **jangan** edit file di `app/`). Uji dengan `./lab.sh fix-up`, lalu
   verifikasi resmi dengan `./lab.sh verify`: verifier me-rebuild app dari
   `fix/`, menjalankan ulang serangan fase 1, dan memastikan serangan itu
   sekarang gagal sementara fungsi normal tetap berjalan.
3. Kriteria fix yang benar:
   - Serangan fase 1 GAGAL: GET bersih ke URL yang diserang penyerang tetap
     mengembalikan bodi utuh.
   - Request langsung *dengan* header `X-HTTP-Method-Override: HEAD` tetap
     mengembalikan bodi utuh — aplikasi harus mengabaikan header itu, bukan
     sekadar mengandalkan perilaku cache.
   - Baseline `GET /static/app.js` tetap `200` + bodi utuh.
   - `GET /` tetap `200`.
   - `GET /static/app.js` dua kali tetap `200`, dan fetch kedua berheader
     `X-Cache: HIT` — artinya kamu tidak merusak fungsi caching yang legitimate.
4. Bonus (defense in depth, tidak dinilai): selain di aplikasi, di lapisan
   mana lagi serangan ini bisa ditutup? (Petunjuk: apa yang seharusnya masuk
   cache key selain method+path? Bagaimana kalau suatu hari nanti ada header
   override lain?)

## Perintah

```bash
./lab.sh start    # bangun & jalankan lab (SELALU kondisi rentan)
./lab.sh verify   # verifikasi otomatis fase 1 + fase 2
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan & bersihkan
```

**Catatan reset:** `./lab.sh start` selalu build ulang dari file pristine, jadi lab
selalu kembali rentan. Fix-mu hanya aktif lewat `./lab.sh fix-up` atau `./lab.sh verify`.

## Jejak audit (untuk fase 1)

- `GET /static/app.js` → `200` file statis (`Cache-Control: public, max-age=3600`).
- `GET /` → `200`, halaman publik (`Cache-Control: public, max-age=60`).
- Header `X-Cache: MISS/HIT/BYPASS` menandai perilaku cache (alat observasi).
- Query string masuk ke cache key — `/static/app.js?cb=1` dan `?cb=2` adalah
  entri cache yang berbeda.

## Referensi

- HackerOne #1160407 — cache poisoning DoS via X-HTTP-Method-Override di GitLab
  (laporan utama lab ini).
- PortSwigger — "Web cache poisoning" (latar teknik method override).
