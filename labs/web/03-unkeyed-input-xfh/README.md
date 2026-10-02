# Lab 3: Unkeyed Input → Cache Poisoning via X-Forwarded-Host

**Sumber:** HackerOne [#977851](https://hackerone.com/reports/977851)
(Shopify, 2020). Satu request dengan header `X-Forwarded-Host: attacker.com`
meracuni respons yang ter-cache di `apps.shopify.com` (dan subdomain lokalnya)
— bounty awal **$1.300**, dieskalasi ke **$6.300** karena satu racun berdampak
ke banyak host. (Angka bounty dari blog peneliti; tidak tampil di halaman
publik HackerOne.)

## Skenario

Sebuah aplikasi membangun URL absolut untuk asetnya dari header
`X-Forwarded-Host` — header yang lazim ditambahkan/diteruskan oleh reverse
proxy. Di depannya ada cache edge yang menyimpan respons berdasarkan
*method + path saja*:

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
                    | / membangun URL  |
                    | aset dari header |
                    +------------------+
```

*Cache poisoning via unkeyed input* terjadi saat dua kondisi bertemu:
(1) ada **input yang memengaruhi respons tapi TIDAK masuk cache key**
(di sini: `X-Forwarded-Host`), dan (2) respons yang dipengaruhi itu
**disimpan di cache**. Akibatnya satu request penyerang mencemari respons
yang disajikan ke semua orang — persis seperti kasus Shopify di write-up
(satu request meracuni cache lintas subdomain).

## Fase 1 — Hacking

**Objektif:** tanpa memakai header jahat, dapatkan `HTTP 200` yang badannya
memuat host penyerang — dari URL yang sudah kamu racuni.

### Metodologi

Black-box dulu, seperti di write-up:

1. **Baseline.** Kirim request normal dan catat responsnya. Dari mana halaman
   mengambil host untuk URL asetnya?
   ```bash
   curl -i http://localhost:8080/
   ```
2. **Kenali cache.** Respons halaman utama bisa di-cache. Fetch dua kali dan
   perhatikan header `X-Cache`: `MISS` lalu `HIT` artinya respons kedua
   disajikan dari cache, bukan origin.
   ```bash
   curl -sI "http://localhost:8080/?cb=1" | grep -i x-cache
   curl -sI "http://localhost:8080/?cb=1" | grep -i x-cache
   ```
3. **Uji hipotesis.** Header apa saja yang memengaruhi isi respons? Coba kirim
   `X-Forwarded-Host` dengan nilai versimu dan lihat apakah ia muncul di badan
   respons. Kalau ya: apakah header itu masuk cache key? (Uji dengan URL
   ber-query unik: racuni dengan header, lalu fetch ulang *tanpa* header.)
   ```bash
   curl -s -H "X-Forwarded-Host: evil.test" "http://localhost:8080/?cb=2" | grep evil
   curl -s "http://localhost:8080/?cb=2" | grep evil
   ```
4. **Eksploitasi.** Racuni satu URL unik, lalu buktikan URL itu menyajikan
   host penyerang *tanpa* header jahat. Ulangi sampai konsisten.

### Deliverable

Tulis seranganmu sebagai script di `exploit/exploit.py` (scaffold sudah
disiapkan). Menyerang manual via curl boleh untuk eksplorasi, tapi kelulusan
butuh script yang reproducible. Kontrak dengan verifier (`./lab.sh verify`):

- Dijalankan sebagai `python3 exploit/exploit.py` saat lab hidup di `127.0.0.1:8080`.
- Hanya Python stdlib, selesai < 60 detik.
- Wajib mencetak tepat tiga baris:
  ```
  STATUS: <kode>            status HTTP dari GET *tanpa* header jahat
                            ke URL yang kamu racuni. Contoh sukses: 200
  POISONED_URL: <path>      URL yang kamu racuni (mis. /?x=<acak>)
  POISONED_HOST: <host>     host penyerang yang kamu pakai
                            (mis. evil-<acak>.test)
  ```
- Verifier **tidak percaya begitu saja**: ia melakukan GET bersih sendiri ke
  `POISONED_URL`. Fase 1 lulus hanya jika responsnya `200` **dan** badannya
  benar-benar memuat `POISONED_HOST`.
- Pakai URL racun yang unik tiap eksekusi (query `?x=<acak>`) supaya tidak
  tercampur dengan percobaan lain — termasuk percobaan manualmu sendiri.
- Kalau skripmu membaca respons sampai EOF, pastikan request-mu mengandung
  `Connection: close` — kalau tidak, koneksi tidak ditutup dan skripmu hang.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `app/app.py`. Di fungsi mana aplikasi memutuskan host apa yang
   dipakai untuk membangun URL absolut? Header apa yang ia percaya, dan
   apakah header itu berada dalam kendali penyerang?
2. Tulis perbaikanmu di `fix/app/app.py` (scaffold sudah disiapkan —
   **jangan** edit file di `app/`, itu definisi rentan yang harus tetap pristine).
   Uji dengan `./lab.sh fix-up` (lab berjalan dengan overlay fix-mu), lalu verifikasi
   resmi dengan `./lab.sh verify`: verifier me-rebuild app dari `fix/`,
   menjalankan ulang serangan fase 1, dan memastikan serangan itu sekarang gagal
   sementara fungsi normal tetap berjalan.
3. Kriteria fix yang benar:
   - Serangan fase 1 GAGAL: GET bersih ke URL yang diracuni penyerang tidak
     lagi memuat host penyerang.
   - Request langsung *dengan* header `X-Forwarded-Host` jahat tidak lagi
     mencerminkan host itu di respons — aplikasi harus mengabaikannya, bukan
     sekadar mengandalkan perilaku cache.
   - Baseline `GET /` tetap `200` dan badannya memuat host normal
     (`127.0.0.1:8080`) — artinya URL aset tetap dibangun dari sumber
     tepercaya (Host yang diteruskan cache), bukan di-hardcode entah ke mana.
   - `GET /static/app.js` dua kali tetap `200`, dan fetch kedua berheader
     `X-Cache: HIT` — artinya kamu tidak merusak fungsi caching yang legitimate.
4. Bonus (defense in depth, tidak dinilai): setelah fix-mu, header `Host`
   sendiri masih memengaruhi respons dan tidak masuk cache key. Apa risikonya?
   Bagaimana kamu mengeraskannya berlapis (allowlist host? `Vary`? validasi
   di cache?)?

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

- `GET /` → `200`, halaman publik berisi `<script src="https://<host>/static/app.js">`
  (`Cache-Control: public, max-age=60`).
- `GET /static/app.js` → `200` file statis (`Cache-Control: public, max-age=3600`).
- Header `X-Cache: MISS/HIT/BYPASS` menandai perilaku cache (alat observasi).
- Query string masuk ke cache key — `/?cb=1` dan `/?cb=2` adalah entri cache
  yang berbeda.

## Referensi

- HackerOne #977851 — cache poisoning via X-Forwarded-Host di Shopify
  (laporan utama lab ini).
- PortSwigger — "Web cache poisoning" (latar teknik unkeyed header).
