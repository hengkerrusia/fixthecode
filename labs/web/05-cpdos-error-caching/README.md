# Lab 5: CPDoS — Cache Poisoning DoS via Error Caching (403)

**Sumber:** paper ["Cache Poisoned Denial of Service"](https://cpdos.org/)
("Your Cache Has Fallen", CCS 2019) dan kasus bounty **$2.500** — respons
`403` yang ter-cache di Cloudflare (write-up Iustin). Intinya sama:
penyerang memicu origin mengembalikan *error*, cache menyimpannya, semua
orang mendapat error itu. (Angka bounty dari blog peneliti.)

## Skenario

Aplikasi memvalidasi host secara ketat: request dengan `X-Forwarded-Host`
asing ditolak `403`. Di depannya ada cache edge yang — keliru — menyimpan
respons `403` juga:

```
                    +------------------+
                    |  kamu (penyerang) |
                    +--------+---------+
                             | http://localhost:8080
                    +--------v---------+
                    | cache (python)   |
                    | - key: method    |
                    |   + path         |
                    | - nyimpen 200    |
                    |   DAN 403 (!)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    | app (python)     |
                    | host asing ->    |
                    | 403              |
                    +------------------+
```

*Cache-Poisoned DoS* terjadi saat dua kondisi bertemu: (1) penyerang bisa
memicu origin mengembalikan error untuk suatu URL (di sini: `403` via
`X-Forwarded-Host` asing — header yang tidak masuk cache key, seperti Lab 3),
dan (2) cache **menyimpan error itu**. Satu request meracuni entri cache
dengan `403`, dan semua pengunjung berikutnya mendapat `403` — halaman mati
total sampai cache diisi ulang.

Aplikasi hanya menerima host `127.0.0.1:8080` / `localhost:8080`
(dikonfigurasi via env `ALLOWED_HOSTS`); host lain ditolak `403`.

## Fase 1 — Hacking

**Objektif:** tanpa header asing, dapatkan `HTTP 403` dari URL yang sudah
kamu racuni (baseline normal: `200`).

### Metodologi

Black-box dulu, seperti di paper:

1. **Baseline.** Fetch halaman utama dan catat responsnya:
   ```bash
   curl -i http://localhost:8080/
   ```
2. **Kenali cache.** Fetch dua kali, perhatikan `X-Cache`: `MISS` lalu `HIT`.
3. **Uji hipotesis.** Bisakah kamu membuat origin mengembalikan error?
   Coba kirim `X-Forwarded-Host` dengan nilai asing dan lihat statusnya.
   Kalau dapat error: apakah error itu masuk cache? (Racuni URL ber-query
   unik dengan header itu, lalu fetch ulang *tanpa* header — apakah
   error-nya bertahan?)
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-Host: evil.test" "http://localhost:8080/?cb=1"
   curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:8080/?cb=1"
   ```
4. **Eksploitasi.** Racuni satu URL unik, lalu buktikan URL itu menyajikan
   `403` *tanpa* header asing. Ulangi sampai konsisten.

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
                            asing) ke URL yang kamu racuni. Contoh: 403
  POISONED_URL: <path>      URL yang kamu racuni (mis. /?x=<acak>)
  ```
- Verifier **tidak percaya begitu saja**: ia melakukan GET bersih sendiri ke
  `POISONED_URL`. Fase 1 lulus hanya jika responsnya `403`.
- Pakai URL racun yang unik tiap eksekusi (query `?x=<acak>`) supaya tidak
  tercampur dengan percobaan lain — termasuk percobaan manualmu sendiri.
- Kalau skripmu membaca respons sampai EOF, pastikan request-mu mengandung
  `Connection: close` — kalau tidak, koneksi tidak ditutup dan skripmu hang.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `cache/cache.py`. Di mana tepatnya keputusan "respons ini boleh
   disimpan di cache" dibuat? Status apa saja yang boleh disimpan — dan
   seharusnya begitu?
2. Tulis perbaikanmu di `fix/cache/cache.py` (salinan pristine tanpa komentar —
   **jangan** edit file di `cache/`). Uji dengan `./lab.sh fix-up`, lalu
   verifikasi resmi dengan `./lab.sh verify`: verifier me-rebuild cache dari
   `fix/`, menjalankan ulang serangan fase 1, dan memastikan serangan itu
   sekarang gagal sementara fungsi normal tetap berjalan.
3. Kriteria fix yang benar:
   - Serangan fase 1 GAGAL: GET bersih ke URL yang diserang penyerang tetap
     `200` (error tidak lagi di-cache).
   - Request langsung *dengan* header asing tetap `403` dari origin —
     validasi host aplikasi tidak boleh dirusak oleh fix-mu.
   - Baseline `GET /` tetap `200`.
   - `GET /static/app.js` dua kali tetap `200`, dan fetch kedua berheader
     `X-Cache: HIT` — artinya kamu tidak merusak fungsi caching yang legitimate.
4. Bonus (defense in depth, tidak dinilai): paper CPDoS mendokumentasikan
   beberapa varian pemicu error lain (header oversize, method override).
   Seberapa jauh fix-mu melindungi dari varian-varian itu? Apa yang masih
   bisa diracuni di desain ini?

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

- `GET /` → `200`, halaman publik (`Cache-Control: public, max-age=60`).
- `GET /static/app.js` → `200` file statis (`Cache-Control: public, max-age=3600`).
- `GET /` dengan `X-Forwarded-Host` asing → `403` (`Cache-Control: public, max-age=60`).
- Header `X-Cache: MISS/HIT/BYPASS` menandai perilaku cache (alat observasi).
- Query string masuk ke cache key — `/?cb=1` dan `/?cb=2` adalah entri cache
  yang berbeda.

## Referensi

- "Your Cache Has Fallen" — paper CPDoS (cpdos.org, CCS 2019; teknik utama lab ini).
- Iustin — write-up 403-caching di Cloudflare ($2.500; jangkar bounty lab ini).
