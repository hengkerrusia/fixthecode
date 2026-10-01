# Lab 2: Web Cache Deception → Halaman Privat Ter-cache Publik

**Sumber:** Omer Gil, ["Web Cache Deception Attack"](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
(Black Hat USA 2017). Teknik ini menempati #2 PortSwigger Top 10 Web Hacking
Techniques 2017; temuan di PayPal dibayar bounty **$3.000**.

## Skenario

Sebuah aplikasi punya halaman akun privat yang butuh login. Di depannya ada
cache edge yang meng-cache konten "statis":

```
                    +------------------+
                    |  kamu (penyerang) |
                    +--------+---------+
                             | http://localhost:8080
                    +--------v---------+
                    | cache (python)   |
                    | - cache by ext   |
                    | - header X-Cache |
                    +--------+---------+
                             |
                    +--------v---------+
                    | app (python)     |
                    | /account butuh   |
                    | login            |
                    +------------------+
```

*Web cache deception* terjadi saat dua kondisi bertemu: (1) origin menyajikan
konten privat untuk URL yang *terlihat* statis (mis. `/account/x.css`), dan
(2) cache menyimpan respons itu tanpa memperhatikan siapa yang boleh
melihatnya. Akibatnya halaman privat satu pengguna bisa tersaji ke publik
dari cache — persis seperti kasus PayPal di write-up (URL `/myaccount/home/foo.css`
mengembalikan halaman akun lengkap, ter-cache ~5 jam).

## Akun uji & model ancaman

- Login: `POST /login` dengan form `user=victim` & `pass=victim-pass` →
  respons `200` + cookie sesi.
- Kamu mensimulasikan dua peran: sebagai **korban** (kamu memegang sesi korban —
  di dunia nyata penyerang memancing korban membuka URL racun) dan sebagai
  **penyerang** yang membuktikan URL racun bisa diakses tanpa login.

## Fase 1 — Hacking

**Objektif:** tanpa cookie login, dapatkan `HTTP 200` berisi halaman akun korban
dari URL ber-ekstensi statis (baseline normal: `401`).

### Metodologi

Black-box dulu, seperti di write-up:

1. **Baseline.** Kirim request normal dan catat responsnya:
   ```bash
   curl -i http://localhost:8080/account
   curl -i http://localhost:8080/
   curl -i http://localhost:8080/static/app.css
   ```
2. **Kenali cache.** Fetch URL statis dua kali dan perhatikan header `X-Cache`:
   `MISS` lalu `HIT` artinya respons kedua disajikan dari cache, bukan origin.
   ```bash
   curl -sI http://localhost:8080/static/app.css | grep -i x-cache
   curl -sI http://localhost:8080/static/app.css | grep -i x-cache
   ```
3. **Uji hipotesis.** Bisakah kamu membuat origin menyajikan halaman akun di URL
   yang terlihat statis? Coba tambah segmen path ber-ekstensi di bawah
   `/account/` — sambil login sebagai victim. Kalau ya: apakah cache menyimpan
   respons itu? (Lihat `X-Cache` pada fetch tanpa login.)
4. **Eksploitasi.** Racuni satu URL unik, lalu buktikan URL itu menyajikan data
   korban *tanpa* login. Ulangi sampai dapat `200` + data korban.

### Deliverable

Tulis seranganmu sebagai script di `exploit/exploit.py` (scaffold sudah
disiapkan). Menyerang manual via curl boleh untuk eksplorasi, tapi kelulusan
butuh script yang reproducible. Kontrak dengan verifier (`./lab.sh verify`):

- Dijalankan sebagai `python3 exploit/exploit.py` saat lab hidup di `127.0.0.1:8080`.
- Hanya Python stdlib, selesai < 60 detik.
- Wajib mencetak baris `STATUS: <kode>` berisi status HTTP dari GET *tanpa sesi
  login* ke URL yang sudah kamu racuni. Contoh sukses: `STATUS: 200`.
- Fase 1 lulus jika verifier menemukan `STATUS: 200` di output skrip.
- Kalau skripmu membaca respons sampai EOF, pastikan request-mu mengandung
  `Connection: close` — kalau tidak, koneksi tidak ditutup dan skripmu hang.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `cache/cache.py`. Di mana tepatnya keputusan "respons ini boleh
   disimpan di cache" dibuat? Apa yang dilakukan (atau tidak dilakukan) kode
   itu terhadap header `Cache-Control` yang dikirim origin?
2. Tulis perbaikanmu di `fix/cache/cache.py` (scaffold sudah disiapkan —
   **jangan** edit file di `cache/`, itu definisi rentan yang harus tetap pristine).
   Uji dengan `./lab.sh fix-up` (lab berjalan dengan overlay fix-mu), lalu verifikasi
   resmi dengan `./lab.sh verify`: verifier me-rebuild cache dari `fix/`,
   menjalankan ulang serangan fase 1, dan memastikan serangan itu sekarang gagal
   sementara fungsi normal tetap berjalan.
3. Kriteria fix yang benar:
   - Serangan fase 1 GAGAL: GET tanpa login ke URL racun tidak lagi mengembalikan
     halaman korban (`401` dari origin).
   - Baseline `GET /account` tanpa login tetap `401`.
   - `GET /` tetap `200`.
   - `GET /static/app.css` dua kali tetap `200`, dan fetch kedua berheader
     `X-Cache: HIT` — artinya kamu tidak merusak fungsi caching yang legitimate.
4. Bonus (defense in depth, tidak dinilai): apa yang masih rapuh dari desain
   ini? Bagaimana kamu mengeraskannya berlapis?

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

- `GET /` → `200`, halaman publik.
- `GET /account` tanpa login → `401`; dengan login → `200` halaman akun.
- `POST /login` → `200` + cookie sesi (kredensial di atas).
- `GET /static/app.css` → `200` file statis.
- Header `X-Cache: MISS/HIT/BYPASS` menandai perilaku cache (alat observasi).

## Referensi

- Omer Gil — "Web Cache Deception Attack" (artikel utama lab ini).
- PortSwigger Top 10 Web Hacking Techniques 2017 (#2).
