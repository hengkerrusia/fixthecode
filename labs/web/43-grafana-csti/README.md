# Lab 43 — Grafana: Client-Side Template Injection via URL Terefleksi

Sumber: CVE-2021-41174 / GHSA-3j9m-hcv9-rpj8 — XSS pada halaman publik
Grafana 8.0.0-beta1 sampai 8.2.2, diperbaiki di 8.2.3. Penyerang yang
membujuk pengguna yang belum login membuka URL tercraft mendapat eksekusi
JavaScript arbitrer di origin Grafana, karena URL itu terefleksi ke
tautan login pada navbar lalu dievaluasi oleh mesin rendering AngularJS
sebagai ekspresi template `{{ }}`.

## Skenario

Aplikasi lab ini, **Pantau**, meniru perilaku Grafana rentan dalam skala
kecil: aplikasi pemantauan dengan halaman publik, navbar berisi tautan
**Masuk**, dan halaman login (kredensial demo: `demo` / `demo123`).

- Seperti Grafana pra-8.2.3, tautan Masuk pada navbar membawa URL yang
  sedang diminta (path + query) sebagai parameter `redirectTo`, supaya
  pengguna kembali ke halaman asal sesudah login. URL itu ditulis ke
  `href` apa adanya — hanya di-escape untuk HTML, tanpa validasi dan
  tanpa perlakuan khusus terhadap kurung kurawal.
- Halaman publik dirender oleh mesin template sisi klien yang
  menginterpolasi binding `{{ }}` di seluruh DOM — teks maupun nilai
  atribut — persis cara AngularJS bekerja pada halaman Grafana lama.
  (Di lab ini mesinnya versi mini yang meniru semantik interpolasi
  AngularJS; pola dan payload-nya identik dengan aslinya.)
- Korban adalah pengunjung yang **belum login**: ia membuka tautan
  tercraft, halaman memuat, dan binding pada `href` tautan Masuk
  dievaluasi sebagai ekspresi — termasuk jalan keluar sandbox klasik
  AngularJS, `constructor.constructor(...)`, yang memberi eksekusi
  JavaScript penuh.

Rantai serangan: **URL tercraft → refleksi ke href navbar → interpolasi
template sisi klien → pelarian sandbox → JavaScript arbitrer di origin
aplikasi.**

Service `browser` (port 8081) berperan sebagai browser korban: ia
me-render HTML di Chromium headless dan mengembalikan DOM sesudah
JavaScript berjalan, sehingga eksekusi bisa dibuktikan lewat HTTP biasa.

## Akar Masalah

Pola umumnya: **data yang dikendalikan penyerang diperlakukan sebagai
template**. Mesin template sisi klien seperti AngularJS tidak membedakan
"markup yang ditulis pengembang" dan "string yang datang dari luar" —
setiap `{{ }}` yang sampai ke DOM akan dievaluasi sebagai ekspresi.
Akibatnya setiap titik refleksi (URL, parameter, nama, judul) berubah
menjadi titik injeksi kode, tanpa penyerang perlu menembus sanitasi HTML
apa pun: kurung kurawal bukan karakter khusus HTML, jadi escape HTML yang
benar pun tidak menolong.

Dua pelajaran dari perbaikan upstream (Grafana 8.2.3):

1. **Perbaiki datanya, bukan matikan framework-nya.** Grafana sempat
   mencoba mitigasi "jangan bootstrap AngularJS bila path mengandung
   `{{`" — dan *membatalkan* pendekatan itu di rilis perbaikan yang sama.
   Yang bertahan adalah sanitasi di titik render: fungsi
   `sanitizeAngularInterpolation` mengganti `{{` → `%7B%7B` dan
   `}}` → `%7D%7D` pada URL tautan navigasi, sehingga string tetap
   berfungsi sebagai URL tetapi tidak pernah terlihat sebagai binding
   oleh mesin template.
2. **Bentuk aman dari pola yang sama:** nilai apa pun yang berasal dari
   permintaan dan akan ditulis ke halaman yang dirender mesin template
   harus di-encode untuk karakter pembuka/penutup binding pada titik
   penulisan — seluruh kemunculan, bukan hanya yang pertama — sementara
   nilai itu sendiri tetap data, bukan kode.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** Buka halaman publik tanpa login dan periksa navbar:
   tautan Masuk selalu membawa URL halaman itu sendiri sebagai
   `redirectTo`. Minta path sembarang, misalnya `/dash/xyz`, dan amati
   bahwa path itu muncul kembali utuh di `href` tautan Masuk.
2. **Probe diferensial.** Sisipkan ekspresi aritmetika sebagai bagian
   dari path: `/dash/{{7*7}}`. Render halaman lewat service `browser`
   (`POST /render`) dan periksa DOM hasil render: bila `href` tautan
   Masuk berubah menjadi `/login?redirectTo=/dash/49`, string yang kamu
   kendalikan **dievaluasi sebagai ekspresi template**, bukan sekadar
   ditampilkan — itu tanda tangan client-side template injection.
   Bandingkan dengan respons mentah dari server: di sana `{{7*7}}` masih
   utuh; evaluasinya murni terjadi di sisi klien.
3. **Konfirmasi konteks.** Payload harus mendarat di dalam wilayah yang
   diinterpolasi mesin template (di sini: nilai atribut `href` pada
   navbar halaman publik) dan korbannya adalah pengunjung yang belum
   login — tidak ada sesi yang perlu dicuri lebih dulu.
4. **Eksploitasi.** Naik dari aritmetika ke eksekusi: pakai jalan keluar
   sandbox ekspresi AngularJS, `constructor.constructor('<kode>')()`,
   untuk menjalankan JavaScript arbitrer dalam konteks halaman. Sebagai
   bukti yang bisa diperiksa mesin, buat kode itu mengubah
   `document.title` menjadi penanda unik.

### Deliverable

`exploit/exploit.py` — skrip Python stdlib yang secara otomatis meminta
path tercraft ke aplikasi, me-render balasannya lewat service `browser`,
dan mencetak kontrak output berikut (rincian di `exploit/README.md`):

```
STATUS: 200
URL: /dash/<path tercraft>
RENDERED: true
MARKER: CSTI-XSS-OK
```

Baris `MARKER` hanya boleh dicetak bila judul dokumen pada DOM hasil
render benar-benar berubah menjadi `CSTI-XSS-OK` — teks penanda yang
muncul mentah di dalam string payload pada halaman **bukan** bukti
eksekusi.

## Fase 2 — Review & Fix

1. **Review code.** Baca `app/app.py` dan telusuri aliran datanya: dari
   mana URL permintaan diambil, ke mana ia ditulis pada halaman publik,
   dan transformasi apa (jika ada) yang ia alami di tengah jalan.
   Temukan titik penulisan ke tautan navigasi — di situlah data berubah
   status menjadi calon template.
2. **Tulis fix** di `fix/app/app.py` mengikuti pola upstream: pada titik
   penulisan itu, ganti seluruh kemunculan `{{` menjadi `%7B%7B` dan
   `}}` menjadi `%7D%7D` sebelum URL direfleksikan. Jangan mengubah
   rute, cookie sesi, kredensial, atau perilaku redirect; URL normal
   tanpa kurung kurawal harus lolos tanpa perubahan.
3. **Verifikasi.** Verifier membangun ulang aplikasi dari `fix/`-mu:
   payload yang sama harus terefleksi dalam keadaan ter-encode dan
   gagal dieksekusi, sementara login dan fungsi normal tetap utuh.

## Perintah

```sh
./lab.sh start    # jalankan rakitan rentan (app :8080, browser :8081)
./lab.sh verify   # verifikasi 2 fase (Docker)
./lab.sh fix-up   # jalankan dengan fix/ milikmu
./lab.sh stop     # hentikan
```

Kredensial demo: `demo` / `demo123`.

## Referensi

- Grafana security advisory GHSA-3j9m-hcv9-rpj8 (CVE-2021-41174):
  https://github.com/grafana/grafana/security/advisories/GHSA-3j9m-hcv9-rpj8
- Commit perbaikan upstream (`sanitizeAngularInterpolation` pada tautan
  NavBar + pembatalan mitigasi bootstrap AngularJS):
  https://github.com/grafana/grafana/commit/31b78d51c693d828720a5b285107a50e6024c912
- CVE record: https://www.cve.org/CVERecord?id=CVE-2021-41174
