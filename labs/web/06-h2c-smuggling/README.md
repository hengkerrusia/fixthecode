# Lab 6: H2C Smuggling — HTTP/2 Cleartext Upgrade Tunnel

**Sumber:** riset **Bishop Fox** tentang *H2C request smuggling* beserta tool
`h2csmuggler`. Ide dasarnya: HTTP/2 punya mode *cleartext* (`h2c`) yang
di-negosiasi lewat mekanisme *upgrade* HTTP/1.1 biasa. Kalau sebuah
front-end/proxy meneruskan request upgrade itu lalu berhenti mem-parsing —
hanya meneruskan byte mentah bolak-balik — penyerang bisa berbicara HTTP/2
langsung ke backend, melewati semua pemeriksaan yang hanya dilakukan di
lapisan HTTP/1.1.

## Skenario

```
                    +------------------+
                    |  kamu (penyerang) |
                    +--------+---------+
                             | http://localhost:8080
                    +--------v---------+
                    | gateway (python) |
                    | - request ke     |
                    |   /admin -> 403  |
                    | - meneruskan     |
                    |   sisanya ke     |
                    |   backend        |
                    +--------+---------+
                             |
                    +--------v---------+
                    | backend (python) |
                    | - melayani h2c   |
                    | - /admin -> 200  |
                    |   (tanpa proteksi|
                    |    sendiri)      |
                    +------------------+
```

Gateway adalah satu-satunya penjaga: request HTTP/1.1 ke `/admin` langsung
ditolak `403`. Backend sendiri tidak memproteksi `/admin` — seperti banyak
arsitektur nyata, otorisasi dianggap urusan lapisan depan. Backend mendukung
upgrade ke `h2c`: ia menjawab `101 Switching Protocols`, lalu berbicara
frame-frame biner HTTP/2.

## Fase 1 — Hacking

**Objektif:** dapatkan `HTTP 200` beserta konten panel admin dari `/admin`
*melalui gateway* — padahal request langsung ke `/admin` diblokir `403`.

### Metodologi

Black-box dulu, seperti di riset aslinya:

1. **Baseline.** Fetch halaman utama dan halaman admin, catat responsnya:
   ```bash
   curl -i http://localhost:8080/
   curl -i http://localhost:8080/admin
   ```
2. **Uji upgrade.** HTTP/2 cleartext di-negosiasi lewat request HTTP/1.1
   biasa (RFC 7540 §3.2) dengan tiga header ini:
   ```
   Connection: Upgrade, HTTP2-Settings
   Upgrade: h2c
   HTTP2-Settings: <base64url dari payload SETTINGS, boleh kosong>
   ```
   Kirim request itu ke `/` (path yang lolos pemeriksaan gateway) dan
   perhatikan responsnya. `101` artinya: gateway meneruskan upgrade-mu, dan
   mulai detik itu ia berhenti mem-parsing — ia hanya meneruskan byte mentah
   antara kamu dan backend.
3. **Hipotesa inti.** Pemeriksaan `/admin -> 403` hanya melihat *request
   line* HTTP/1.1 yang pertama. Setelah `101`, tidak ada lagi yang memeriksa
   apa pun. Jadi: apa yang terjadi kalau, di dalam terowongan itu, kamu
   berbicara HTTP/2 dan meminta `/admin`?
4. **Berbicara HTTP/2 minimal.** Setelah `101`, kirim:
   - *connection preface*: tepat 24 byte `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`,
   - satu frame SETTINGS kosong (type `0x4`),
   - satu frame HEADERS (type `0x1`) di stream `1` berisi header request
     untuk `/admin`.
   
   Backend di lab ini hanya mengerti subset kecil HTTP/2 — cukup untuk lab,
   dan cukup untuk dipelajari:
   - Frame = 24-bit panjang, 8-bit type, 8-bit flags, 31-bit stream id,
     lalu payload.
   - Blok header memakai *literal without indexing*: satu byte `0x00`,
     lalu 1 byte panjang nama, nama, 1 byte panjang nilai, nilai
     (nama < 16 byte, nilai < 128 byte — lebih dari cukup).
   - Pseudo-header yang dibutuhkan: `:method`, `:scheme`, `:path`,
     `:authority`.
   
   Contoh blok header untuk `GET /admin` (heks):
   ```
   00 07 3a6d6574686f64 03 474554        ; :method = GET
   00 07 3a736368656d65 04 68747470      ; :scheme = http
   00 05 3a70617468 06 2f61646d696e      ; :path = /admin
   00 0a 3a617574686f72697479 0e 3132372e302e302e313a38303830
                                        ; :authority = 127.0.0.1:8080
   ```
   Responsnya juga frame: HEADERS berisi `:status`, lalu DATA berisi bodi.
   Baca frame dengan panjang eksak — jangan baca sampai EOF.
5. **Eksploitasi.** Selundupkan request `/admin` lewat terowongan h2c dan
   buktikan kamu mendapat `200` + konten panel admin. Ulangi sampai konsisten.

### Deliverable

Tulis seranganmu sebagai script di `exploit/exploit.py` (scaffold: kode +
`raise NotImplementedError`). Eksplorasi manual boleh, tapi kelulusan butuh
script yang reproducible. Kontrak dengan verifier (`./lab.sh verify`):

- Dijalankan sebagai `python3 exploit/exploit.py` saat lab hidup di `127.0.0.1:8080`.
- Hanya Python stdlib, selesai < 60 detik.
- Wajib mencetak tepat dua baris:
  ```
  STATUS: <kode>            status HTTP dari request yang kamu selundupkan
                            lewat terowongan h2c. Contoh sukses: 200
  SMUGGLED_PATH: <path>     path yang kamu selundupkan (mis. /admin)
  ```
- Verifier **tidak percaya begitu saja**: ia melakukan smuggling sendiri ke
  `SMUGGLED_PATH`. Fase 1 lulus hanya jika responsnya `200` dan memuat konten
  panel admin.
- Jangan kirim `Connection: close` pada request upgrade — koneksi itu
  memang diniatkan menjadi terowongan. Baca frame respons dengan panjang
  eksak; skrip yang hang (> 60 detik) dianggap gagal.

## Fase 2 — Fixing

**Objektif:** tutup kerentanannya **tanpa merusak fungsi normal**.

1. Review `gateway/proxy.py`. Di mana tepatnya pemeriksaan `/admin`
   ditegakkan? Setelah respons `101`, apa yang dilakukan gateway terhadap
   byte-byte berikutnya — dan pemeriksaan apa yang masih berjalan di sana?
2. Tulis perbaikanmu di `fix/gateway/proxy.py` (salinan pristine tanpa
   komentar — **jangan** edit file di `gateway/`). Uji dengan
   `./lab.sh fix-up`, lalu verifikasi resmi dengan `./lab.sh verify`:
   verifier me-rebuild gateway dari `fix/`, mengulang serangan fase 1, dan
   memastikan serangan itu sekarang gagal sementara fungsi normal tetap
   berjalan.
3. Kriteria fix yang benar:
   - Serangan fase 1 GAGAL: request `/admin` yang diselundupkan lewat h2c
     tidak lagi menghasilkan `200` + konten admin.
   - Baseline `GET /` tetap `200`.
   - `GET /admin` langsung tetap `403` — pemeriksaan lapisan depan tidak
     boleh dirusak oleh fix-mu.
4. Bonus (tidak dinilai): adakah cara *legitimate* memakai upgrade `h2c`
   yang perlu kamu pertahankan? Kalau backend-mu butuh h2c untuk klien
   internal, di mana seharusnya upgrade itu diizinkan — dan pemeriksaan apa
   yang harus tetap berjalan di dalam terowongan?

## Perintah

```bash
./lab.sh start    # jalankan lab (selalu kembali rentan)
./lab.sh stop     # hentikan
./lab.sh verify   # verifikasi resmi 2 fase
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
```
