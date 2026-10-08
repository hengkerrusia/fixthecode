# Lab 16 — CRLF-Powered Desync: Request Splitting → Response Queue Poisoning (PortSwigger Research 2026)

Sumber: [PortSwigger Research — "CRLF-Powered Desync Attacks"](https://portswigger.net/research/crlf-powered-desync-attacks)
(Tom Stacey & Tobia Righi, 2026). Kasus nyata: **Nginx `$uri` request
splitting** — empat laporan bounty ($20.000 / $5.000 / $4.500 / $2.200)
di perusahaan telekomunikasi, retail, streaming, dan TikTok; plus
varian header-injection di Rust `hyper`, `curl`, dan `urllib`.

## Skenario

Sebuah gateway reverse-proxy meneruskan request HTTP/1.1 klien ke
backend internal lewat **satu koneksi keep-alive yang dipakai bersama**
semua klien (seperti connection pooling di proxy produksi). Sebelum
membangun upstream request, gateway melakukan **URL-decode terhadap
request target** — perilaku yang meniru Nginx `proxy_pass ...$uri`.

Celahnya: `%0d%0a` yang dikirim klien sebagai bagian dari path berubah
menjadi CRLF literal di upstream request. Satu request dari klien
terbelah menjadi **dua request** di sisi backend (request splitting).
Respons untuk request selundupan tidak punya pasangan di sisi klien —
ia **mengantre** di koneksi backend dan diberikan ke request berikutnya
yang masuk lewat koneksi itu: *response queue poisoning*.

### Topologi

```text
[learner --HTTP/1.1--> gateway:8080 --HTTP/1.1--> backend:8000]
                         (satu koneksi backend dipakai bersama)
```

- `gateway/` — reverse proxy HTTP/1.1: meneruskan request ke backend
  lewat satu koneksi keep-alive bersama, dengan URL-decode pada
  request target sebelum membangun upstream request line.
- `backend/` — origin HTTP/1.1 keep-alive: `GET /` → 200 "backend ok",
  `GET /echo?m=<nilai>` → 200 berisi `echo:<nilai>`.

## Akar Masalah

**Penyebab umum.** Desync terjadi setiap kali dua lapisan menghitung
"di mana request berakhir" dari **byte yang berbeda**. Di sini yang
berbeda adalah *representasi* request target: klien (dan parser
gateway) melihat `%0d%0a` sebagai 6 karakter path biasa — satu request.
Backend, yang menerima hasil decode, melihat CRLF literal — dua
request. CRLF hanyalah primitif pemecahnya; keluarga yang sama
mencakup CL.TE, H2.CL, dan 0.CL (Lab 6–10).

Kutipan Tom Stacey dari riset ini: *"Desyncs from header injections
aren't going anywhere, while Nginx exists."*

**Bentuk aman dari pola yang sama.** Proxy yang perlu menormalisasi
target harus memilih salah satu:

1. Teruskan request target **apa adanya** (masih ter-encode) ke
   upstream — jangan pernah menaruh hasil decode ke request line;
2. atau tolak secara fail-closed bila hasil decode mengandung CR/LF;
3. atau hilangkan HTTP/1.1 di sisi upstream (pakai HTTP/2 ke backend),
   sehingga framing tidak lagi bergantung pada CRLF.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** `GET /` via gateway → 200 "backend ok". Kirim
   beberapa request berurutan — tiap respons selalu cocok dengan
   request-nya (1 request : 1 respons).
2. **Probe.** Sisipkan `%0d%0a` di path. Responsnya? Coba juga
   `%0d%0a%0d%0a`. Perhatikan: dari sisi klien, request-mu tetap
   *satu* request yang valid.
3. **Diferensial.** Setelah request beracun, kirim satu request normal
   lagi (boleh di koneksi yang sama, boleh koneksi baru) dan baca
   responsnya baik-baik. Apakah respons itu benar-benar jawaban untuk
   request terakhirmu? Kalau tidak — dari request *siapa* ia berasal,
   dan bagaimana ia bisa sampai ke tanganmu?
4. **Eksploitasi.** Selundupkan request kedua yang lengkap dan valid —
   misalnya `GET /echo?m=<marker>` — di dalam satu request terbelah.
   Trik kerapian: buat *prefix* (request pertama hasil belahan) menjadi
   request yang valid juga, dengan menyelundupkan versi HTTP ke dalam
   target yang ter-decode, mis. target ter-decode berbentuk
   `/ HTTP/1.1\r\nX-Pad: x\r\n\r\n...`. Lalu buktikan dengan koneksi
   kedua (peran "korban"): korban yang hanya mengirim `GET /` normal
   menerima respons berisi marker-mu.

### Deliverable

Exploit mencetak tepat dua baris:

```text
STATUS: 200
POISONED: <marker>
```

- `<marker>` alfanumerik pilihanmu (mis. `qrisp16`).
- `STATUS` = status respons yang diterima **korban**.
- `POISONED` = marker yang teramati di **respons korban** (koneksi
  kedua), bukan di koneksimu sendiri.
- Verifier me-replay seranganmu dengan marker-mu: ia mengirim request
  terbelah sebagai penyerang, lalu mengirim `GET /` sebagai korban,
  dan memastikan marker-mu muncul di respons korban.

## Fase 2 — Review & Fix

Baca `gateway/gateway.py` dan `backend/app.py`. Temukan di mana
representasi request berubah antara saat gateway mem-parse request
klien dan saat ia membangun upstream request — dan mengapa perubahan
itu memecah satu request menjadi dua.

Tulis perbaikan di `fix/gateway/gateway.py`: tolak request secara
fail-closed (400) bila request target yang sudah ter-decode mengandung
CR atau LF, dan jangan teruskan ke backend. Verifier memastikan:
serangan referensi digagalkan (400, tidak ada yang diteruskan) dan
fungsi normal tetap utuh.

## Perintah

```bash
./lab.sh start    # jalankan lab rentan di http://localhost:8080
./lab.sh verify   # verifikasi dua fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

## Referensi

- PortSwigger Research — "CRLF-Powered Desync Attacks" (2026):
  https://portswigger.net/research/crlf-powered-desync-attacks
- James Kettle — "HTTP/1.1 Must Die: The Desync Endgame" (2025):
  https://portswigger.net/research/http1-must-die
