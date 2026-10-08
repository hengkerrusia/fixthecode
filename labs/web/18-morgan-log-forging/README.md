# Lab 18 — Log Forging via CRLF di `:remote-user` (morgan CVE-2026-5078)

Sumber: [GHSA-4vj7-5mj6-jm8m — "morgan vulnerable to Log Forging via
unneutralized control characters in :remote-user"](https://github.com/advisories/GHSA-4vj7-5mj6-jm8m)
(CVE-2026-5078). Middleware logging Express `morgan` menulis username
dari header `Authorization: Basic` (token `:remote-user`) ke access log
tanpa menetralkan karakter kontrol — CRLF di username menyuntik baris
log palsu. Terdampak format `combined`, `common`, `default`, `short`.
Diperbaiki di morgan 1.11.0.

## Skenario

Sebuah portal dengan area admin berproteksi HTTP Basic auth mencatat
setiap request ke access log dengan format ala morgan `short`:
`IP - user "METHOD path" status size`. Username diambil dari kredensial
Basic auth (yang ter-decode dari base64) dan ditulis **mentah** ke log.

Celahnya: username yang mengandung CR/LF memecah struktur
"satu-request-satu-baris" — penyerang menyuntik baris log arbitrer.
Dampak nyata: memalsukan jejak audit (mis. baris palsu "admin sukses
akses /admin"), menutupi serangan, atau meracuni SIEM yang meng-ingest
log.

Untuk keperluan lab, isi access log dapat dibaca via `GET /logs`
(mensimulasikan sudut pandang auditor/SIEM — korban sebenarnya dari
log forging, bukan penyerang).

### Topologi

```text
[learner --HTTP--> app:8080]   (satu container; log di /logs)
```

- `app/` — portal: `GET /` → 200, `GET /admin` → Basic auth
  (admin/s3cr3t!), `GET /logs` → isi access log. Setiap request
  dicatat ke access log dengan username apa adanya.

## Akar Masalah

**Penyebab umum.** Kapan pun input tak tepercaya ditulis ke format
**berbasis baris** tanpa netralisasi, injeksi baris mungkin terjadi.
CRLF tidak melulu soal framing HTTP (Lab 15–17) — pola yang sama
hidup di: baris access log, entri syslog, baris CSV, dan isi email
(header injection). Aturannya satu: *data* tidak boleh bisa menjadi
*struktur*.

**Bentuk aman dari pola yang sama.** Netralkan karakter kontrol
(`\r`, `\n`) pada setiap nilai yang ditulis ke log — ganti dengan
placeholder atau hapus — di titik penulisan log (sink), bukan hanya
di titik input.

## Fase 1 — Hacking

### Metodologi

1. **Baseline.** `GET /` → 200. `GET /admin` tanpa kredensial → 401.
   Baca `GET /logs`: satu baris per request, format
   `IP - user "METHOD path" status size`.
2. **Probe.** Login dengan username mengandung CRLF (ingat: kredensial
   Basic auth adalah `base64(user:password)`, jadi CRLF dikirim
   ter-encode dan ter-decode di server). Amati `GET /logs` — berapa
   baris yang bertambah dari satu request?
3. **Diferensial.** Bandingkan baris-baris baru dengan request yang
   kamu kirim. Baris mana yang tidak sesuai dengan kenyataan (kamu
   dapat 401, tapi log berkata lain)?
4. **Eksploitasi.** Rancang username yang menyuntik satu baris palsu
   yang meyakinkan: seolah `admin` sukses `GET /admin` dengan status
   200, berisi marker-mu. Batasan: username Basic auth dipisah dari
   password pada colon **pertama**, jadi injeksinya tidak boleh
   mengandung `:`.

### Deliverable

Exploit mencetak tepat dua baris:

```text
STATUS: 401
FORGED: <marker alfanumerik pilihanmu>
```

- `STATUS` = status respons login-mu yang sebenarnya (401).
- `FORGED` = marker yang teramati di **baris palsu** dalam access log
  (bukan di baris request-mu yang asli).
- Verifier membaca `GET /logs` dan memastikan ada baris mengandung
  marker-mu yang mengklaim status 200.

## Fase 2 — Review & Fix

Baca `app/app.py`. Temukan di mana data tak tepercaya mengalir ke
penulisan log tanpa netralisasi — dan mengapa format log yang
"sekadar teks" tetap butuh sanitasi.

Tulis perbaikan di `fix/app/app.py`: netralkan `\r` dan `\n` pada
username di titik penulisan log. Verifier memastikan: serangan
referensi tidak lagi menambah baris palsu (satu request = satu baris),
dan fungsi normal tetap utuh.

## Perintah

```bash
./lab.sh start    # jalankan lab rentan di http://localhost:8080
./lab.sh verify   # verifikasi dua fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

## Referensi

- GHSA-4vj7-5mj6-jm8m (CVE-2026-5078):
  https://github.com/advisories/GHSA-4vj7-5mj6-jm8m
