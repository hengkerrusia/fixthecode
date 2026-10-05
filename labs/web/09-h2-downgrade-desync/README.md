# Lab 9 — H2.CL Downgrade Desync (James Kettle, PortSwigger Research 2021)

Sumber: [James Kettle — "HTTP/2: The Sequel is Always Worse"](https://portswigger.net/research/http2)
(PortSwigger Research, Agustus 2021, Black Hat USA 2021).

Kasus nyata dari riset ini: **Netflix — H2.CL, $20.000** (bounty maksimum
Netflix; tercatat sebagai **CVE-2021-21295** pada Netty); **Verizon —
H2.TE, $7.000 + $10.000** (pembajakan redirect membocorkan kode OAuth, dan
pencurian bearer token live); **Netlify — H2.TE, $4.000** (seluruh situs
yang di-host Netlify terdampak). Dilaporkan juga ke AWS ALB dan Atlassian
Jira (request splitting → response queue poisoning membocorkan PII pengguna
lain).

## Skenario

Sebuah gateway menerima koneksi **HTTP/2 cleartext (h2c, prior knowledge)**
dari klien, menerjemahkan setiap stream menjadi request **HTTP/1.1**, lalu
meneruskannya ke backend internal yang hanya bicara HTTP/1.1. Semua request
diteruskan lewat **satu koneksi keep-alive bersama** ke backend (connection
reuse — persis seperti reverse proxy produksi).

### Topologi

```text
[klien --HTTP/2 (h2c)--> gateway:8080 --HTTP/1.1--> backend:8000]
```

- `gateway/` — terminasi HTTP/2, downgrade ke HTTP/1.1.
- `backend/` — origin HTTP/1.1: `GET /` → 200, path lain → 200 berisi echo
  `METHOD path` (supaya request yang diproses backend bisa dikenali).

## Akar Masalah

Di HTTP/2, framing body **tidak** memakai `Content-Length` — body dibingkai
oleh DATA frame. Karena itu RFC 7540 §8.1.2.2 melarang header
connection-specific di dalam pesan HTTP/2: sebuah endpoint **dilarang**
menghasilkan pesan HTTP/2 yang mengandung header seperti `connection`,
`keep-alive`, `transfer-encoding`, dan kawan-kawannya.

Masalah muncul di **lapisan translasi**: penerjemah H2→H1 yang ceroboh
meneruskan header `content-length` / `transfer-encoding` yang dikirim klien
lewat HTTP/2 **apa adanya** ke request HTTP/1.1. Backend HTTP/1.1 lalu
membingkai body berdasarkan `Content-Length` tersebut, sementara byte body
yang benar-benar dikirim gateway adalah seluruh isi DATA frame. Begitu
panjang keduanya berbeda → **desync**: sisa byte dianggap sebagai awal
request berikutnya di koneksi keep-alive yang dipakai bersama.

Varian ini disebut **H2.CL** (depan H2, belakang pakai Content-Length) —
varian yang dipakai di Netflix (CVE-2021-21295, bug di codec H2→H1 Netty).

Bentuk aman dari pola yang sama: di tepi downgrade, **tolak atau buang**
header connection-specific yang datang lewat HTTP/2 sebelum diterjemahkan;
atau dorong HTTP/2 end-to-end sampai ke backend.

## Fase 1 — Hacking (black-box)

Target: `http://localhost:8080` — HTTP/2 prior-knowledge (h2c, tanpa TLS).
Contoh baseline: `curl --http2-prior-knowledge http://localhost:8080/`

### Metodologi

1. **Baseline** — Kirim `GET /` via HTTP/2. Respons normal seperti apa?
   Header apa saja yang kembali?
2. **Probe** — Kirim request HTTP/2 dengan header `content-length: 0` dan
   DATA frame berisi **satu request HTTP/1.1 utuh** (request line + header +
   baris kosong). Apakah gateway meneruskan `content-length` itu ke
   backend? Petunjuk: backend membingkai body dari `Content-Length`.
3. **Diferensial** — Setelah probe, kirim satu request HTTP/2 normal.
   Bandingkan responsnya dengan baseline. Kalau responsnya "salah alamat"
   (isi respons milik request lain), kamu baru saja meracuni antrean.
4. **Eksploitasi** — Selundupkan request ke path pilihanmu (beri marker
   yang unik), lalu buktikan lewat **response queue poisoning**: request
   normal berikutnya menerima respons milik request selundupanmu. Itu
   bukti desync yang deterministik — teknik konfirmasi yang sama dipakai
   Kettle di lapangan.

Catatan framing: di HTTP/2 tidak ada "request mentah" seperti di HTTP/1.1.
Kamu merangkai frame sendiri: preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`,
SETTINGS, HEADERS (HPACK), DATA. Untuk HPACK, encoding paling sederhana
sudah cukup: *literal without indexing, nama baru* — byte `0x00`, panjang
nama (1 byte bila < 127), nama, panjang value, value. Contoh header
`content-length: 0` menjadi `00 0e "content-length" 01 "0"`.

### Deliverable

Tulis seranganmu di `exploit/exploit.py` (Python stdlib saja, < 60 detik).
Kontrak output (ke stdout, baris persis seperti ini):

```text
STATUS: <kode status HTTP, 3 digit>
SMUGGLED_PATH: </path>
```

- `STATUS`: kode status dari respons probe yang menerima respons racun
  (200 bila queue poisoning berhasil).
- `SMUGGLED_PATH`: path request yang kamu selundupkan (mis. `/pwned9`).

**Penting:** seranganmu wajib **menyisakan satu respons racun di antrean
backend** — selundupkan request yang sama **dua kali** dalam satu DATA
frame, lalu probe **tepat sekali**. Verifier melakukan probe independen
tepat setelah skripmu: bila probe itu menerima respons berisi
`SMUGGLED_PATH`-mu, seranganmu terbukti nyata (bukan klaim kosong).

## Fase 2 — Review & Fix

Baca `gateway/gateway.py`, temukan bagaimana header yang datang lewat
HTTP/2 diteruskan menjadi request HTTP/1.1 ke backend. Tulis perbaikanmu
di `fix/gateway/gateway.py`.

Lulus bila serangan referensi **gagal total** (request ambigu → 400, tidak
ada byte yang diteruskan ke backend, antrean bersih) sementara fungsi
normal utuh: `GET /` → 200, `POST /` via HTTP/2 (body lewat DATA frame,
tanpa `content-length`) → 200.

## Perintah

```bash
./lab.sh start    # jalankan lab (selalu kembali rentan)
./lab.sh stop     # hentikan lab
./lab.sh verify   # verifikasi 2 fase (butuh Docker di host)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
```

## Referensi

- James Kettle, "HTTP/2: The Sequel is Always Worse" —
  https://portswigger.net/research/http2
- CVE-2021-21295 (Netty HTTP/2 → HTTP/1.1 downgrade)
- RFC 7540 §8.1.2.2 (larangan header connection-specific di HTTP/2),
  RFC 7541 (HPACK)
