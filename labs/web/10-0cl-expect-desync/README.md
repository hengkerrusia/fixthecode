# Lab 10 — 0.CL Desync via Expect: 100-continue (James Kettle, PortSwigger Research 2025)

Sumber: [James Kettle — "HTTP/1.1 Must Die: The Desync Endgame"](https://portswigger.net/research/http1-must-die)
(PortSwigger Research, Agustus 2025, Black Hat USA / DEF CON 33).

Kasus nyata dari riset ini: **T-Mobile — 0.CL via `Expect: 100-continue`
polos, $12.000**; **GitLab — 0.CL via `Expect: y 100-continue`
(obfuscated), $7.000** (response queue poisoning membocorkan video laporan
bug bounty orang lain); **Akamai — CL.0 via obfuscated Expect,
CVE-2025-32094, $9.000** + 74 laporan pelanggan senilai total $221.000.
Total riset ini menghasilkan >$350.000 bounty. Lab ini mengangkat varian
**0.CL via vanilla Expect** (kasus T-Mobile) — primitif paling bersih
dari keluarga ini.

## Skenario

Sebuah gateway HTTP/1.1 meneruskan request klien ke backend internal
lewat koneksi keep-alive. Gateway mengimplementasikan handshake
`Expect: 100-continue`: header diteruskan dulu ke backend, body menyusul
setelah backend membalas `100 Continue`.

Backend menghormati `Content-Length` secara ketat. Salah satu path-nya
(`/static/logo.png`, meniru file statis ala nginx) adalah **early-response
gadget**: untuk request ber-`Expect`, backend membalas `200 OK` **segera**
tanpa menunggu body, lalu menguras body demi menjaga sinkronisasi
keep-alive.

### Topologi

```text
[klien --HTTP/1.1--> gateway:8080 --HTTP/1.1--> backend:8000]
```

- `gateway/` — reverse proxy HTTP/1.1 dengan penanganan `Expect`.
- `backend/` — origin: `GET /` → 200, path lain → 200 berisi echo path
  (supaya request yang diproses backend bisa dikenali), `POST /echo`
  → 200 berisi echo body.

## Akar Masalah

Header `Expect: 100-continue` membelah pengiriman satu request menjadi
dua tahap: klien mengirim blok header dulu, server menilai, dan hanya
bila server membalas `100 Continue` klien boleh mengirim body. Untuk
klien/server langsung ini sekadar optimasi. Untuk **reverse proxy** ini
bom kompleksitas: proxy harus meneruskan header, menunggu balasan
interim backend, lalu memutuskan apa yang dilakukan terhadap body —
semuanya sambil menjaga sinkronisasi dua koneksi (klien↔proxy,
proxy↔backend).

Pola bug yang umum (kasus T-Mobile): implementasi Expect yang rusak di
proxy **meneruskan header dengan benar, tetapi bingung oleh balasan
non-100 dari backend** (mis. `200 OK` dari early-response gadget) lalu
**lupa bahwa body masih harus diterima dari klien**. Request dianggap
selesai dengan panjang body 0 — inilah sisi "0" dari 0.CL. Sementara
backend **menghormati Content-Length** (sisi "CL"): ia menguras tepat
`Content-Length` byte sebagai body. Akibatnya byte yang oleh proxy
dianggap "awal request berikutnya" ditelan backend sebagai "body request
sebelumnya" → **desync**: antrean respons bergeser satu posisi
(response queue poisoning). Tanpa gadget early-response, kedua sisi
saling menunggu dan serangan buntu (deadlock 0.CL) — gadget inilah yang
memecah kebuntuan.

Bentuk umum polanya: **setiap ketidaksepakatan panjang body antara dua
lapisan** (di sini 0 vs Content-Length; di lab lain CL vs TE) dengan
koneksi yang dipakai ulang = desync. Bentuk aman dari pola yang sama:
proxy yang tidak sanggup mengimplementasikan handshake `Expect` dengan
benar sebaiknya **menolaknya secara fail-closed** (400) daripada
meneruskan dengan semantik yang salah; atau pastikan body selalu
diteruskan/dikuras utuh apa pun balasan backend.

## Fase 1 — Hacking (black-box)

Target: `http://localhost:8080` — HTTP/1.1 biasa. Gunakan socket mentah
atau `printf ... | openssl s_client` / netcat; **jangan menunggu
`100 Continue`** — kirim semua byte sekaligus (pipelining), seperti PoC
Kettle.

### Metodologi

1. **Baseline.** `GET /` → 200. `POST /echo` dengan `Content-Length`
   (tanpa Expect) → 200 echo. `POST /echo` dengan
   `Expect: 100-continue` → `100` dulu, lalu 200. Catat perilaku normal.
2. **Probe gadget.** Coba path lain dengan `Expect: 100-continue`.
   Adakah path yang membalas `200` **langsung tanpa `100`**? Itulah
   early-response gadget — pemecah deadlock 0.CL. (Dunia nyata:
   `/con` di IIS, file statis di nginx, redirect level server.)
3. **Diferensial.** Kirim sekaligus: `POST <gadget>` +
   `Expect: 100-continue` + `Content-Length: N`, lalu N byte berisi
   satu request `GET /<marker-kamu>` utuh, lalu satu request
   `GET /<marker-probe>` biasa. Bandingkan dengan baseline:
   - Normal: tiap request mendapat responsnya sendiri.
   - 0.CL: kamu mengirim **3 request logis** tetapi hanya menerima
     **2 respons** — dan respons ke-2 berisi marker **probe**, bukan
     marker selundupanmu. Antrean bergeser: request selundupanmu
     ditelan backend sebagai body.
4. **Eksploitasi.** Otomatiskan diferensial di atas dalam
   `exploit/exploit.py` hingga mencetak kontrak di bawah.

### Deliverable

`exploit/exploit.py` (stdlib saja, < 60 detik) mencetak ke stdout,
baris persis seperti ini:

```text
STATUS: 200
SMUGGLED_PATH: /<path-yang-kamu-selundupkan>
```

`STATUS` adalah kode respons yang posisinya tergeser (200 bila
pergeseran berhasil). Verifier juga menjalankan serangan referensinya
sendiri sebagai health check lab.

## Fase 2 — Review & Fix

Baca `gateway/gateway.py`: temukan cabang yang menangani balasan
backend untuk request ber-`Expect`, dan perhatikan apa yang terjadi
pada body ketika balasannya bukan `100`. Tulis perbaikan di
`fix/gateway/gateway.py`.

Kriteria lulus: request dengan `Expect: 100-continue` ditolak secara
fail-closed (400, koneksi ditutup) sehingga serangan referensi gagal
total, sementara fungsi normal utuh (`GET /`, `POST /echo` tanpa
Expect, `GET /lain` → 200). Pertimbangkan trade-off-nya: menolak
`Expect` mengorbankan klien yang sah memakainya — dokumentasikan
pilihanmu di catatan fix bila perlu.

## Perintah

```bash
./lab.sh start    # jalankan lab rentan di http://localhost:8080
./lab.sh verify   # verifikasi 2 fase (butuh Docker)
./lab.sh fix-up   # jalankan lab dengan fix-mu (tanpa verifikasi)
./lab.sh stop     # hentikan lab
```

## Referensi

- James Kettle, "HTTP/1.1 Must Die: The Desync Endgame", PortSwigger
  Research, Agustus 2025 — https://portswigger.net/research/http1-must-die
  (bagian "0.CL desync attacks" dan "Expect-based desync attacks").
- PortSwigger Web Security Academy — lab "0.CL Request Smuggling"
  (latihan interaktif teknik yang sama).
- HTTP Request Smuggler v3.0 (ekstensi Burp, open-source) — tool
  deteksi diskrepansi parser yang dipakai dalam riset ini.
